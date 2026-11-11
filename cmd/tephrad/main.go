// SPDX-License-Identifier: Apache-2.0

// tephrad is the Tephra node agent. It loads the eBPF programs, reads their
// events, attributes them to pods and writes them as JSON lines on stdout.
// Its own log goes to stderr.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/Naved124/tephra/internal/enrich"
	"github.com/Naved124/tephra/internal/events"
	"github.com/Naved124/tephra/internal/export"
	"github.com/Naved124/tephra/internal/k8s"
	"github.com/Naved124/tephra/internal/loader"
	"github.com/Naved124/tephra/internal/proctree"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

type options struct {
	ringBufSize uint
	metricsAddr string
	procRoot    string
	cgroupRoot  string
	queueLen    int
}

// counters are the agent's own metrics; kernel counters come from the stats
// map.
type counters struct {
	decodeErrors atomic.Uint64
	exported     atomic.Uint64
	exportErrors atomic.Uint64
}

func main() {
	var o options
	flag.UintVar(&o.ringBufSize, "ringbuf-size", loader.DefaultRingBufSize, "events ring buffer size in bytes (power of two)")
	flag.StringVar(&o.metricsAddr, "metrics-addr", ":9090", "listen address for /metrics; empty disables it")
	flag.StringVar(&o.procRoot, "proc", "/proc", "procfs mount showing the node's processes")
	flag.StringVar(&o.cgroupRoot, "cgroup-root", "/sys/fs/cgroup", "cgroup v2 mount showing the node's hierarchy")
	flag.IntVar(&o.queueLen, "queue", 8192, "decoded events buffered between the reader and enrichment")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(log, o); err != nil {
		log.Error("tephrad exiting", "error", err.Error())
		os.Exit(1)
	}
}

func run(log *slog.Logger, o options) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	node := os.Getenv("NODE_NAME")
	if node == "" {
		node, _ = os.Hostname()
	}
	log.Info("tephrad starting", "version", version, "node", node)

	feats := loader.Probe()
	for _, f := range feats {
		log.Info("kernel feature", "feature", f.Name, "available", f.Available, "required", f.Required, "detail", f.Detail)
	}
	if err := loader.CheckRequired(feats); err != nil {
		return err
	}
	if err := k8s.CheckCgroupV2(o.cgroupRoot); err != nil {
		return err
	}

	// Pods first: the index is complete before the first event needs it.
	var pods *k8s.PodIndex
	index := k8s.NewPodIndex()
	switch err := k8s.WatchPods(ctx, node, index); {
	case err == nil:
		pods = index
		log.Info("pod informer synced", "node", node, "pods", index.Len())
	case errors.Is(err, k8s.ErrNotInCluster):
		log.Warn("not running in a cluster; events carry container IDs but no pod attribution")
	default:
		return fmt.Errorf("pod informer: %w", err)
	}

	sensor, err := loader.Load(loader.Options{RingBufSize: uint32(o.ringBufSize)})
	if err != nil {
		return err
	}
	defer func() {
		if err := sensor.Close(); err != nil {
			log.Error("detach failed", "error", err.Error())
			return
		}
		log.Info("programs detached")
	}()
	self := sensor.Self()
	log.Info("agent located", "cgroup_id", self.CgroupID, "pidns_level", self.PidNSLevel, "pidns_inum", self.PidNSInum)
	for _, a := range sensor.Attachments() {
		log.Info("program attached", "program", a.Program, "hook", a.Hook)
	}

	// Seed after attaching: a process that starts during the scan is then
	// covered by its events, and one that started before it by the scan.
	// Events wait in the ring buffer meanwhile.
	tree := proctree.New(0, 0)
	procfs := proctree.ProcFS{Root: o.procRoot}
	n, err := tree.Seed(procfs)
	if err != nil {
		return fmt.Errorf("seed process tree: %w", err)
	}
	log.Info("process tree seeded", "processes", n)

	var c counters
	if o.metricsAddr != "" {
		srv := &http.Server{
			Addr:              o.metricsAddr,
			Handler:           metricsHandler(sensor, tree, index, &c),
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("metrics server failed", "error", err.Error())
			}
		}()
		defer func() { _ = srv.Close() }()
	}

	enricher := enrich.New(node, tree, procfs, k8s.NewCgroupResolver(o.cgroupRoot), pods)
	out := export.NewJSONLines(os.Stdout)

	// read -> enrich -> export, joined by a bounded channel. When the
	// later stages fall behind, the reader blocks, the ring buffer fills
	// and the kernel counts the drops.
	queue := make(chan events.Event, o.queueLen)
	readErr := make(chan error, 1)
	go func() { readErr <- read(sensor.Events(), queue, &c, log) }()

	reap := time.NewTicker(10 * time.Second)
	defer reap.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info("signal received, shutting down")
			return out.Flush()
		case err := <-readErr:
			_ = out.Flush()
			return fmt.Errorf("ring buffer reader stopped: %w", err)
		case now := <-reap.C:
			tree.Reap(now)
		case ev := <-queue:
			if err := out.Write(enricher.Handle(ev, time.Now())); err != nil {
				c.exportErrors.Add(1)
			} else {
				c.exported.Add(1)
			}
			if len(queue) == 0 {
				if err := out.Flush(); err != nil {
					c.exportErrors.Add(1)
				}
			}
		}
	}
}

// read decodes ring buffer records until the reader is closed.
func read(rd *ringbuf.Reader, queue chan<- events.Event, c *counters, log *slog.Logger) error {
	var rec ringbuf.Record
	for {
		if err := rd.ReadInto(&rec); err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return err
		}
		ev, err := events.Decode(rec.RawSample)
		if err != nil {
			// Count every one, log the first few.
			if c.decodeErrors.Add(1) <= 10 {
				log.Error("undecodable record", "error", err.Error())
			}
			continue
		}
		queue <- ev
	}
}
