// SPDX-License-Identifier: Apache-2.0

// tephrad is the Tephra node agent. It loads the eBPF programs, reads their
// events, attributes them to pods, evaluates the detection rules, and writes
// events and alerts as JSON lines on stdout and, if configured, to the
// collector. Its own log goes to stderr.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/Naved124/tephra/internal/config"
	"github.com/Naved124/tephra/internal/enrich"
	"github.com/Naved124/tephra/internal/events"
	"github.com/Naved124/tephra/internal/export"
	"github.com/Naved124/tephra/internal/filter"
	"github.com/Naved124/tephra/internal/inodewatch"
	"github.com/Naved124/tephra/internal/k8s"
	"github.com/Naved124/tephra/internal/loader"
	"github.com/Naved124/tephra/internal/proctree"
	"github.com/Naved124/tephra/internal/rules"
	"github.com/Naved124/tephra/internal/runtimeid"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// options are the command-line flags. A flag that was given overrides the
// same setting in the configuration file.
type options struct {
	configPath  string
	rulesDir    string
	collector   string
	ringBufSize uint
	metricsAddr string
	procRoot    string
	cgroupRoot  string
	queueLen    int
	// set holds the names of the flags given on the command line.
	set map[string]bool
}

// counters are the agent's own metrics; kernel counters come from the stats
// map.
type counters struct {
	decodeErrors atomic.Uint64
	nestedOpens  atomic.Uint64
	// deniedUnwatched counts refused opens of files no watch covers.
	deniedUnwatched atomic.Uint64
	exported        atomic.Uint64
	exportErrors    atomic.Uint64
	reloads         atomic.Uint64
	reloadErrors    atomic.Uint64
	rulesLoaded     atomic.Int64

	mu     sync.Mutex
	alerts map[alertKey]uint64
}

type alertKey struct{ rule, level string }

func (c *counters) alert(r *rules.Rule) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.alerts == nil {
		c.alerts = map[alertKey]uint64{}
	}
	c.alerts[alertKey{r.ID, r.Level}]++
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "rules" {
		os.Exit(rulesCmd(os.Args[2:], os.Stdout, os.Stderr))
	}

	o := options{set: map[string]bool{}}
	flag.StringVar(&o.configPath, "config", "", "configuration file; empty uses the defaults")
	flag.StringVar(&o.rulesDir, "rules-dir", "", "directory of detection rules (overrides rules_dir)")
	flag.StringVar(&o.collector, "collector", "", "host:port of the collector (overrides export.collector)")
	flag.UintVar(&o.ringBufSize, "ringbuf-size", loader.DefaultRingBufSize, "events ring buffer size in bytes, a power of two (overrides ring_buffer_size)")
	flag.StringVar(&o.metricsAddr, "metrics-addr", ":9090", "listen address for /metrics; empty disables it (overrides metrics_addr)")
	flag.StringVar(&o.procRoot, "proc", "/proc", "procfs mount showing the node's processes")
	flag.StringVar(&o.cgroupRoot, "cgroup-root", "/sys/fs/cgroup", "cgroup v2 mount showing the node's hierarchy")
	flag.IntVar(&o.queueLen, "queue", 8192, "decoded events buffered between the reader and enrichment")
	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "usage: tephrad [flags]\n       tephrad rules validate|test ...\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	flag.Visit(func(f *flag.Flag) { o.set[f.Name] = true })

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(log, o); err != nil {
		log.Error("tephrad exiting", "error", err.Error())
		os.Exit(1)
	}
}

// settings is one loaded configuration with its rules.
type settings struct {
	cfg   *config.Config
	rules *rules.Set
}

// load reads the configuration file and the rules. Any problem in either is
// an error: the agent never runs on a rule set it only half understood.
func load(o options) (*settings, error) {
	cfg, err := config.Load(o.configPath)
	if err != nil {
		return nil, err
	}
	if o.set["rules-dir"] {
		cfg.RulesDir = o.rulesDir
	}
	if o.set["collector"] {
		cfg.Export.Collector = o.collector
	}
	if o.set["ringbuf-size"] {
		cfg.RingBufferSize = uint32(o.ringBufSize)
	}
	if o.set["metrics-addr"] {
		cfg.MetricsAddr = o.metricsAddr
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	set, err := rules.NewSet(nil)
	if err != nil {
		return nil, err
	}
	if cfg.RulesDir != "" {
		if set, err = rules.Load(cfg.RulesDir); err != nil {
			return nil, err
		}
	}
	return &settings{cfg: cfg, rules: set}, nil
}

// enabled is the set of event types the kernel should emit: the ones named
// in the configuration, else every type when raw events are exported, else
// only what the rules need.
func (s *settings) enabled() []events.Type {
	if types, _ := s.cfg.EventTypes(); types != nil {
		return types
	}
	if s.cfg.Export.RawEvents {
		return nil
	}
	return s.rules.EventTypes()
}

func (s *settings) filters() filter.Set {
	extra, _ := s.cfg.Watches()
	ignore, _ := s.cfg.NetIgnorePrefixes()
	return filter.Set{Watches: append(s.rules.Watches(), extra...), NetIgnore: ignore}
}

// apiServers are the addresses that count as the Kubernetes API: the
// service address every pod is given, plus any that are configured.
func (s *settings) apiServers() []netip.AddrPort {
	out, _ := s.cfg.APIServers()
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if ap, err := netip.ParseAddrPort(netJoin(host, port)); err == nil {
		out = append(out, ap)
	}
	return out
}

func netJoin(host, port string) string {
	if a, err := netip.ParseAddr(host); err == nil && a.Is6() {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}

// agent is the running pipeline's state. It is touched only by the main
// loop.
type agent struct {
	log      *slog.Logger
	o        options
	cur      *settings
	sensor   *loader.Sensor
	tree     *proctree.Tree
	tracker  *inodewatch.Tracker
	runtimes *runtimeid.Set
	enricher *enrich.Enricher
	stdout   *export.JSONLines
	grpc     *export.GRPC
	c        *counters
}

// apply makes the kernel filters, the inode watches and the matcher follow
// s. Filters are written before the event types are switched, so a newly
// enabled hook never runs without its filters.
func (a *agent) apply(s *settings) error {
	f := s.filters()
	if err := a.sensor.SetFilters(f); err != nil {
		return err
	}
	if err := a.sensor.SetEnabled(s.enabled()); err != nil {
		return err
	}
	a.tracker.SetWatches(f.Exacts())
	a.observeRoots()
	a.enricher.SetWatched(f.Match)
	a.runtimes.SetPaths(s.cfg.RuntimeBinaries)
	runtimeBinaries := a.runtimes.Refresh()
	if runtimeBinaries == 0 {
		a.log.Warn("none of runtime_binaries was found on the node; rules that let the container runtime through will report it")
	}
	a.enricher.SetAPIServers(s.apiServers())
	a.cur = s
	a.c.rulesLoaded.Store(int64(len(s.rules.Rules)))

	var on []string
	for _, t := range events.Types {
		if a.sensor.Enabled(t) {
			on = append(on, t.String())
		}
	}
	inodes, roots, _ := a.tracker.Stats()
	a.log.Info("configuration loaded", "rules", len(s.rules.Rules), "file_watches", len(f.Watches),
		"inode_watches", inodes, "roots", roots, "runtime_binaries", runtimeBinaries, "net_ignore", len(f.NetIgnore), "events", on, "raw_events", s.cfg.Export.RawEvents)
	return nil
}

// observeRoots resolves the watched files in the node's own root and in the
// root of every container that is running.
func (a *agent) observeRoots() {
	a.tracker.Observe(1, inodewatch.HostOwner)
	for _, p := range a.tree.Live() {
		if p.ContainerID != "" {
			a.tracker.Observe(p.Key.PID, p.ContainerID)
		}
	}
}

// reload re-reads the configuration and the rules on SIGHUP. If either is
// invalid the running set stays in force.
func (a *agent) reload() {
	s, err := load(a.o)
	if err == nil {
		err = a.apply(s)
	}
	if err != nil {
		a.c.reloadErrors.Add(1)
		a.log.Error("reload failed; the running configuration stays in force", "error", err.Error())
		return
	}
	a.c.reloads.Add(1)
	if s.cfg.RingBufferSize != a.startRing() {
		a.log.Warn("ring_buffer_size is read at start-up only; restart the agent to change it")
	}
}

func (a *agent) startRing() uint32 { return uint32(a.o.ringBufSize) }

// handle runs one event through enrichment, the rules and the sinks.
func (a *agent) handle(ev events.Event) {
	rec := a.enricher.Handle(ev, time.Now())
	if rec == nil {
		if _, denied := ev.(*events.FileDenied); denied {
			a.c.deniedUnwatched.Add(1)
		} else {
			a.c.nestedOpens.Add(1)
		}
		return
	}
	if a.cur.cfg.Export.RawEvents {
		a.emit(rec)
	}
	for _, r := range a.cur.rules.Match(rec) {
		a.c.alert(r)
		a.emit(r.Alert(rec))
	}
}

func (a *agent) emit(rec *export.Record) {
	if err := a.stdout.Write(rec); err != nil {
		a.c.exportErrors.Add(1)
	} else {
		a.c.exported.Add(1)
	}
	if a.grpc != nil {
		a.grpc.Offer(rec)
	}
}

// health sends the agent's own counters to the collector, so that the
// dashboard can show sensor health from the same store as the events.
func (a *agent) health(node string, now time.Time) {
	if a.grpc == nil {
		return
	}
	h := map[string]uint64{
		"rules_loaded":   uint64(a.c.rulesLoaded.Load()),
		"decode_errors":  a.c.decodeErrors.Load(),
		"reload_errors":  a.c.reloadErrors.Load(),
		"proctree_procs": uint64(a.tree.Len()),
	}
	for _, t := range events.Types {
		st, err := a.sensor.ReadStats(t)
		if err != nil {
			continue
		}
		h["kernel_seen"] += st.Seen
		h["kernel_emitted"] += st.Emitted
		h["kernel_filtered"] += st.Filtered
		h["ringbuf_dropped"] += st.Dropped
	}
	a.c.mu.Lock()
	for _, n := range a.c.alerts {
		h["alerts"] += n
	}
	a.c.mu.Unlock()
	st := a.grpc.Stats()
	h["export_queue_depth"] = uint64(st.Queued)
	h["export_dropped_events"] = st.DroppedEvents
	h["export_dropped_alerts"] = st.DroppedAlerts
	h["export_retries"] = st.Retries
	a.grpc.Offer(&export.Record{
		TS:     now.UTC().Format("2006-01-02T15:04:05.000000Z"),
		Type:   export.TypeHealth,
		Node:   node,
		K8s:    export.K8s{Namespace: os.Getenv("POD_NAMESPACE")},
		Health: h,
	})
}

func run(log *slog.Logger, o options) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)

	node := os.Getenv("NODE_NAME")
	if node == "" {
		node, _ = os.Hostname()
	}
	log.Info("tephrad starting", "version", version, "node", node)

	// Configuration and rules first: an invalid rule stops the agent
	// before it touches the kernel.
	s, err := load(o)
	if err != nil {
		return err
	}
	// The ring buffer size the sensor is created with, for reload.
	o.ringBufSize = uint(s.cfg.RingBufferSize)

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

	// Pods next: the index is complete before the first event needs it.
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

	sensor, err := loader.Load(loader.Options{RingBufSize: s.cfg.RingBufferSize, Enabled: s.enabled(), Filters: s.filters()})
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
	for _, at := range sensor.Attachments() {
		log.Info("program attached", "program", at.Program, "hook", at.Hook)
	}
	for _, sk := range sensor.Skipped() {
		log.Warn("program not attached", "program", sk.Program, "hook", sk.Hook, "reason", sk.Reason)
	}
	for _, t := range events.Types {
		if !sensor.Available(t) {
			log.Warn("event type unavailable on this kernel", "type", t.String())
		}
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

	c := &counters{}
	a := &agent{
		log:      log,
		o:        o,
		sensor:   sensor,
		tree:     tree,
		tracker:  inodewatch.New(o.procRoot, sensor),
		runtimes: runtimeid.New(o.procRoot, nil),
		enricher: enrich.New(node, tree, procfs, k8s.NewCgroupResolver(o.cgroupRoot), pods),
		stdout:   export.NewJSONLines(os.Stdout),
		c:        c,
	}
	a.enricher.ObserveRoots(a.tracker)
	a.enricher.SetRuntimes(a.runtimes)
	if err := a.apply(s); err != nil {
		return err
	}

	var exporting sync.WaitGroup
	if addr := s.cfg.Export.Collector; addr != "" {
		if a.grpc, err = export.NewGRPC(addr, s.cfg.Export.Queue); err != nil {
			return err
		}
		// The exporter outlives the pipeline's context by one last
		// delivery attempt.
		exportCtx, stopExport := context.WithCancel(context.Background())
		exporting.Add(1)
		go func() { defer exporting.Done(); a.grpc.Run(exportCtx) }()
		defer func() { stopExport(); exporting.Wait() }()
		log.Info("exporting to collector", "address", addr, "queue", s.cfg.Export.Queue)
	}

	if addr := s.cfg.MetricsAddr; addr != "" {
		srv := &http.Server{
			Addr:              addr,
			Handler:           metricsHandler(a, index),
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("metrics server failed", "error", err.Error())
			}
		}()
		defer func() { _ = srv.Close() }()
	}

	// read -> enrich -> evaluate -> export, joined by a bounded channel.
	// When the later stages fall behind, the reader blocks, the ring
	// buffer fills and the kernel counts the drops.
	queue := make(chan events.Event, o.queueLen)
	readErr := make(chan error, 1)
	go func() { readErr <- read(sensor.Events(), queue, c, log) }()

	reap := time.NewTicker(10 * time.Second)
	defer reap.Stop()
	gc := time.NewTicker(time.Minute)
	defer gc.Stop()
	health := time.NewTicker(15 * time.Second)
	defer health.Stop()
	for {
		select {
		case now := <-health.C:
			a.health(node, now)
		case <-ctx.Done():
			log.Info("signal received, shutting down")
			return a.stdout.Flush()
		case err := <-readErr:
			_ = a.stdout.Flush()
			return fmt.Errorf("ring buffer reader stopped: %w", err)
		case <-hup:
			log.Info("SIGHUP received, reloading")
			a.reload()
		case now := <-reap.C:
			tree.Reap(now)
		case <-gc.C:
			// Identity watches of containers that are gone.
			live := map[string]bool{}
			for _, p := range tree.Live() {
				live[p.ContainerID] = true
			}
			a.tracker.GC(func(owner string) bool { return live[owner] })
			// A runtime upgraded since the last look.
			a.runtimes.Refresh()
		case ev := <-queue:
			a.handle(ev)
			if len(queue) == 0 {
				if err := a.stdout.Flush(); err != nil {
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
