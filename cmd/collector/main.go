// SPDX-License-Identifier: Apache-2.0

// collector receives records from the Tephra agents over gRPC and pushes
// them to Loki.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"

	tephrav1 "github.com/Naved124/tephra/api/tephra/v1"
	"github.com/Naved124/tephra/internal/collector"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	var (
		listen      = flag.String("listen", ":4317", "gRPC listen address for the agents")
		metricsAddr = flag.String("metrics-addr", ":9091", "listen address for /metrics; empty disables it")
		lokiURL     = flag.String("loki-url", "http://loki:3100", "base URL of Loki")
		lokiTenant  = flag.String("loki-tenant", "", "tenant sent as X-Scope-OrgID; empty for a single-tenant Loki")
		cluster     = flag.String("cluster", "default", "value of the cluster label")
		maxBytes    = flag.Int("max-bytes", 64<<20, "bytes of records held in memory before streams are refused")
	)
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(log, *listen, *metricsAddr, *lokiURL, *lokiTenant, *cluster, *maxBytes); err != nil {
		log.Error("collector exiting", "error", err.Error())
		os.Exit(1)
	}
}

func run(log *slog.Logger, listen, metricsAddr, lokiURL, lokiTenant, cluster string, maxBytes int) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	c := collector.New(collector.NewLoki(lokiURL, lokiTenant), collector.Options{Cluster: cluster, MaxBytes: maxBytes, Namespace: os.Getenv("POD_NAMESPACE")}, log)
	flushed := make(chan struct{})
	flushCtx, stopFlush := context.WithCancel(context.Background())
	defer stopFlush()
	go func() { c.Run(flushCtx); close(flushed) }()

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", listen, err)
	}
	srv := grpc.NewServer(
		// Records are a few kilobytes; a stream is bounded in count by
		// the collector.
		grpc.MaxRecvMsgSize(1<<20),
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: 30 * time.Second, Timeout: 10 * time.Second}),
	)
	tephrav1.RegisterExporterServer(srv, c)
	hs := health.NewServer()
	healthpb.RegisterHealthServer(srv, hs)

	if metricsAddr != "" {
		ms := &http.Server{Addr: metricsAddr, Handler: metricsHandler(c), ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := ms.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("metrics server failed", "error", err.Error())
			}
		}()
		defer func() { _ = ms.Close() }()
	}

	log.Info("collector starting", "version", version, "listen", listen, "loki", lokiURL, "cluster", cluster)
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()

	select {
	case err := <-served:
		return fmt.Errorf("gRPC server stopped: %w", err)
	case <-ctx.Done():
	}
	log.Info("signal received, shutting down")
	hs.Shutdown()
	// Let streams that are waiting for their batch finish, then flush
	// whatever is left. Anything not acknowledged stays with its agent.
	done := make(chan struct{})
	go func() { srv.GracefulStop(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		srv.Stop()
	}
	stopFlush()
	<-flushed
	return nil
}

func metricsHandler(c *collector.Collector) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		st := c.Stats()
		var b strings.Builder
		for _, m := range []struct {
			name, help, typ string
			v               uint64
		}{
			{"tephra_collector_records_received_total", "Records read from agent streams.", "counter", st.Received},
			{"tephra_collector_records_invalid_total", "Records that failed validation.", "counter", st.Invalid},
			{"tephra_collector_records_pushed_total", "Records stored in Loki.", "counter", st.Pushed},
			{"tephra_collector_records_rejected_total", "Records Loki refused for good.", "counter", st.Rejected},
			{"tephra_collector_push_errors_total", "Failed pushes to Loki.", "counter", st.PushErrors},
			{"tephra_collector_streams_refused_total", "Streams refused because the queue was full; the agent sends them again.", "counter", st.Refused},
			{"tephra_collector_queue_bytes", "Bytes of records held in memory.", "gauge", uint64(st.QueuedBytes)},
		} {
			fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n%s %d\n", m.name, m.help, m.name, m.typ, m.name, m.v)
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write([]byte(b.String()))
	})
	return mux
}
