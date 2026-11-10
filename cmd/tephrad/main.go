// SPDX-License-Identifier: Apache-2.0

// tephrad is the Tephra node agent. It loads the eBPF programs, and from M1
// reads their events, attributes them to pods and evaluates detection rules.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Naved124/tephra/internal/loader"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	statsInterval := flag.Duration("stats-interval", 10*time.Second, "how often to read the kernel counters")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log, *statsInterval); err != nil {
		log.Error("tephrad exiting", "error", err.Error())
		os.Exit(1)
	}
}

func run(log *slog.Logger, statsInterval time.Duration) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("tephrad starting", "version", version, "node", os.Getenv("NODE_NAME"))

	feats := loader.Probe()
	for _, f := range feats {
		log.Info("kernel feature", "feature", f.Name, "available", f.Available, "required", f.Required, "detail", f.Detail)
	}
	if err := loader.CheckRequired(feats); err != nil {
		return err
	}

	sensor, err := loader.Load()
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

	for _, a := range sensor.Attachments() {
		log.Info("program attached", "program", a.Program, "hook", a.Hook)
	}

	tick := time.NewTicker(statsInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info("signal received, shutting down")
			return nil
		case <-tick.C:
			st, err := sensor.ReadStats(loader.EventExec)
			if err != nil {
				log.Error("read stats failed", "error", err.Error())
				continue
			}
			log.Info("stats", "type", "exec", "seen", st.Seen, "filtered", st.Filtered, "emitted", st.Emitted, "dropped", st.Dropped)
		}
	}
}
