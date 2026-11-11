// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/Naved124/tephra/internal/events"
	"github.com/Naved124/tephra/internal/k8s"
)

// metricsHandler serves the Prometheus text format. The kernel counters are
// read from the stats map on every scrape.
func metricsHandler(a *agent, pods *k8s.PodIndex) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		var b strings.Builder
		c := a.c
		b.WriteString("# HELP tephra_kernel_events_total Events per hook by outcome. seen = filtered + emitted + dropped.\n")
		b.WriteString("# TYPE tephra_kernel_events_total counter\n")
		for _, t := range events.Types {
			st, err := a.sensor.ReadStats(t)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			for _, o := range []struct {
				name string
				v    uint64
			}{{"seen", st.Seen}, {"filtered", st.Filtered}, {"emitted", st.Emitted}, {"dropped", st.Dropped}} {
				fmt.Fprintf(&b, "tephra_kernel_events_total{type=%q,outcome=%q} %d\n", t.String(), o.name, o.v)
			}
		}

		b.WriteString("# HELP tephra_event_type_available Whether the event type has a hook attached on this kernel.\n")
		b.WriteString("# TYPE tephra_event_type_available gauge\n")
		for _, t := range events.Types {
			fmt.Fprintf(&b, "tephra_event_type_available{type=%q} %d\n", t.String(), b2i(a.sensor.Available(t)))
		}

		b.WriteString("# HELP tephra_alerts_total Alerts raised, by rule.\n")
		b.WriteString("# TYPE tephra_alerts_total counter\n")
		c.mu.Lock()
		keys := make([]alertKey, 0, len(c.alerts))
		for k := range c.alerts {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i].rule < keys[j].rule })
		for _, k := range keys {
			fmt.Fprintf(&b, "tephra_alerts_total{rule=%q,level=%q} %d\n", k.rule, k.level, c.alerts[k])
		}
		c.mu.Unlock()

		counter(&b, "tephra_agent_decode_errors_total", "Ring buffer records the agent could not decode.", c.decodeErrors.Load())
		counter(&b, "tephra_agent_nested_opens_total", "File opens dropped as the second report of one overlayfs open.", c.nestedOpens.Load())
		counter(&b, "tephra_agent_records_exported_total", "Records written to stdout.", c.exported.Load())
		counter(&b, "tephra_agent_export_errors_total", "Records that failed to write.", c.exportErrors.Load())
		counter(&b, "tephra_agent_reloads_total", "Configuration reloads that took effect.", c.reloads.Load())
		counter(&b, "tephra_agent_reload_errors_total", "Configuration reloads refused because the new configuration or rules were invalid.", c.reloadErrors.Load())
		gauge(&b, "tephra_rules_loaded", "Detection rules in force.", uint64(c.rulesLoaded.Load()))
		gauge(&b, "tephra_proctree_entries", "Processes in the process tree, live and lingering.", uint64(a.tree.Len()))
		gauge(&b, "tephra_pods_known", "Pods in the pod index.", uint64(pods.Len()))
		inodes, roots, errs := a.tracker.Stats()
		gauge(&b, "tephra_inode_watches", "Files watched by identity.", uint64(inodes))
		gauge(&b, "tephra_watched_roots", "Root filesystems in which watched files were resolved.", uint64(roots))
		counter(&b, "tephra_inode_watch_errors_total", "Failed writes to the inode watch map.", errs)

		if a.grpc != nil {
			st := a.grpc.Stats()
			gauge(&b, "tephra_export_queue_depth", "Records waiting for, or on their way to, the collector.", uint64(st.Queued))
			counter(&b, "tephra_export_acked_total", "Records the collector confirmed stored.", st.Acked)
			counter(&b, "tephra_export_rejected_total", "Records the collector refused for good.", st.Rejected)
			counter(&b, "tephra_export_retries_total", "Streams to the collector that failed and were sent again.", st.Retries)
			b.WriteString("# HELP tephra_export_dropped_total Records discarded because the export queue was full.\n")
			b.WriteString("# TYPE tephra_export_dropped_total counter\n")
			fmt.Fprintf(&b, "tephra_export_dropped_total{stream=\"event\"} %d\n", st.DroppedEvents)
			fmt.Fprintf(&b, "tephra_export_dropped_total{stream=\"alert\"} %d\n", st.DroppedAlerts)
		}

		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write([]byte(b.String()))
	})
	return mux
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func counter(b *strings.Builder, name, help string, v uint64) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, v)
}

func gauge(b *strings.Builder, name, help string, v uint64) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s gauge\n%s %d\n", name, help, name, name, v)
}
