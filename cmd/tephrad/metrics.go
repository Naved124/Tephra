// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/Naved124/tephra/internal/events"
	"github.com/Naved124/tephra/internal/export"
	"github.com/Naved124/tephra/internal/k8s"
)

// metricsHandler serves the Prometheus text format. The kernel counters are
// read from the stats map on every scrape.
func metricsHandler(a *agent, pods *k8s.PodIndex) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		var b strings.Builder
		c := a.c
		b.WriteString("# HELP tephra_build_info The running agent's version.\n# TYPE tephra_build_info gauge\n")
		fmt.Fprintf(&b, "tephra_build_info{version=%q} 1\n", version)
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
		counter(&b, "tephra_agent_proctree_ghosts_total", "Processes found gone while the process tree still had them as live, their exits lost with ring buffer drops.", c.ghosts.Load())
		fmt.Fprintf(&b, "# HELP tephra_agent_processing_lag_seconds How far behind the kernel the agent was at most over the last 10 s: the age of the oldest event it handled.\n# TYPE tephra_agent_processing_lag_seconds gauge\ntephra_agent_processing_lag_seconds %g\n", float64(c.lagWindow.Load())/1e9)
		counter(&b, "tephra_agent_nested_opens_total", "File opens dropped as the second report of one overlayfs open.", c.nestedOpens.Load())
		counter(&b, "tephra_agent_denied_unwatched_total", "Refused opens dropped because no watch covers the file.", c.deniedUnwatched.Load())
		counter(&b, "tephra_agent_loopback_held_total", "Raw events of loopback connections judged by the rules but not exported (export.loopback_events off).", c.loopbackHeld.Load())
		counter(&b, "tephra_agent_quiet_marks_total", "Processes marked quiet: their connections that no loaded rule can fire on are skipped in the kernel.", c.quietMarked.Load())
		counter(&b, "tephra_agent_quiet_errors_total", "Failed writes or removals of quiet marks, and failed reads of counted connections.", c.quietErrors.Load())
		counter(&b, "tephra_agent_connection_summaries_total", "connection_summary records made from the counted connections of quiet processes.", c.connSummaries.Load())
		counter(&b, "tephra_agent_tamper_lost_total", "Signals to the agent and attaches to it whose records found the tamper buffer full, reported as alerts without a sender.", c.tamperLost.Load())
		counter(&b, "tephra_agent_tamper_errors_total", "Failed reads or writes of the kernel's tamper counts and table.", c.tamperErrors.Load())
		counter(&b, "tephra_agent_tamper_replayed_total", "Signals to the agent and attaches to it handled from the kernel's table of the last ones, because their records never arrived through the tamper buffer.", c.tamperReplayed.Load())
		counter(&b, "tephra_agent_tamper_unordered_total", "Tamper records handled before the main ring buffer was read up to them, because a backlog took longer than half a second to read.", c.tamperUnordered.Load())
		counter(&b, "tephra_agent_tamper_duplicates_total", "Tamper records that arrived a second time, from the buffer and from the table, and were dropped.", c.tamperDuplicates.Load())
		counter(&b, "tephra_agent_records_exported_total", "Records written to stdout.", c.exported.Load())
		counter(&b, "tephra_agent_export_errors_total", "Records that failed to write.", c.exportErrors.Load())
		counter(&b, "tephra_agent_reloads_total", "Configuration reloads that took effect.", c.reloads.Load())
		counter(&b, "tephra_agent_reload_errors_total", "Configuration reloads refused because the new configuration or rules were invalid.", c.reloadErrors.Load())
		gauge(&b, "tephra_rules_loaded", "Detection rules in force.", uint64(c.rulesLoaded.Load()))
		// Read from the kernel, so that the kill switch shows at once.
		var mode uint64
		if ok, _ := a.sensor.EnforcementAvailable(); ok {
			m, _ := a.sensor.Enforcement()
			mode = uint64(m)
		}
		gauge(&b, "tephra_enforce_mode", "Enforcement in force, as the kernel holds it: 0 off, 1 dry-run, 2 on.", mode)
		gauge(&b, "tephra_enforce_pods", "Pods on this node that enforcement applies to.", c.enforcePods.Load())
		counter(&b, "tephra_enforce_denied_total", "Actions refused by enforcement.", c.enforceDenied.Load())
		counter(&b, "tephra_enforce_would_deny_total", "Actions enforcement would have refused; it is in dry-run mode.", c.enforceWouldDeny.Load())
		gauge(&b, "tephra_rule_sequences", "Partial rule sequences held in memory; bounded by a fixed cap.", c.seqHeld.Load())
		counter(&b, "tephra_rule_sequences_evicted_total", "Partial rule sequences dropped, oldest first, to stay under the cap.", c.seqEvicted.Load())
		gauge(&b, "tephra_proctree_entries", "Processes in the process tree, live and lingering.", uint64(a.tree.Len()))
		gauge(&b, "tephra_pods_known", "Pods in the pod index.", uint64(pods.Len()))
		inodes, roots, errs := a.tracker.Stats()
		gauge(&b, "tephra_inode_watches", "Files watched by identity.", uint64(inodes))
		credWatches, _ := a.creds.Stats()
		gauge(&b, "tephra_credential_watches", "Kubernetes credential volumes and files watched, from the pod specs.", uint64(credWatches))
		gauge(&b, "tephra_watched_roots", "Root filesystems in which watched files were resolved.", uint64(roots))
		counter(&b, "tephra_inode_watch_errors_total", "Failed writes to the inode watch map.", errs)
		digests, files, idErrs := a.ids.Stats()
		gauge(&b, "tephra_identity_digests", "Shells, interpreters and download tools known by content, learned from container images.", uint64(digests))
		gauge(&b, "tephra_identity_files", "Executed files identified, cached by device, inode and change time.", uint64(files))
		counter(&b, "tephra_identity_errors_total", "Executed files that could not be read to identify them.", idErrs)

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
			b.WriteString("# HELP tephra_export_dropped_alerts_total Alerts discarded because the export queue was full, by level.\n")
			b.WriteString("# TYPE tephra_export_dropped_alerts_total counter\n")
			for _, l := range export.Levels {
				fmt.Fprintf(&b, "tephra_export_dropped_alerts_total{level=%q} %d\n", l, st.DroppedByLevel[l])
			}
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
