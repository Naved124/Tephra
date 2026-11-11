// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/Naved124/tephra/internal/events"
	"github.com/Naved124/tephra/internal/k8s"
	"github.com/Naved124/tephra/internal/loader"
	"github.com/Naved124/tephra/internal/proctree"
)

// metricsHandler serves the Prometheus text format. The kernel counters are
// read from the stats map on every scrape.
func metricsHandler(sensor *loader.Sensor, tree *proctree.Tree, pods *k8s.PodIndex, c *counters) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		var b strings.Builder
		b.WriteString("# HELP tephra_kernel_events_total Events per hook by outcome. seen = filtered + emitted + dropped.\n")
		b.WriteString("# TYPE tephra_kernel_events_total counter\n")
		for _, t := range events.Types {
			st, err := sensor.ReadStats(t)
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
		counter(&b, "tephra_agent_decode_errors_total", "Ring buffer records the agent could not decode.", c.decodeErrors.Load())
		counter(&b, "tephra_agent_records_exported_total", "Records written to stdout.", c.exported.Load())
		counter(&b, "tephra_agent_export_errors_total", "Records that failed to write.", c.exportErrors.Load())
		gauge(&b, "tephra_proctree_entries", "Processes in the process tree, live and lingering.", uint64(tree.Len()))
		gauge(&b, "tephra_pods_known", "Pods in the pod index.", uint64(pods.Len()))

		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write([]byte(b.String()))
	})
	return mux
}

func counter(b *strings.Builder, name, help string, v uint64) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, v)
}

func gauge(b *strings.Builder, name, help string, v uint64) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s gauge\n%s %d\n", name, help, name, name, v)
}
