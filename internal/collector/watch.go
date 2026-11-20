// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"sync"
	"time"

	"github.com/Naved124/tephra/internal/export"
)

// R031 is raised by the collector, not by an agent's rule engine: it is
// about an agent that has gone quiet, which no agent can report itself.
const (
	silenceRuleID    = "R031"
	silenceTitle     = "Tephra agent silent"
	restartTitle     = "Tephra agent restarted unexpectedly"
	defaultSilence   = 45 * time.Second
	forgetSilentNode = 24 * time.Hour
)

var silenceTags = []string{"attack.defense_evasion", "attack.t1562.001"}

// agentState is what the collector knows of one node's agent.
type agentState struct {
	// last is when its last health record arrived, by the collector's
	// clock; start is the agent's start time from that record.
	last  time.Time
	start uint64
	// stopping says the last record announced a planned stop, so the
	// silence that follows is expected.
	stopping bool
	// reported says this silence has been reported already.
	reported bool
}

// watch turns the health records of the agents into alerts when an agent goes
// silent without announcing it, or comes back as a new process without
// having announced a stop. Planned stops (a rollout, an upgrade, an
// uninstall, a drain) announce themselves and raise nothing.
//
// The state is in memory only: a collector that restarts learns each agent
// again from its next health record, and until then reports no silence.
type watch struct {
	after time.Duration
	mu    sync.Mutex
	nodes map[string]*agentState
}

func newWatch(after time.Duration) *watch {
	return &watch{after: after, nodes: map[string]*agentState{}}
}

// health records one agent health record that arrived at now, and returns
// an alert if it shows a restart nobody announced.
func (w *watch) health(node string, h map[string]uint64, now time.Time) *export.Record {
	w.mu.Lock()
	defer w.mu.Unlock()
	start := h["agent_start_unix"]
	st, known := w.nodes[node]
	if !known {
		w.nodes[node] = &agentState{last: now, start: start, stopping: h["stopping"] == 1}
		return nil
	}
	var alert *export.Record
	if start > st.start && st.start != 0 && !st.stopping {
		alert = silenceAlert(node, now, restartTitle, "medium", map[string]uint64{
			"gap_seconds":         uint64(now.Sub(st.last).Seconds()),
			"recorded_while_down": h["recorded_while_down"],
			"keeps_recording":     h["keeps_recording"],
		})
	}
	st.last = now
	if start != 0 {
		st.start = start
	}
	st.stopping = h["stopping"] == 1
	st.reported = false
	return alert
}

// check returns an alert for each agent silent for longer than the limit
// without having announced a stop, once per silence.
func (w *watch) check(now time.Time) []*export.Record {
	w.mu.Lock()
	defer w.mu.Unlock()
	var alerts []*export.Record
	for node, st := range w.nodes {
		quiet := now.Sub(st.last)
		if quiet > forgetSilentNode {
			// A node removed for good: reported long ago, or stopped
			// as planned.
			delete(w.nodes, node)
			continue
		}
		if st.stopping || st.reported || quiet <= w.after {
			continue
		}
		st.reported = true
		alerts = append(alerts, silenceAlert(node, now, silenceTitle, "high", map[string]uint64{
			"silent_seconds": uint64(quiet.Seconds()),
		}))
	}
	return alerts
}

func silenceAlert(node string, now time.Time, title, level string, facts map[string]uint64) *export.Record {
	return &export.Record{
		TS:     now.UTC().Format("2006-01-02T15:04:05.000000Z"),
		Type:   export.TypeHealth,
		Node:   node,
		Rule:   &export.Rule{ID: silenceRuleID, Title: title, Level: level, Tags: silenceTags},
		K8s:    export.K8s{Namespace: "host"},
		Health: facts,
	}
}
