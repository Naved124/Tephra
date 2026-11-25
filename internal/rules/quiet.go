// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"sort"
	"strings"

	"github.com/Naved124/tephra/internal/export"
)

// Quiet connections. Most connect and accept rules decide on the process
// (an interpreter that is not the container's application), not on the
// connection. Once the agent has judged a process, it can tell the kernel
// to stop reporting that process's connections, if no loaded rule could
// fire on any of them. Two kinds of connection stay reported even then,
// because the kernel can recognise them itself: connects to a destination
// port a rule names, and connects to the Kubernetes API.
//
// The judgement uses three values. A test on a fact the kernel keeps
// stable for the process (its binary, its cgroup, its parent, its user)
// is decided on the record in hand. A test on the connection is "maybe",
// except where the connection's kind decides it: the direction, a family
// other than IPv4 or IPv6, and the destinations the kernel always
// reports, which a skipped connection never has. A test on a fact that can
// change without the kernel noticing (the parent's binary, pod labels) is
// "maybe" too. A process is quiet for a direction only when every rule on
// that direction is "no".

type tri int8

const (
	no tri = iota
	maybe
	yes
)

func triOf(b bool) tri {
	if b {
		return yes
	}
	return no
}

func (a tri) and(b tri) tri { return min(a, b) }
func (a tri) or(b tri) tri  { return max(a, b) }
func (a tri) not() tri      { return yes - a }

// volatile fields can change while the kernel sees nothing change for the
// process: the parent can execute another program, a pod can be relabelled.
var volatile = map[string]bool{
	"parent.Image":          true,
	"parent.CommandLine":    true,
	"parent.identity":       true,
	"parent.is_main_binary": true,
	"parent.runtime":        true,
}

// quietValue is a test's value for any connection the kernel would skip,
// by the process the record describes, in a direction.
func (t test) quietValue(rec *export.Record, direction string) tri {
	if volatile[t.field] || strings.HasPrefix(t.field, labelPrefix) {
		return maybe
	}
	if !strings.HasPrefix(t.field, "network.") {
		return triOf(t.match(rec))
	}
	// Each possible value of the network fields that has few.
	probe := func(families ...string) tri {
		out := no
		for i, f := range families {
			r := *rec
			r.Network = &export.Network{Direction: direction, Family: f}
			v := triOf(t.match(&r))
			if i == 0 {
				out = v
			} else if v != out {
				return maybe
			}
		}
		return out
	}
	switch t.field {
	case "network.direction", "network.family":
		return probe("ipv4", "ipv6")
	case "network.unix_path":
		// IP connections have none.
		return probe("ipv4")
	case "network.is_k8s_api":
		// The kernel always reports a connect to the API, and an accept
		// is never one.
		return triOf(!t.wantTrue)
	case "network.DestinationPort":
		if direction == "outbound" && (t.modifier == "equals" || t.modifier == "in") {
			// The kernel always reports these destination ports.
			return no
		}
	}
	return maybe
}

func (b *block) quietValue(rec *export.Record, direction string) tri {
	out := yes
	for _, t := range b.tests {
		out = out.and(t.quietValue(rec, direction))
		if out == no {
			return no
		}
	}
	return out
}

func quietEval(e expr, v map[string]tri) tri {
	switch e := e.(type) {
	case blockRef:
		return v[string(e)]
	case notExpr:
		return quietEval(e.x, v).not()
	case andExpr:
		out := yes
		for _, x := range e.xs {
			out = out.and(quietEval(x, v))
		}
		return out
	case orExpr:
		out := no
		for _, x := range e.xs {
			out = out.or(quietEval(x, v))
		}
		return out
	}
	return maybe
}

// quietValue is whether a rule could fire on a skipped connection. A rule
// with no condition, a sequence step that only names its event, fires on
// every one.
func (r *Rule) quietValue(rec *export.Record, direction string) tri {
	if r.cond == nil {
		return yes
	}
	v := make(map[string]tri, len(r.blocks))
	for i := range r.blocks {
		v[r.blocks[i].name] = r.blocks[i].quietValue(rec, direction)
	}
	return quietEval(r.cond, v)
}

// netRules returns every rule, sequence steps included, that judges
// connections in a direction.
func (s *Set) netRules(event string) []*Rule {
	out := append([]*Rule(nil), s.byEvent[event]...)
	for _, seq := range s.seqByEvent[event] {
		for _, st := range seq.Steps {
			if st.Event == event {
				out = append(out, st)
			}
		}
	}
	return out
}

// Quiet reports, for the process a connect or accept record describes,
// whether no loaded rule could fire on its connects (outbound) and on its
// accepts (inbound) that the kernel would skip.
func (s *Set) Quiet(rec *export.Record) (outbound, inbound bool) {
	check := func(event, direction string) bool {
		for _, r := range s.netRules(event) {
			if r.quietValue(rec, direction) != no {
				return false
			}
		}
		return true
	}
	return check("connect", "outbound"), check("accept", "inbound")
}

// AlwaysReportPorts lists the destination ports that connect rules name, for
// the kernel to report even from a quiet process.
func (s *Set) AlwaysReportPorts() []uint16 {
	seen := map[uint16]bool{}
	for _, r := range s.netRules("connect") {
		for _, b := range r.blocks {
			for _, t := range b.tests {
				if t.field != "network.DestinationPort" || (t.modifier != "equals" && t.modifier != "in") {
					continue
				}
				for _, v := range t.ints {
					if v > 0 && v <= 65535 {
						seen[uint16(v)] = true
					}
				}
			}
		}
	}
	out := make([]uint16, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
