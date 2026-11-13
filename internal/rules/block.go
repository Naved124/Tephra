// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Naved124/tephra/internal/export"
	"github.com/Naved124/tephra/internal/filter"
)

// A rule with "action: block" also refuses what it detects, in the pods
// that opted in to enforcement. The refusal is made in the kernel, at the
// moment of the action, from a handful of maps. The kernel there knows the
// action and the task, and nothing of what the agent adds afterwards:
// ancestry, command lines, container and pod names. So each event type that
// can block has one fixed refusal, and a rule may ask for it only if the
// rule says the same thing:
//
//   - it uses only fields the kernel can judge, and
//   - it fires on everything the kernel would refuse and not on what the
//     kernel lets through.
//
// The second is checked by running the rule on sample events.
type blockSpec struct {
	action uint32
	// what the kernel refuses, for error messages.
	what   string
	fields []string
	// must fire, must not fire.
	must, mustNot []*export.Record
}

func inPod(r *export.Record) *export.Record {
	r.K8s = export.K8s{Namespace: "shop", Pod: "web"}
	r.Container = &export.Container{ID: "c0ffee", Name: "web"}
	return r
}

var blockSpecs = map[string]blockSpec{
	"exec": {
		action: filter.ActionExecUnlinked,
		what:   "the exec of a file with no name on disk (a memory file or a deleted binary), except by the container runtime",
		fields: []string{"process.unlinked", "process.Image", "process.runtime", "k8s.namespace"},
		must: []*export.Record{
			inPod(&export.Record{Type: "exec", Process: export.Process{Image: "/memfd:x (deleted)", Exec: &export.Exec{Unlinked: true}}}),
			inPod(&export.Record{Type: "exec", Process: export.Process{Image: "/tmp/gone (deleted)", Exec: &export.Exec{Unlinked: true}}}),
		},
		mustNot: []*export.Record{
			inPod(&export.Record{Type: "exec", Process: export.Process{Image: "/usr/bin/ls", Exec: &export.Exec{}}}),
			inPod(&export.Record{Type: "exec", Process: export.Process{Image: "/memfd:runc_cloned:/proc/self/exe", Runtime: true, Exec: &export.Exec{Unlinked: true}}}),
		},
	},
	"file_open": {
		action: filter.ActionFileWrite,
		what:   "an open for writing of the files the rule names",
		fields: []string{"file.path", "file.write", "file.truncate", "k8s.namespace"},
	},
	"ptrace": {
		action: filter.ActionPtrace,
		what:   "every ptrace attach",
		fields: []string{"ptrace.target_pid", "k8s.namespace"},
		must: []*export.Record{
			inPod(&export.Record{Type: "ptrace", Ptrace: &export.Ptrace{TargetPID: 4242, Mode: 2}}),
		},
	},
	"module_load": {
		action: filter.ActionModule,
		what:   "every kernel module load",
		fields: []string{"module.name", "k8s.namespace"},
		must: []*export.Record{
			inPod(&export.Record{Type: "module_load", Module: &export.Module{Name: "dummy"}}),
			inPod(&export.Record{Type: "module_load", Module: &export.Module{Name: "x"}}),
		},
	},
	"mount": {
		action: filter.ActionMount,
		what:   "every mount, except by the container runtime",
		fields: []string{"mount.target", "mount.fstype", "mount.flags", "process.runtime", "k8s.namespace"},
		must: []*export.Record{
			inPod(&export.Record{Type: "mount", Mount: &export.Mount{FSType: "ext4", Target: "/mnt"}}),
			inPod(&export.Record{Type: "mount", Mount: &export.Mount{FSType: "proc", Target: "/proc"}}),
		},
		mustNot: []*export.Record{
			inPod(&export.Record{Type: "mount", Process: export.Process{Runtime: true}, Mount: &export.Mount{FSType: "proc", Target: "/proc"}}),
		},
	},
}

// compileBlock checks that a rule with action block says what the kernel
// can refuse, and marks its watches.
func (r *Rule) compileBlock() error {
	if r.Action != "block" {
		return nil
	}
	spec, ok := blockSpecs[r.Event]
	if !ok {
		var can []string
		for e := range blockSpecs {
			can = append(can, e)
		}
		sort.Strings(can)
		return fmt.Errorf("nothing can be refused on %s events; the events that can block are %s", r.Event, strings.Join(can, ", "))
	}
	allowed := map[string]bool{}
	for _, f := range spec.fields {
		allowed[f] = true
	}
	for _, b := range r.blocks {
		for _, t := range b.tests {
			if !allowed[t.field] {
				return fmt.Errorf("the kernel refuses %s, and cannot judge %s at that moment; a blocking %s rule may use only %s",
					spec.what, t.field, r.Event, strings.Join(spec.fields, ", "))
			}
		}
	}
	for _, rec := range spec.must {
		if !r.Matches(rec) {
			return fmt.Errorf("the kernel refuses %s, which is more than this rule matches", spec.what)
		}
	}
	for _, rec := range spec.mustNot {
		if r.Matches(rec) {
			return fmt.Errorf("the kernel refuses %s, which is less than this rule matches", spec.what)
		}
	}
	if r.Event == "file_open" {
		byName := map[string]*block{}
		for i := range r.blocks {
			byName[r.blocks[i].name] = &r.blocks[i]
		}
		if !needsWrite(r.cond, byName) {
			return fmt.Errorf("only opens for writing can be refused; the rule also matches reads (add file.write: true)")
		}
		for i := range r.watches {
			r.watches[i].Bits |= filter.Block
		}
	}
	r.blockAction = spec.action
	return nil
}

// Blocks reports whether the rule refuses what it detects.
func (r *Rule) Blocks() bool { return r.blockAction != 0 }

// BlockAction is the action the kernel refuses for the rule, 0 for none.
func (r *Rule) BlockAction() uint32 { return r.blockAction }

// BlockActions lists what the rule set asks the kernel to refuse, sorted.
func (s *Set) BlockActions() []uint32 {
	seen := map[uint32]bool{}
	var out []uint32
	for _, r := range s.Rules {
		if r.blockAction != 0 && !seen[r.blockAction] {
			seen[r.blockAction] = true
			out = append(out, r.blockAction)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

var actionNames = map[string]uint32{
	"exec_unlinked": filter.ActionExecUnlinked,
	"file_write":    filter.ActionFileWrite,
	"ptrace":        filter.ActionPtrace,
	"module_load":   filter.ActionModule,
	"mount":         filter.ActionMount,
}

// MatchEnforce returns the blocking rules behind a record of type enforce:
// an action the kernel refused, or in dry-run mode would have. For a file
// it is the rules that name that file; for the others, the rules that asked
// for the action.
func (s *Set) MatchEnforce(rec *export.Record) []*Rule {
	if rec.Enforce == nil {
		return nil
	}
	action := actionNames[rec.Enforce.Action]
	var out []*Rule
	for _, r := range s.Rules {
		if r.blockAction != action || action == 0 {
			continue
		}
		if action == filter.ActionFileWrite {
			// Judge the open the way the rule would have seen it.
			open := *rec
			open.Type = "file_open"
			if !r.Matches(&open) {
				continue
			}
		}
		out = append(out, r)
	}
	return out
}
