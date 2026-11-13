// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/Naved124/tephra/internal/config"
	"github.com/Naved124/tephra/internal/export"
	"github.com/Naved124/tephra/internal/k8s"
	"github.com/Naved124/tephra/internal/loader"
	"github.com/Naved124/tephra/internal/rules"
)

const enforceUsage = `usage:
  tephrad enforce off [pin directory]
  tephrad enforce status [pin directory]

off is the kill switch: it turns enforcement off in the kernel through the
pinned policy map, whether or not an agent is running. Nothing is refused
from that moment. An agent that starts or reloads afterwards sets the mode
from its configuration again, so set enforcement.enabled or dry_run there
too. The pin directory defaults to ` + loader.DefaultPinDir + `.
`

// enforceCmd runs "tephrad enforce ..." and returns the exit code.
func enforceCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 || len(args) > 2 {
		_, _ = fmt.Fprint(stderr, enforceUsage)
		return 2
	}
	dir := loader.DefaultPinDir
	if len(args) == 2 {
		dir = args[1]
	}
	switch args[0] {
	case "off":
		pinned, err := loader.KillSwitch(dir)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 1
		}
		if !pinned {
			_, _ = fmt.Fprintf(stdout, "nothing is pinned in %s: enforcement is not held by the kernel\n", dir)
			return 0
		}
		_, _ = fmt.Fprintln(stdout, "enforcement is off")
		return 0
	case "status":
		mode, actions, pinned, err := loader.PinnedEnforcement(dir)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 1
		}
		if !pinned {
			_, _ = fmt.Fprintf(stdout, "nothing is pinned in %s\n", dir)
			return 0
		}
		_, _ = fmt.Fprintf(stdout, "mode %s, actions %v\n", modeName(mode), actionNames(actions))
		return 0
	}
	_, _ = fmt.Fprint(stderr, enforceUsage)
	return 2
}

func modeName(mode uint32) string {
	switch mode {
	case loader.EnforceDryRun:
		return "dry-run"
	case loader.EnforceOn:
		return "on"
	}
	return "off"
}

var actionName = map[uint32]string{
	loader.ActionExecUnlinked: "exec_unlinked",
	loader.ActionFileWrite:    "file_write",
	loader.ActionPtrace:       "ptrace",
	loader.ActionModule:       "module_load",
	loader.ActionMount:        "mount",
}

// actionNames renders a bit mask of actions.
func actionNames(bits uint32) []string {
	var out []string
	for a, name := range actionName {
		if bits&(1<<a) != 0 {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// unnamed stands in for the rule when the kernel refused something no
// loaded rule asks for, which can happen for a moment around a reload.
var unnamed = &rules.Rule{ID: "E000", Title: "Action refused by enforcement that no loaded rule names", Level: "high"}

// handleEnforce turns a refusal, or a would-be refusal, into the alert of
// the rule that asked for it. A refused action never produces the event the
// rule itself matches on, so this is the only alert there will be.
func (a *agent) handleEnforce(rec *export.Record) {
	if rec.Enforce.Denied {
		a.c.enforceDenied.Add(1)
	} else {
		a.c.enforceWouldDeny.Add(1)
	}
	matched := a.cur.rules.MatchEnforce(rec)
	if len(matched) == 0 {
		matched = []*rules.Rule{unnamed}
	}
	for _, r := range matched {
		a.c.alert(r)
		a.emit(r.Alert(rec))
	}
}

// judgedByKernel reports whether the kernel judges this record's action
// for a blocking rule: the rule blocks, enforcement covers the pod, and the
// kernel has the rule's action switched on, in dry-run or on. The kernel
// then reports the action itself, refused or would-be refused, and that
// report becomes the rule's alert (handleEnforce). The ordinary event is
// not alerted on as well: for file writes, ptrace and mounts it is taken
// before the kernel decides, and would read like an action that succeeded.
// The rule compiler only accepts a blocking rule whose condition is the
// kernel's decision, so the two cannot disagree on whether it applies.
func (a *agent) judgedByKernel(r *rules.Rule, rec *export.Record) bool {
	action := r.BlockAction()
	if action == 0 {
		return false
	}
	e := a.cur.cfg.Enforcement
	if !e.Enabled || rec.K8s.Labels[e.Label] != "true" || rec.K8s.Namespace == a.ownNamespace {
		return false
	}
	for _, ns := range e.ProtectNamespaces {
		if rec.K8s.Namespace == ns {
			return false
		}
	}
	if ok, _ := a.sensor.EnforcementAvailable(); !ok {
		return false
	}
	mode, bits := a.sensor.Enforcement()
	return mode != loader.EnforceOff && bits&(1<<action) != 0
}

// applyEnforcement sets the mode and the actions from the configuration and
// the rules. The runtime's files are written first: the mode switches on
// last.
func (a *agent) applyEnforcement(s *settings) error {
	ids := a.runtimes.IDs()
	files := make([]loader.FileID, len(ids))
	for i, id := range ids {
		files[i] = loader.FileID{Dev: id.Dev, Inode: id.Inode}
	}
	if err := a.sensor.SetRuntimeFiles(files); err != nil {
		return fmt.Errorf("write runtime_inodes map: %w", err)
	}
	mode := loader.EnforceOff
	if s.cfg.Enforcement.Enabled {
		mode = loader.EnforceOn
		if s.cfg.Enforcement.DryRun {
			mode = loader.EnforceDryRun
		}
	}
	want := s.rules.BlockActions()
	in, err := a.sensor.SetEnforcement(mode, want)
	if err != nil {
		return err
	}
	available, why := a.sensor.EnforcementAvailable()
	if !available {
		mode = loader.EnforceOff
	}
	var bits uint32
	for _, x := range in {
		bits |= 1 << x
	}
	switch {
	case !s.cfg.Enforcement.Enabled:
		if len(want) > 0 {
			a.log.Info("rules with action block only alert: enforcement is not enabled")
		}
	case !available:
		a.log.Error("enforcement is enabled but unavailable; rules with action block only alert", "reason", why)
	default:
		a.log.Info("enforcement", "mode", modeName(mode), "actions", actionNames(bits),
			"on_agent_exit", s.cfg.Enforcement.OnAgentExit, "label", s.cfg.Enforcement.Label)
		if len(in) != len(want) {
			a.log.Error("some actions cannot be refused on this kernel: their programs did not attach", "asked", len(want), "in_force", len(in))
		}
	}
	return nil
}

// enforceScope keeps the kernel's idea of where enforcement applies in step
// with the pods on the node: the cgroups of pods carrying the opt-in label,
// less those in protected namespaces. A pod's cgroup exists before its
// containers do, so a pod is normally in scope before anything runs in it;
// the loop runs often for that reason.
func (a *agent) enforceScope(ctx context.Context, index *k8s.PodIndex, e config.Enforcement, ownNamespace string) {
	protect := map[string]bool{ownNamespace: true}
	for _, ns := range e.ProtectNamespaces {
		protect[ns] = true
	}
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	var last string
	for {
		var enforce, shield []uint64
		cgroups := k8s.PodCgroups(a.o.cgroupRoot)
		for _, p := range index.Pods() {
			id, ok := cgroups[p.UID]
			if !ok {
				continue
			}
			switch {
			case protect[p.Namespace]:
				shield = append(shield, id)
			case p.Labels[e.Label] == "true":
				enforce = append(enforce, id)
			}
		}
		sort.Slice(enforce, func(i, j int) bool { return enforce[i] < enforce[j] })
		sort.Slice(shield, func(i, j int) bool { return shield[i] < shield[j] })
		// Written only on change: the maps are read on every guarded
		// action.
		if now := fmt.Sprint(enforce, shield); now != last {
			errA := a.sensor.SetProtectCgroups(shield)
			errB := a.sensor.SetEnforceCgroups(enforce)
			if errA != nil || errB != nil {
				a.log.Error("could not write the enforcement scope", "protect_error", fmt.Sprint(errA), "enforce_error", fmt.Sprint(errB))
			} else {
				last = now
				a.c.enforcePods.Store(uint64(len(enforce)))
				a.log.Info("enforcement scope", "pods", len(enforce), "protected_pods", len(shield))
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
