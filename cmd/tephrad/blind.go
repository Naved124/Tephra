// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/Naved124/tephra/internal/config"
	"github.com/Naved124/tephra/internal/k8s"
	"github.com/Naved124/tephra/internal/loader"
)

// blindActionIDs maps the names in blind.actions to enforce actions.
var blindActionIDs = map[string]uint32{
	"exec_unlinked": loader.ActionExecUnlinked,
	"ptrace":        loader.ActionPtrace,
	"module_load":   loader.ActionModule,
	"mount":         loader.ActionMount,
}

// blindMode is the kernel's value for blind.mode.
func blindMode(m string) uint32 {
	switch m {
	case config.BlindOn:
		return loader.BlindOn
	case config.BlindDryRun:
		return loader.BlindDryRun
	}
	return loader.BlindOff
}

// blindActions lists what blind mode refuses: the actions named in the
// configuration, and file reads or writes when a protected file asks for
// them.
func blindActions(b config.Blind) []uint32 {
	seen := map[uint32]bool{}
	var out []uint32
	add := func(a uint32) {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	for _, name := range b.Actions {
		add(blindActionIDs[name])
	}
	for _, f := range b.Files {
		for _, op := range f.Ops {
			switch op {
			case "read":
				add(loader.ActionFileRead)
			case "write":
				add(loader.ActionFileWrite)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// applyBlind switches blind mode on as configured and writes the first
// heartbeat, which ends any blindness the previous agent left; it says in
// the log how long the sensor was blind.
func (a *agent) applyBlind(b config.Blind) error {
	if ok, why := a.sensor.BlindAvailable(); !ok {
		if b.Mode != config.BlindOff {
			a.log.Error("blind mode is configured but unavailable: nothing is refused while the sensor is blind", "reason", why)
		}
		return nil
	}
	hb, down, err := a.sensor.BlindTimes()
	if err == nil && hb != 0 && down > hb {
		now := bootNS()
		a.log.Warn("the sensor was blind until now: the previous agent went down without a planned stop",
			"down_at", a.enricher.Wall(down), "blind_for", time.Duration(now-down).Round(time.Millisecond).String())
	}
	want := blindActions(b)
	in, err := a.sensor.SetBlind(blindMode(b.Mode), want, b.StaleAfter)
	if err != nil {
		return err
	}
	a.heartbeat()
	var bits uint32
	for _, x := range in {
		bits |= 1 << x
	}
	a.log.Info("blind mode", "mode", b.Mode, "stale_after", b.StaleAfter.String(), "actions", actionNames(bits), "files", len(b.Files))
	if len(in) != len(want) {
		a.log.Error("some actions cannot be refused while blind on this kernel: their programs did not attach", "asked", len(want), "in_force", len(in))
	}
	return nil
}

// heartbeat tells the kernel the agent is alive. It runs from the main loop,
// so a wedged loop stops it: a heartbeat that comes from a part of the agent
// that still runs while events go unhandled would hide what blind mode is
// for.
func (a *agent) heartbeat() {
	if a.sensor == nil {
		return
	}
	if ok, _ := a.sensor.BlindAvailable(); !ok {
		return
	}
	if err := a.sensor.Heartbeat(bootNS()); err != nil {
		a.c.blindHeartbeatErrors.Add(1)
	}
}

// blindScope keeps the kernel's idea of where blind mode applies in step
// with the node: below the pod roots (so new pods are covered before the
// agent has heard of them), less the pods of protected namespaces. The
// agent's own namespace is not protected while blind, unless it is listed:
// the agent is not there to need it.
func (a *agent) blindScope(ctx context.Context, index *k8s.PodIndex, protectNS []string) {
	protect := map[string]bool{}
	for _, ns := range protectNS {
		protect[ns] = true
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var last string
	for {
		roots := k8s.PodRoots(a.o.cgroupRoot)
		var shield []uint64
		if index != nil {
			cgroups := k8s.PodCgroups(a.o.cgroupRoot)
			for _, p := range index.Pods() {
				if id, ok := cgroups[p.UID]; ok && protect[p.Namespace] {
					shield = append(shield, id)
				}
			}
		}
		sort.Slice(roots, func(i, j int) bool { return roots[i] < roots[j] })
		sort.Slice(shield, func(i, j int) bool { return shield[i] < shield[j] })
		if now := fmt.Sprint(roots, shield); now != last {
			errA := a.sensor.SetBlindProtect(shield)
			errB := a.sensor.SetBlindCgroups(roots)
			if errA != nil || errB != nil {
				a.log.Error("could not write the blind-mode scope", "protect_error", fmt.Sprint(errA), "roots_error", fmt.Sprint(errB))
			} else {
				last = now
				a.c.blindRoots.Store(uint64(len(roots)))
				if len(roots) == 0 {
					a.log.Warn("blind mode: no pod cgroups found; nothing is refused while blind", "cgroup_root", a.o.cgroupRoot)
				} else {
					a.log.Info("blind-mode scope", "pod_roots", len(roots), "protected_pods", len(shield))
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
