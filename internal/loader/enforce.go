// SPDX-License-Identifier: Apache-2.0

package loader

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/tephrasec/tephra/internal/events"
	"github.com/tephrasec/tephra/internal/filter"
)

// Enforcement modes, ENFORCE_* in bpf/common.h.
const (
	EnforceOff    uint32 = 0
	EnforceDryRun uint32 = 1
	EnforceOn     uint32 = 2
)

// Enforce actions, enum enforce_action in bpf/common.h.
const (
	ActionExecUnlinked = filter.ActionExecUnlinked
	ActionFileWrite    = filter.ActionFileWrite
	ActionPtrace       = filter.ActionPtrace
	ActionModule       = filter.ActionModule
	ActionMount        = filter.ActionMount
	ActionFileRead     = filter.ActionFileRead
)

// Blind modes, BLIND_* in bpf/common.h.
const (
	BlindOff    uint32 = 0
	BlindDryRun uint32 = 1
	BlindOn     uint32 = 2
)

// DefaultPinDir is where enforcement is pinned.
const DefaultPinDir = "/sys/fs/bpf/tephra"

// lsmActions says which actions each enforcement program refuses.
var lsmActions = map[string][]uint32{
	"tephra_lsm_exec":      {ActionExecUnlinked},
	"tephra_lsm_file_open": {ActionFileWrite, ActionFileRead},
	"tephra_lsm_ptrace":    {ActionPtrace},
	"tephra_lsm_mount":     {ActionMount},
	// A module arrives through one of two hooks; the action is in force
	// only with both.
	"tephra_lsm_read_file": {ActionModule},
	"tephra_lsm_load_data": {ActionModule},
}

// pinnedMaps are the policy maps that outlive the agent. A new agent adopts
// them, so there is no moment at which a refusal in force is forgotten. The
// watch maps are not among them: the programs of the old agent keep their
// own until the new agent's programs, with maps already filled, take over.
//
// The blind-mode maps are among them: the programs an agent leaves pinned
// read the heartbeat the next agent writes, and the next agent sees when its
// predecessor went down.
var pinnedMaps = []string{"enforce_cfg", "enforce_cgroups", "protect_cgroups", "runtime_inodes", "runtime_tasks",
	"blind_cfg", "blind_heartbeat", "blind_down", "blind_cgroups", "blind_protect",
	// Counted while the agent is gone; the next agent reads it.
	"blind_quiet"}

// lsmListPaths are where the kernel's list of active security modules can
// be read: securityfs, and the same file through the node's first process
// for an agent whose container has no securityfs.
var lsmListPaths = []string{"/sys/kernel/security/lsm", "/proc/1/root/sys/kernel/security/lsm"}

// LSMActive reports whether the kernel calls BPF LSM programs. A kernel
// built with them still ignores them unless "bpf" is in its list of active
// security modules (the lsm= boot parameter); attaching succeeds either way,
// so the list is the only evidence.
func LSMActive() (bool, string) {
	var lastErr error
	for _, p := range lsmListPaths {
		data, err := os.ReadFile(p)
		if err != nil {
			lastErr = err
			continue
		}
		for _, name := range strings.Split(strings.TrimSpace(string(data)), ",") {
			if name == "bpf" {
				return true, ""
			}
		}
		return false, fmt.Sprintf("the kernel's active security modules (%s) do not include bpf; boot with lsm=...,bpf", strings.TrimSpace(string(data)))
	}
	return false, fmt.Sprintf("cannot read the kernel's list of active security modules: %v", lastErr)
}

// EnforcementAvailable reports whether the enforcement programs are
// attached for enforcement, and if not, why.
func (s *Sensor) EnforcementAvailable() (bool, string) {
	return s.enforceOff == "", s.enforceOff
}

// BlindAvailable reports whether the enforcement programs are attached for
// blind mode, and if not, why.
func (s *Sensor) BlindAvailable() (bool, string) {
	return s.blindOff == "", s.blindOff
}

// Enforcing reports whether an action's programs are all attached.
func (s *Sensor) Enforcing(action uint32) bool {
	if !s.enforcing[action] {
		return false
	}
	// Both module hooks, or a module can still be loaded the other way.
	if action == ActionModule {
		n := 0
		for _, a := range s.attachments {
			if a.Program == "tephra_lsm_read_file" || a.Program == "tephra_lsm_load_data" {
				n++
			}
		}
		return n == 2
	}
	return true
}

// newCollection loads the programs, adopting the pinned policy maps of an
// earlier agent when there are any and they still fit.
func (s *Sensor) newCollection(spec *ebpf.CollectionSpec) (*ebpf.Collection, error) {
	enforce, err := adoptPinned(s.pinDir, pinnedMaps)
	if err != nil {
		return nil, fmt.Errorf("enforcement pin directory: %w", err)
	}
	if v, ok := pinnedLayout(s.detectDir); ok && v != events.LayoutVersion || !ok && hasPins(s.detectDir, detectMaps) {
		// Recorded in another record layout: the backlog cannot be
		// decoded, and is not adopted.
		s.freshStart = fmt.Sprintf("the pinned ring buffer was written in record layout %d, this version reads %d", v, events.LayoutVersion)
		if !ok {
			s.freshStart = fmt.Sprintf("the pinned ring buffer has no record layout, so an earlier version wrote it; this version reads layout %d", events.LayoutVersion)
		}
		for _, name := range append([]string{layoutPin}, detectMaps...) {
			_ = os.Remove(filepath.Join(s.detectDir, name))
		}
	}
	detect, err := adoptPinned(s.detectDir, detectMaps)
	if err != nil {
		closeMaps(enforce)
		return nil, fmt.Errorf("detection pin directory: %w", err)
	}
	defer func() { closeMaps(enforce); closeMaps(detect) }()
	build := func() (*ebpf.Collection, error) {
		replace := map[string]*ebpf.Map{}
		for n, m := range enforce {
			replace[n] = m
		}
		for n, m := range detect {
			replace[n] = m
		}
		return ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{MapReplacements: replace})
	}
	coll, err := build()
	if err != nil && len(detect) > 0 && errors.Is(err, ebpf.ErrMapIncompatible) {
		// Pinned by a version with another layout or another ring
		// buffer size: what it recorded cannot be read. Its programs
		// keep their maps until their links are replaced.
		s.freshStart = "the pinned ring buffer does not fit this version or size: " + firstLine(err.Error())
		for _, name := range detectMaps {
			_ = os.Remove(filepath.Join(s.detectDir, name))
		}
		closeMaps(detect)
		detect = map[string]*ebpf.Map{}
		coll, err = build()
	}
	if err != nil && len(enforce) > 0 && errors.Is(err, ebpf.ErrMapIncompatible) {
		// Pinned by a version with another layout: start again from
		// nothing. Enforcement by the old programs ends here.
		unpinAll(s.pinDir)
		closeMaps(enforce)
		enforce = map[string]*ebpf.Map{}
		coll, err = build()
	}
	if err != nil {
		return nil, err
	}
	if err := pinNew(coll, s.pinDir, pinnedMaps, enforce); err != nil {
		coll.Close()
		return nil, err
	}
	if err := pinNew(coll, s.detectDir, detectMaps, detect); err != nil {
		coll.Close()
		return nil, err
	}
	if err := pinLayout(s.detectDir); err != nil {
		coll.Close()
		return nil, err
	}
	_, s.backlog = detect["events"]
	return coll, nil
}

// pinLink replaces the pinned link of an enforcement program with the new
// one.
func (s *Sensor) pinLink(h hook, l link.Link) error {
	return replaceLink(s.pinDir, h, l)
}

// unpinAll removes everything pinned in dir, which detaches the programs an
// earlier agent left behind. Directories in it, such as the detection pins
// under the enforcement directory, are left alone.
func unpinAll(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		_ = os.Remove(filepath.Join(dir, e.Name()))
	}
	_ = os.Remove(dir)
}

// Unpin removes the pins, so that enforcement ends when the agent does.
func (s *Sensor) Unpin() {
	if s.pinDir != "" {
		unpinAll(s.pinDir)
	}
}

// SetEnforcement sets the mode and the actions in force. Actions whose
// programs are not attached are left out; the result says which are in.
func (s *Sensor) SetEnforcement(mode uint32, actions []uint32) ([]uint32, error) {
	var bits uint32
	var in []uint32
	if s.enforceOff != "" {
		mode = EnforceOff
	}
	for _, a := range actions {
		if s.Enforcing(a) {
			bits |= 1 << a
			in = append(in, a)
		}
	}
	cfg := tephraEnforceCfg{Mode: mode, Actions: bits}
	if err := s.coll.Maps["enforce_cfg"].Put(uint32(0), &cfg); err != nil {
		return nil, fmt.Errorf("write enforce_cfg map: %w", err)
	}
	return in, nil
}

// SetBlind sets blind mode: what it refuses while the sensor is blind, and
// how old the heartbeat may get before the sensor counts as blind. Actions
// whose programs are not attached are left out; the result says which are
// in.
func (s *Sensor) SetBlind(mode uint32, actions []uint32, stale time.Duration) ([]uint32, error) {
	var bits uint32
	var in []uint32
	if s.blindOff != "" {
		mode = BlindOff
	}
	for _, a := range actions {
		if s.Enforcing(a) {
			bits |= 1 << a
			in = append(in, a)
		}
	}
	cfg := tephraBlindCfg{Mode: mode, Actions: bits, StaleNs: uint64(stale)}
	if err := s.coll.Maps["blind_cfg"].Put(uint32(0), &cfg); err != nil {
		return nil, fmt.Errorf("write blind_cfg map: %w", err)
	}
	return in, nil
}

// Heartbeat tells the kernel the agent is alive at boot-clock time now. A
// heartbeat newer than the last time the agent went down ends blindness.
func (s *Sensor) Heartbeat(now uint64) error {
	return s.coll.Maps["blind_heartbeat"].Put(uint32(0), now)
}

// BlindQuiet counts the refusals made while blind that were not reported
// one by one: repeats, within a second, of one pod's refusal of one action
// on one file. Every one of them was refused.
func (s *Sensor) BlindQuiet() (uint64, error) {
	m := s.coll.Maps["blind_quiet"]
	if m == nil {
		return 0, nil
	}
	var per []uint64
	if err := m.Lookup(uint32(0), &per); err != nil {
		return 0, fmt.Errorf("read blind_quiet: %w", err)
	}
	var n uint64
	for _, v := range per {
		n += v
	}
	return n, nil
}

// BlindTimes returns the last heartbeat and the last time the kernel saw an
// agent go down, in boot-clock ns.
func (s *Sensor) BlindTimes() (heartbeat, down uint64, err error) {
	if err := s.coll.Maps["blind_heartbeat"].Lookup(uint32(0), &heartbeat); err != nil {
		return 0, 0, fmt.Errorf("read blind_heartbeat: %w", err)
	}
	if err := s.coll.Maps["blind_down"].Lookup(uint32(0), &down); err != nil {
		return 0, 0, fmt.Errorf("read blind_down: %w", err)
	}
	return heartbeat, down, nil
}

// SetBlindCgroups names the cgroups pods live under; blind mode applies
// below them only.
func (s *Sensor) SetBlindCgroups(ids []uint64) error {
	return replace(s.coll.Maps["blind_cgroups"], idSet(ids))
}

// SetBlindProtect names the cgroups blind mode leaves alone: those of the
// pods the operator trusts. The agent's own is not among them: while the
// sensor is blind, the agent is not there to need it.
func (s *Sensor) SetBlindProtect(ids []uint64) error {
	return replace(s.coll.Maps["blind_protect"], idSet(ids))
}

// Enforcement reads the mode and action bits now in force.
func (s *Sensor) Enforcement() (mode, actions uint32) {
	var cfg tephraEnforceCfg
	if err := s.coll.Maps["enforce_cfg"].Lookup(uint32(0), &cfg); err != nil {
		return EnforceOff, 0
	}
	return cfg.Mode, cfg.Actions
}

func idSet(ids []uint64) map[uint64]uint8 {
	out := make(map[uint64]uint8, len(ids))
	for _, id := range ids {
		out[id] = 1
	}
	return out
}

// SetEnforceCgroups makes enforcement apply to exactly these cgroups and
// what is below them.
func (s *Sensor) SetEnforceCgroups(ids []uint64) error {
	return replace(s.coll.Maps["enforce_cgroups"], idSet(ids))
}

// SetProtectCgroups names the cgroups that are never refused anything. The
// agent's own is always among them.
func (s *Sensor) SetProtectCgroups(ids []uint64) error {
	return replace(s.coll.Maps["protect_cgroups"], idSet(append(ids, s.self.CgroupID)))
}

// FileID identifies a file; Dev is in the kernel's encoding.
type FileID struct {
	Dev   uint32
	Inode uint64
}

// SetRuntimeFiles tells the enforcement programs which files are the node's
// container runtime.
func (s *Sensor) SetRuntimeFiles(ids []FileID) error {
	want := make(map[tephraInodeKey]uint8, len(ids))
	for _, id := range ids {
		want[tephraInodeKey{Inode: id.Inode, Dev: id.Dev}] = 1
	}
	return replace(s.coll.Maps["runtime_inodes"], want)
}

// PinnedEnforcement reads the mode and action bits from the pinned policy
// map.
func PinnedEnforcement(pinDir string) (mode, actions uint32, pinned bool, err error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "enforce_cfg"), nil)
	if errors.Is(err, os.ErrNotExist) {
		return 0, 0, false, nil
	}
	if err != nil {
		return 0, 0, false, err
	}
	defer func() { _ = m.Close() }()
	var cfg tephraEnforceCfg
	if err := m.Lookup(uint32(0), &cfg); err != nil {
		return 0, 0, true, err
	}
	return cfg.Mode, cfg.Actions, true, nil
}

// KillSwitch turns enforcement and blind mode off through the pinned maps,
// without the agent: the next refusal does not happen. It is the way out
// when no agent can run on the node to do it. The next agent sets both again
// from its configuration. It reports whether anything was pinned.
func KillSwitch(pinDir string) (bool, error) {
	pinned := false
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "enforce_cfg"), nil)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return false, err
	default:
		pinned = true
		defer func() { _ = m.Close() }()
		var cfg tephraEnforceCfg
		if err := m.Lookup(uint32(0), &cfg); err != nil {
			return true, err
		}
		cfg.Mode = EnforceOff
		if err := m.Put(uint32(0), &cfg); err != nil {
			return true, err
		}
	}
	b, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "blind_cfg"), nil)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return pinned, nil
	case err != nil:
		return pinned, err
	}
	defer func() { _ = b.Close() }()
	var bc tephraBlindCfg
	if err := b.Lookup(uint32(0), &bc); err != nil {
		return true, err
	}
	bc.Mode = BlindOff
	return true, b.Put(uint32(0), &bc)
}
