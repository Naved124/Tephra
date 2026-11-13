// SPDX-License-Identifier: Apache-2.0

package loader

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/Naved124/tephra/internal/filter"
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
)

// DefaultPinDir is where enforcement is pinned.
const DefaultPinDir = "/sys/fs/bpf/tephra"

// lsmActions says which actions each enforcement program refuses.
var lsmActions = map[string][]uint32{
	"tephra_lsm_exec":      {ActionExecUnlinked},
	"tephra_lsm_file_open": {ActionFileWrite},
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
var pinnedMaps = []string{"enforce_cfg", "enforce_cgroups", "protect_cgroups", "runtime_inodes", "runtime_tasks"}

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
// attached, and if not, why.
func (s *Sensor) EnforcementAvailable() (bool, string) {
	return s.enforceOff == "", s.enforceOff
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
	if s.pinDir == "" {
		return ebpf.NewCollection(spec)
	}
	if err := os.MkdirAll(s.pinDir, 0o700); err != nil {
		return nil, fmt.Errorf("enforcement pin directory: %w", err)
	}
	adopt := map[string]*ebpf.Map{}
	defer func() {
		for _, m := range adopt {
			_ = m.Close()
		}
	}()
	for _, name := range pinnedMaps {
		m, err := ebpf.LoadPinnedMap(filepath.Join(s.pinDir, name), nil)
		if err == nil {
			adopt[name] = m
		}
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{MapReplacements: adopt})
	if err != nil && len(adopt) > 0 && errors.Is(err, ebpf.ErrMapIncompatible) {
		// Pinned by a version with another layout: start again from
		// nothing. Enforcement by the old programs ends here.
		unpinAll(s.pinDir)
		coll, err = ebpf.NewCollection(spec)
	}
	if err != nil {
		return nil, err
	}
	for _, name := range pinnedMaps {
		if _, adopted := adopt[name]; adopted {
			continue
		}
		path := filepath.Join(s.pinDir, name)
		_ = os.Remove(path)
		if err := coll.Maps[name].Pin(path); err != nil {
			coll.Close()
			return nil, fmt.Errorf("pin %s: %w", name, err)
		}
	}
	return coll, nil
}

// pinLink replaces the pinned link of an enforcement program with the new
// one. The new program is attached already, so the hook is never left
// without one.
func (s *Sensor) pinLink(h hook, l link.Link) error {
	if s.pinDir == "" {
		return nil
	}
	path := filepath.Join(s.pinDir, "link_"+h.program)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = l.Close()
		return fmt.Errorf("replace pinned link: %w", err)
	}
	if err := l.Pin(path); err != nil {
		_ = l.Close()
		return fmt.Errorf("pin link: %w", err)
	}
	return nil
}

// unpinAll removes everything pinned in dir, which detaches the enforcement
// programs an earlier agent left behind.
func unpinAll(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
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

// KillSwitch turns enforcement off through the pinned map, without the
// agent: the next refusal does not happen. It reports whether anything was
// pinned.
func KillSwitch(pinDir string) (bool, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "enforce_cfg"), nil)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = m.Close() }()
	var cfg tephraEnforceCfg
	if err := m.Lookup(uint32(0), &cfg); err != nil {
		return true, err
	}
	cfg.Mode = EnforceOff
	return true, m.Put(uint32(0), &cfg)
}
