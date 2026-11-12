// SPDX-License-Identifier: Apache-2.0

// Package loader loads the embedded eBPF programs into the kernel, attaches
// them and gives the agent access to their maps.
package loader

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/Naved124/tephra/internal/events"
	"github.com/Naved124/tephra/internal/filter"
)

// DefaultRingBufSize is the size of the events ring buffer in bytes.
const DefaultRingBufSize = 16 << 20

// Options configure Load.
type Options struct {
	// RingBufSize is the events ring buffer size in bytes. It must be a
	// power of two and a multiple of the page size. Zero means the default.
	RingBufSize uint32
	// Enabled lists the event types to emit. Nil means every type. Exec,
	// fork and exit are always on: the process tree is built from them.
	Enabled []events.Type
	// Filters are written before anything attaches.
	Filters filter.Set
}

// Attachment describes one attached program.
type Attachment struct {
	Program string
	Hook    string
}

// Skipped describes a program that was left out, and why.
type Skipped struct {
	Program string
	Hook    string
	Reason  string
}

// Self is where the agent sits, as seen by the kernel.
type Self struct {
	// CgroupID is the agent's own cgroup; its events are never emitted.
	CgroupID uint64
	// PidNSLevel and PidNSInum identify the node's pid namespace. Level 0
	// is the root namespace; a kind node is one level down.
	PidNSLevel uint32
	PidNSInum  uint32
}

// Stats mirrors struct stats_val in bpf/common.h.
type Stats struct {
	Seen     uint64
	Filtered uint64
	Emitted  uint64
	Dropped  uint64
}

// hook is one program and what depends on it.
type hook struct {
	program string
	section string
	// required hooks stop the agent when they cannot load. The others
	// only disable their event types.
	required bool
	types    []events.Type
	// kfunc is the kernel function an fentry or fexit program attaches
	// to; params, if non-zero, is the argument count the program was
	// written for.
	kfunc  string
	params int
	// group names hooks that deliver the same events. Only the first of
	// a group that the kernel takes is attached.
	group string
}

var hooks = []hook{
	{program: "tephra_fork", section: "tp_btf/sched_process_fork", required: true, types: []events.Type{events.TypeFork}},
	{program: "tephra_exec", section: "tp_btf/sched_process_exec", required: true, types: []events.Type{events.TypeExec}},
	{program: "tephra_exit", section: "tp_btf/sched_process_exit", required: true, types: []events.Type{events.TypeExit}},
	{program: "tephra_connect", section: "fentry/security_socket_connect", kfunc: "security_socket_connect",
		types: []events.Type{events.TypeConnect, events.TypeUnixConnect}},
	{program: "tephra_accept", section: "fentry/security_sock_graft", kfunc: "security_sock_graft", group: "accept",
		types: []events.Type{events.TypeAccept}},
	{program: "tephra_accept_v1", section: "fexit/inet_csk_accept", kfunc: "inet_csk_accept", params: 4, group: "accept",
		types: []events.Type{events.TypeAccept}},
	{program: "tephra_accept_v2", section: "fexit/inet_csk_accept", kfunc: "inet_csk_accept", params: 2, group: "accept",
		types: []events.Type{events.TypeAccept}},
	{program: "tephra_file_open", section: "fentry/security_file_open", kfunc: "security_file_open",
		types: []events.Type{events.TypeFileOpen}},
	{program: "tephra_ptrace", section: "fentry/security_ptrace_access_check", kfunc: "security_ptrace_access_check",
		types: []events.Type{events.TypePtrace}},
	{program: "tephra_memfd", section: "fentry/__x64_sys_memfd_create", kfunc: "__x64_sys_memfd_create",
		types: []events.Type{events.TypeMemfd}},
	{program: "tephra_module", section: "tp_btf/module_load", types: []events.Type{events.TypeModuleLoad}},
	{program: "tephra_bpf", section: "fentry/security_bpf", kfunc: "security_bpf",
		types: []events.Type{events.TypeBPFLoad}},
	// commit_creds is not a stable interface; of all the hooks it is the
	// likeliest to be missing on some kernel.
	{program: "tephra_cred", section: "fentry/commit_creds", kfunc: "commit_creds",
		types: []events.Type{events.TypeCredChange}},
	{program: "tephra_mount", section: "fentry/security_sb_mount", kfunc: "security_sb_mount",
		types: []events.Type{events.TypeMount}},
	{program: "tephra_setns", section: "fentry/switch_task_namespaces", kfunc: "switch_task_namespaces",
		types: []events.Type{events.TypeSetns}},
}

// brokenHook, when set by a test, names a program whose kernel function is
// replaced by one that does not exist.
var brokenHook string

// Sensor owns the loaded programs and their links. Links are held open and not
// pinned: when the agent exits the kernel detaches everything.
type Sensor struct {
	coll        *ebpf.Collection
	links       []link.Link
	attachments []Attachment
	skipped     []Skipped
	available   map[events.Type]bool
	self        Self
	reader      *ringbuf.Reader
}

// Spec returns the embedded collection spec, for tests that check layouts.
func Spec() (*ebpf.CollectionSpec, error) {
	return loadTephra()
}

// Load loads the collection, tells the kernel side where the agent sits, and
// attaches every program the kernel can take.
func Load(opts Options) (*Sensor, error) {
	size := opts.RingBufSize
	if size == 0 {
		size = DefaultRingBufSize
	}
	if size&(size-1) != 0 || size%uint32(os.Getpagesize()) != 0 {
		return nil, fmt.Errorf("ring buffer size %d is not a power of two multiple of the page size", size)
	}

	// Needed on kernels that account BPF memory against RLIMIT_MEMLOCK
	// (before 5.11); a no-op on newer ones.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock limit: %w", err)
	}

	spec, err := loadTephra()
	if err != nil {
		return nil, fmt.Errorf("read embedded BPF object: %w", err)
	}
	spec.Maps["events"].MaxEntries = size

	s := &Sensor{available: map[events.Type]bool{}}
	keep := s.precheck(spec)
	if s.coll, keep, err = s.load(spec, keep); err != nil {
		return nil, err
	}
	for _, h := range keep {
		for _, t := range h.types {
			s.available[t] = true
		}
	}

	if err := s.configure(opts); err != nil {
		_ = s.Close()
		return nil, err
	}

	// The reader exists before anything attaches, so no event is produced
	// without a consumer.
	s.reader, err = ringbuf.NewReader(s.coll.Maps["events"])
	if err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("open ring buffer: %w", err)
	}

	served := map[string]string{}
	for _, h := range keep {
		if by, ok := served[h.group]; ok && h.group != "" {
			s.skipped = append(s.skipped, Skipped{Program: h.program, Hook: h.section, Reason: "fallback not needed: " + by + " is attached"})
			continue
		}
		l, err := link.AttachTracing(link.TracingOptions{Program: s.coll.Programs[h.program]})
		if err != nil {
			if h.required {
				_ = s.Close()
				return nil, fmt.Errorf("attach %s: %w", h.program, err)
			}
			s.skip(h, "attach failed: "+err.Error())
			continue
		}
		s.links = append(s.links, l)
		s.attachments = append(s.attachments, Attachment{Program: h.program, Hook: h.section})
		served[h.group] = h.program
	}
	// A type whose hook failed to attach is off; rewrite the bitmask.
	s.settle()
	if err := s.SetEnabled(opts.Enabled); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

func (s *Sensor) skip(h hook, reason string) {
	s.skipped = append(s.skipped, Skipped{Program: h.program, Hook: h.section, Reason: reason})
}

// settle works out which event types ended up with an attached hook.
func (s *Sensor) settle() {
	s.available = map[events.Type]bool{}
	for _, a := range s.attachments {
		for _, h := range hooks {
			if h.program == a.Program {
				for _, t := range h.types {
					s.available[t] = true
				}
			}
		}
	}
}

// precheck drops the programs whose kernel function is missing or has a
// different argument list, using the kernel's own BTF. If the BTF cannot be
// read every program is kept and the load itself decides.
func (s *Sensor) precheck(spec *ebpf.CollectionSpec) []hook {
	kernel, err := btf.LoadKernelSpec()
	var keep []hook
	for _, h := range hooks {
		if h.kfunc == "" || err != nil {
			keep = append(keep, h)
			continue
		}
		var fn *btf.Func
		if h.program == brokenHook {
			h.kfunc = "tephra_no_such_function"
		}
		if err := kernel.TypeByName(h.kfunc, &fn); err != nil {
			s.drop(spec, h, "kernel has no function "+h.kfunc)
			continue
		}
		if proto, ok := fn.Type.(*btf.FuncProto); ok && h.params != 0 && len(proto.Params) != h.params {
			s.drop(spec, h, fmt.Sprintf("%s takes %d arguments on this kernel, this variant is for %d", h.kfunc, len(proto.Params), h.params))
			continue
		}
		keep = append(keep, h)
	}
	return keep
}

func (s *Sensor) drop(spec *ebpf.CollectionSpec, h hook, reason string) {
	delete(spec.Programs, h.program)
	s.skipped = append(s.skipped, Skipped{Program: h.program, Hook: h.section, Reason: reason})
}

// load creates the collection. When the kernel rejects an optional program,
// that program is dropped and the load is tried again without it, so one
// unusable hook costs only its own event type.
func (s *Sensor) load(spec *ebpf.CollectionSpec, keep []hook) (*ebpf.Collection, []hook, error) {
	for {
		coll, err := ebpf.NewCollection(spec)
		if err == nil {
			return coll, keep, nil
		}
		culprit := -1
		for i, h := range keep {
			if !h.required && strings.Contains(err.Error(), "program "+h.program+":") {
				culprit = i
			}
		}
		if culprit < 0 {
			var ve *ebpf.VerifierError
			if errors.As(err, &ve) {
				// Include the whole verifier log; the default message truncates it.
				return nil, nil, fmt.Errorf("verifier rejected program: %w\n%s", err, strings.Join(ve.Log, "\n"))
			}
			return nil, nil, fmt.Errorf("load BPF objects: %w", err)
		}
		s.drop(spec, keep[culprit], "load failed: "+firstLine(err.Error()))
		keep = append(keep[:culprit:culprit], keep[culprit+1:]...)
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// configure runs tephra_self in the agent's context, then writes cfg, the
// agent's own cgroup into cgroup_ignore, and the filters. It must finish
// before any program attaches.
func (s *Sensor) configure(opts Options) error {
	ret, err := s.coll.Programs["tephra_self"].Run(&ebpf.RunOptions{})
	if err != nil {
		return fmt.Errorf("run tephra_self: %w", err)
	}
	if ret != 0 {
		return fmt.Errorf("tephra_self could not read the agent's pid namespace (code %d)", ret)
	}
	var info tephraSelfInfo
	if err := s.coll.Maps["self"].Lookup(uint32(0), &info); err != nil {
		return fmt.Errorf("read self map: %w", err)
	}
	s.self = Self{CgroupID: info.CgroupId, PidNSLevel: info.PidnsLevel, PidNSInum: info.PidnsInum}

	if err := s.SetEnabled(opts.Enabled); err != nil {
		return err
	}
	if err := s.coll.Maps["cgroup_ignore"].Put(info.CgroupId, uint8(1)); err != nil {
		return fmt.Errorf("write cgroup_ignore map: %w", err)
	}
	return s.SetFilters(opts.Filters)
}

// SetEnabled chooses the event types the kernel emits. Nil means every type
// that has a hook. Exec, fork and exit stay on whatever is asked.
func (s *Sensor) SetEnabled(types []events.Type) error {
	if types == nil {
		types = events.Types
	}
	types = append([]events.Type{events.TypeExec, events.TypeFork, events.TypeExit}, types...)
	var enabled uint64
	for _, t := range types {
		if s.available[t] {
			enabled |= 1 << uint(t)
		}
	}
	cfg := tephraTephraCfg{Enabled: enabled, PidnsLevel: s.self.PidNSLevel, PidnsInum: s.self.PidNSInum}
	if err := s.coll.Maps["cfg"].Put(uint32(0), &cfg); err != nil {
		return fmt.Errorf("write cfg map: %w", err)
	}
	return nil
}

// Enabled reports whether the kernel is emitting an event type.
func (s *Sensor) Enabled(t events.Type) bool {
	var cfg tephraTephraCfg
	if err := s.coll.Maps["cfg"].Lookup(uint32(0), &cfg); err != nil {
		return false
	}
	return cfg.Enabled&(1<<uint(t)) != 0
}

// Attachments lists what is attached.
func (s *Sensor) Attachments() []Attachment {
	return s.attachments
}

// Skipped lists the programs that were left out.
func (s *Sensor) Skipped() []Skipped {
	return s.skipped
}

// Available reports whether an event type has an attached hook.
func (s *Sensor) Available(t events.Type) bool {
	return s.available[t]
}

// Self reports the agent's cgroup and pid namespace.
func (s *Sensor) Self() Self {
	return s.self
}

// Events returns the ring buffer reader. Closing the sensor unblocks a
// pending Read with ringbuf.ErrClosed.
func (s *Sensor) Events() *ringbuf.Reader {
	return s.reader
}

// ReadStats returns the counters for one event type, summed over all CPUs.
func (s *Sensor) ReadStats(t events.Type) (Stats, error) {
	var perCPU []tephraStatsVal
	if err := s.coll.Maps["stats"].Lookup(uint32(t), &perCPU); err != nil {
		return Stats{}, fmt.Errorf("read stats[%d]: %w", t, err)
	}
	var total Stats
	for _, v := range perCPU {
		total.Seen += v.Seen
		total.Filtered += v.Filtered
		total.Emitted += v.Emitted
		total.Dropped += v.Dropped
	}
	return total, nil
}

// Close detaches all programs and frees the maps.
func (s *Sensor) Close() error {
	var errs []error
	for _, l := range s.links {
		errs = append(errs, l.Close())
	}
	s.links = nil
	if s.reader != nil {
		errs = append(errs, s.reader.Close())
		s.reader = nil
	}
	if s.coll != nil {
		s.coll.Close()
		s.coll = nil
	}
	return errors.Join(errs...)
}
