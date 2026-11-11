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
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/Naved124/tephra/internal/events"
)

// DefaultRingBufSize is the size of the events ring buffer in bytes.
const DefaultRingBufSize = 16 << 20

// Options configure Load.
type Options struct {
	// RingBufSize is the events ring buffer size in bytes. It must be a
	// power of two and a multiple of the page size. Zero means the default.
	RingBufSize uint32
}

// Attachment describes one attached program.
type Attachment struct {
	Program string
	Hook    string
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

// Sensor owns the loaded programs and their links. Links are held open and not
// pinned: when the agent exits the kernel detaches everything.
type Sensor struct {
	objs        execObjects
	links       []link.Link
	attachments []Attachment
	self        Self
	reader      *ringbuf.Reader
}

// Spec returns the embedded collection spec, for tests that check layouts.
func Spec() (*ebpf.CollectionSpec, error) {
	return loadExec()
}

// Load loads the collection, tells the kernel side where the agent sits, and
// attaches every program.
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

	spec, err := loadExec()
	if err != nil {
		return nil, fmt.Errorf("read embedded BPF object: %w", err)
	}
	spec.Maps["events"].MaxEntries = size

	s := &Sensor{}
	if err := spec.LoadAndAssign(&s.objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			// Include the whole verifier log; the default message truncates it.
			return nil, fmt.Errorf("verifier rejected program: %w\n%s", err, strings.Join(ve.Log, "\n"))
		}
		return nil, fmt.Errorf("load BPF objects: %w", err)
	}

	if err := s.configure(); err != nil {
		_ = s.Close()
		return nil, err
	}

	// The reader exists before anything attaches, so no event is produced
	// without a consumer.
	s.reader, err = ringbuf.NewReader(s.objs.Events)
	if err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("open ring buffer: %w", err)
	}

	progs := []struct {
		name string
		hook string
		prog *ebpf.Program
	}{
		{"tephra_fork", "tp_btf/sched_process_fork", s.objs.TephraFork},
		{"tephra_exec", "tp_btf/sched_process_exec", s.objs.TephraExec},
		{"tephra_exit", "tp_btf/sched_process_exit", s.objs.TephraExit},
	}
	for _, p := range progs {
		l, err := link.AttachTracing(link.TracingOptions{Program: p.prog})
		if err != nil {
			_ = s.Close()
			return nil, fmt.Errorf("attach %s: %w", p.name, err)
		}
		s.links = append(s.links, l)
		s.attachments = append(s.attachments, Attachment{Program: p.name, Hook: p.hook})
	}

	return s, nil
}

// configure runs tephra_self in the agent's context, then writes cfg and the
// agent's own cgroup into cgroup_ignore. It must finish before any program
// attaches.
func (s *Sensor) configure() error {
	ret, err := s.objs.TephraSelf.Run(&ebpf.RunOptions{})
	if err != nil {
		return fmt.Errorf("run tephra_self: %w", err)
	}
	if ret != 0 {
		return fmt.Errorf("tephra_self could not read the agent's pid namespace (code %d)", ret)
	}
	var info execSelfInfo
	if err := s.objs.Self.Lookup(uint32(0), &info); err != nil {
		return fmt.Errorf("read self map: %w", err)
	}
	s.self = Self{CgroupID: info.CgroupId, PidNSLevel: info.PidnsLevel, PidNSInum: info.PidnsInum}

	var enabled uint64
	for _, t := range []events.Type{events.TypeExec, events.TypeFork, events.TypeExit} {
		enabled |= 1 << uint(t)
	}
	cfg := execTephraCfg{Enabled: enabled, PidnsLevel: info.PidnsLevel, PidnsInum: info.PidnsInum}
	if err := s.objs.Cfg.Put(uint32(0), &cfg); err != nil {
		return fmt.Errorf("write cfg map: %w", err)
	}
	if err := s.objs.CgroupIgnore.Put(info.CgroupId, uint8(1)); err != nil {
		return fmt.Errorf("write cgroup_ignore map: %w", err)
	}
	return nil
}

// Attachments lists what is attached.
func (s *Sensor) Attachments() []Attachment {
	return s.attachments
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
	var perCPU []execStatsVal
	if err := s.objs.Stats.Lookup(uint32(t), &perCPU); err != nil {
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
	errs = append(errs, s.objs.Close())
	return errors.Join(errs...)
}
