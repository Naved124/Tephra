// SPDX-License-Identifier: Apache-2.0

// Package loader loads the embedded eBPF programs into the kernel, attaches
// them and gives the agent access to their maps.
package loader

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// EventExec mirrors EVENT_EXEC in bpf/common.h.
const EventExec uint32 = 1

// Attachment describes one attached program.
type Attachment struct {
	Program string
	Hook    string
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
}

// Load loads the collection and attaches every program.
func Load() (*Sensor, error) {
	// Needed on kernels that account BPF memory against RLIMIT_MEMLOCK
	// (before 5.11); a no-op on newer ones.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock limit: %w", err)
	}

	s := &Sensor{}
	if err := loadExecObjects(&s.objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			// Include the whole verifier log; the default message truncates it.
			return nil, fmt.Errorf("verifier rejected program: %w\n%s", err, strings.Join(ve.Log, "\n"))
		}
		return nil, fmt.Errorf("load BPF objects: %w", err)
	}

	l, err := link.AttachTracing(link.TracingOptions{Program: s.objs.TephraExec})
	if err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("attach tephra_exec: %w", err)
	}
	s.links = append(s.links, l)
	s.attachments = append(s.attachments, Attachment{
		Program: "tephra_exec",
		Hook:    "tp_btf/sched_process_exec",
	})

	return s, nil
}

// Attachments lists what is attached.
func (s *Sensor) Attachments() []Attachment {
	return s.attachments
}

// ReadStats returns the counters for one event type, summed over all CPUs.
func (s *Sensor) ReadStats(eventType uint32) (Stats, error) {
	var perCPU []execStatsVal
	if err := s.objs.Stats.Lookup(eventType, &perCPU); err != nil {
		return Stats{}, fmt.Errorf("read stats[%d]: %w", eventType, err)
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
	errs = append(errs, s.objs.Close())
	return errors.Join(errs...)
}
