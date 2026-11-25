// SPDX-License-Identifier: Apache-2.0

package loader

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"

	"github.com/Naved124/tephra/internal/events"
)

// Directions of a quiet mark, NET_QUIET_* in bpf/common.h.
const (
	QuietOut uint32 = 1
	QuietIn  uint32 = 2
	// QuietLoopback limits the mark to connections to a loopback address.
	QuietLoopback uint32 = 4
)

// QuietMark is what a quiet mark was judged on. The kernel applies it only
// while the process still matches every field.
type QuietMark struct {
	StartNS  uint64
	CgroupID uint64
	ExecID   uint64
	PPID     uint32
	UID      uint32
	GID      uint32
	Dirs     uint32
}

// MarkOf builds the mark for the process a connect or accept event came
// from.
func MarkOf(ev *events.Net, dirs uint32) QuietMark {
	return QuietMark{
		StartNS: ev.StartTimeNS, CgroupID: ev.CgroupID, ExecID: ev.ExecID,
		PPID: ev.PPID, UID: ev.UID, GID: ev.GID, Dirs: dirs,
	}
}

// SetQuiet marks a process, by its pid in the node's namespace.
func (s *Sensor) SetQuiet(pid uint32, m QuietMark) error {
	return s.coll.Maps["net_quiet"].Put(pid, tephraNetQuietVal{
		StartTimeNs: m.StartNS, CgroupId: m.CgroupID, ExecId: m.ExecID,
		Ppid: m.PPID, Uid: m.UID, Gid: m.GID, Dirs: m.Dirs,
	})
}

// ClearQuiet removes a process's mark, if it has one.
func (s *Sensor) ClearQuiet(pid uint32) error {
	err := s.coll.Maps["net_quiet"].Delete(pid)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

// ClearAllQuiet removes every mark: every connection is reported again
// until processes are judged anew.
func (s *Sensor) ClearAllQuiet() error {
	return replace(s.coll.Maps["net_quiet"], map[uint32]tephraNetQuietVal{})
}

// SetAlwaysReport makes the kernel report connects to these destination
// ports and these addresses from every process, quiet or not.
func (s *Sensor) SetAlwaysReport(ports []uint16, dsts []netip.AddrPort) error {
	pm := make(map[uint16]uint8, len(ports))
	for _, p := range ports {
		pm[p] = 1
	}
	dm := make(map[tephraNetDstKey]uint8, len(dsts))
	for _, d := range dsts {
		k := tephraNetDstKey{Port: d.Port()}
		if a := d.Addr().Unmap(); a.Is4() {
			k.Family = events.AFInet
			a4 := a.As4()
			copy(k.Addr[:], a4[:])
		} else {
			k.Family = events.AFInet6
			k.Addr = a.As16()
		}
		dm[k] = 1
	}
	if err := replace(s.coll.Maps["net_always_port"], pm); err != nil {
		return fmt.Errorf("write net_always_port map: %w", err)
	}
	if err := replace(s.coll.Maps["net_always_dst"], dm); err != nil {
		return fmt.Errorf("write net_always_dst map: %w", err)
	}
	return nil
}

// QuietCount is how many connections the kernel skipped as quiet, summed
// over CPUs.
func (s *Sensor) QuietCount() (uint64, error) {
	var perCPU []uint64
	if err := s.coll.Maps["net_quiet_count"].Lookup(uint32(0), &perCPU); err != nil {
		return 0, err
	}
	var n uint64
	for _, v := range perCPU {
		n += v
	}
	return n, nil
}

// SetRingWakeup sets how many bytes may wait in the ring buffer before the
// kernel wakes the agent; 0 wakes it for every record that finds it caught
// up. With a batch the agent must also read on a timer.
func (s *Sensor) SetRingWakeup(bytes uint32) error {
	return s.coll.Maps["ring_wakeup"].Put(uint32(0), bytes)
}
