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
	// QuietSummary has the kernel count the skipped connections in
	// net_summary, and emit any it has no room to count.
	QuietSummary uint32 = 4
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
func (s *Sensor) QuietCount() (uint64, error) { return s.quietCounter(0) }

// SummaryFull is how many connections of quiet processes were emitted after
// all because the summary map had no room to count them.
func (s *Sensor) SummaryFull() (uint64, error) { return s.quietCounter(1) }

func (s *Sensor) quietCounter(i uint32) (uint64, error) {
	var perCPU []uint64
	if err := s.coll.Maps["net_quiet_count"].Lookup(i, &perCPU); err != nil {
		return 0, err
	}
	var n uint64
	for _, v := range perCPU {
		n += v
	}
	return n, nil
}

// SummaryKey identifies one counted destination of one process.
type SummaryKey = tephraNetSumKey

// Summary is the count of a quiet process's connections to one destination.
type Summary struct {
	Key  SummaryKey
	Type uint32 // events.TypeConnect or events.TypeAccept
	PID  uint32
	// StartNS, with PID, is the process key.
	StartNS uint64
	// Remote is the peer's address. Port is the peer's port for a connect
	// and the local, listening port for an accept.
	Remote   netip.Addr
	Port     uint16
	Family   uint16
	Proto    uint8
	Count    uint64
	FirstNS  uint64 // boot time of the first and last connection
	LastNS   uint64
	CgroupID uint64
	ExecID   uint64
	PPID     uint32
	UID      uint32
	GID      uint32
	PidNS    uint32
	MntNS    uint32
	NetNS    uint32
	Comm     string
}

func summaryOf(k tephraNetSumKey, v tephraNetSumVal) Summary {
	var addr netip.Addr
	if k.Family == events.AFInet {
		addr = netip.AddrFrom4([4]byte(k.Addr[:4]))
	} else {
		addr = netip.AddrFrom16(k.Addr)
	}
	return Summary{
		Key: k, Type: uint32(k.Type), PID: k.Pid, StartNS: k.StartTimeNs,
		Remote: addr, Port: k.Port, Family: k.Family, Proto: k.Proto,
		Count: v.Count, FirstNS: v.FirstNs, LastNS: v.LastNs,
		CgroupID: v.CgroupId, ExecID: v.ExecId, PPID: v.Ppid, UID: v.Uid, GID: v.Gid,
		PidNS: v.PidNs, MntNS: v.MntNs, NetNS: v.NetNs, Comm: cString(v.Comm[:]),
	}
}

// Summaries returns every counted destination. The counts keep growing in
// the kernel; TakeSummary removes one.
func (s *Sensor) Summaries() ([]Summary, error) {
	var (
		k   tephraNetSumKey
		v   tephraNetSumVal
		out []Summary
	)
	it := s.coll.Maps["net_summary"].Iterate()
	for it.Next(&k, &v) {
		out = append(out, summaryOf(k, v))
	}
	return out, it.Err()
}

// SummarySent is how much of one count the agent has reported.
type SummarySent struct {
	Count  uint64
	LastNS uint64
}

// SentSummaries returns what earlier reads reported, including those of an
// earlier agent when the maps were adopted.
func (s *Sensor) SentSummaries() (map[SummaryKey]SummarySent, error) {
	var (
		k   tephraNetSumKey
		v   tephraNetSumSent
		out = map[SummaryKey]SummarySent{}
	)
	it := s.coll.Maps["net_summary_sent"].Iterate()
	for it.Next(&k, &v) {
		out[k] = SummarySent{Count: v.Count, LastNS: v.LastNs}
	}
	return out, it.Err()
}

// SetSent records how much of a count was reported.
func (s *Sensor) SetSent(k SummaryKey, v SummarySent) error {
	return s.coll.Maps["net_summary_sent"].Put(k, tephraNetSumSent{Count: v.Count, LastNs: v.LastNS})
}

// ForgetSent removes what was recorded for a count that was taken.
func (s *Sensor) ForgetSent(k SummaryKey) error {
	err := s.coll.Maps["net_summary_sent"].Delete(k)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

// TakeSummary removes a counted destination and returns its final count.
// ok is false when it was already gone.
func (s *Sensor) TakeSummary(k SummaryKey) (sum Summary, ok bool, err error) {
	var v tephraNetSumVal
	err = s.coll.Maps["net_summary"].LookupAndDelete(&k, &v)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return Summary{}, false, nil
	}
	if err != nil {
		return Summary{}, false, err
	}
	return summaryOf(k, v), true, nil
}

// SetRingWakeup sets how many bytes may wait in the ring buffer before the
// kernel wakes the agent; 0 wakes it for every record that finds it caught
// up. With a batch the agent must also read on a timer.
func (s *Sensor) SetRingWakeup(bytes uint32) error {
	return s.coll.Maps["ring_wakeup"].Put(uint32(0), bytes)
}

// cString reads a NUL-terminated C string from a fixed-size field.
func cString(b []int8) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		out = append(out, byte(c))
	}
	return string(out)
}
