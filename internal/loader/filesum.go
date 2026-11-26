// SPDX-License-Identifier: Apache-2.0

package loader

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"

	"github.com/tephrasec/tephra/internal/events"
)

// FileSumKey names one file summary: the opens of one file by one program in
// one cgroup, for reading or for writing.
type FileSumKey = tephraFileSumKey

// fileSumHead is the size of the counts before the first open's record in
// struct file_sum_val.
const fileSumHead = 32

// FileSummary is what the kernel counted for a key while the ring buffer was
// under pressure.
type FileSummary struct {
	Key FileSumKey
	// Count is the opens that were not sent as records: counted in a
	// window, or sent when the buffer was full.
	Count uint64
	// WindowNS and LastNS are boot times: the start of the window and the
	// last open counted.
	WindowNS, LastNS uint64
	// Delivered says a record of the key reached the ring buffer. When it
	// did not, the summary is the only trace of these opens.
	Delivered bool
	// First is the open that created the entry, with its process and path.
	First *events.FileOpen
}

// SetFileSummaryWindow turns file summaries on with the window given, or off
// with zero.
func (s *Sensor) SetFileSummaryWindow(d time.Duration) error {
	m := s.coll.Maps["file_sum_cfg"]
	if m == nil {
		return errors.New("file_sum_cfg map missing")
	}
	return m.Put(uint32(0), uint64(d))
}

// FileSummaryKeys lists the keys counted so far.
func (s *Sensor) FileSummaryKeys() ([]FileSumKey, error) {
	var (
		k   FileSumKey
		out []FileSumKey
	)
	it := s.coll.Maps["file_summary"].Iterate()
	var v []byte
	for it.Next(&k, &v) {
		out = append(out, k)
	}
	return out, it.Err()
}

// TakeFileSummary removes a key's entry and returns it; ok is false when it
// was already gone. The kernel starts a new entry with the key's next open.
func (s *Sensor) TakeFileSummary(k FileSumKey) (FileSummary, bool, error) {
	var raw []byte
	err := s.coll.Maps["file_summary"].LookupAndDelete(&k, &raw)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return FileSummary{}, false, nil
	}
	if err != nil {
		return FileSummary{}, false, err
	}
	sum, err := decodeFileSum(k, raw)
	return sum, err == nil, err
}

func decodeFileSum(k FileSumKey, raw []byte) (FileSummary, error) {
	if len(raw) <= fileSumHead {
		return FileSummary{}, fmt.Errorf("file summary of %d bytes", len(raw))
	}
	le := binary.LittleEndian
	sum := FileSummary{
		Key:       k,
		Count:     le.Uint64(raw[0:]),
		WindowNS:  le.Uint64(raw[8:]),
		LastNS:    le.Uint64(raw[16:]),
		Delivered: le.Uint32(raw[24:]) != 0,
	}
	ev, err := events.Decode(raw[fileSumHead:])
	if err != nil {
		return FileSummary{}, fmt.Errorf("file summary record: %w", err)
	}
	f, ok := ev.(*events.FileOpen)
	if !ok {
		return FileSummary{}, fmt.Errorf("file summary holds a %s record", ev.Hdr().Type)
	}
	sum.First = f
	return sum, nil
}

// FileSummaryCounts returns the opens counted instead of sent, and those
// under pressure the map had no room for.
func (s *Sensor) FileSummaryCounts() (counted, full uint64, err error) {
	m := s.coll.Maps["file_sum_count"]
	for i, dst := range []*uint64{&counted, &full} {
		var per []uint64
		if err := m.Lookup(uint32(i), &per); err != nil {
			return 0, 0, fmt.Errorf("read file_sum_count: %w", err)
		}
		for _, n := range per {
			*dst += n
		}
	}
	return counted, full, nil
}
