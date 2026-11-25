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

	"github.com/Naved124/tephra/internal/events"
)

// DefaultDetectPinDir is where detection is pinned when it is kept running
// across the agent's death.
const DefaultDetectPinDir = DefaultPinDir + "/detect"

// detectMaps outlive an agent that did not stop cleanly: the detection
// programs it attached keep writing events into the ring buffer, and the
// next agent adopts the buffer and reads what was recorded meanwhile. The
// connections they counted for quiet processes are adopted the same way.
var detectMaps = []string{"events", "stats", "net_summary", "net_summary_sent"}

// adoptPinned opens the maps pinned in dir, creating dir. It returns no maps
// when dir is empty.
func adoptPinned(dir string, names []string) (map[string]*ebpf.Map, error) {
	adopt := map[string]*ebpf.Map{}
	if dir == "" {
		return adopt, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	for _, name := range names {
		if m, err := ebpf.LoadPinnedMap(filepath.Join(dir, name), nil); err == nil {
			adopt[name] = m
		}
	}
	return adopt, nil
}

func closeMaps(maps map[string]*ebpf.Map) {
	for _, m := range maps {
		_ = m.Close()
	}
}

// pinNew pins the maps of coll that were not adopted.
func pinNew(coll *ebpf.Collection, dir string, names []string, adopted map[string]*ebpf.Map) error {
	if dir == "" {
		return nil
	}
	for _, name := range names {
		if _, ok := adopted[name]; ok {
			continue
		}
		path := filepath.Join(dir, name)
		_ = os.Remove(path)
		if err := coll.Maps[name].Pin(path); err != nil {
			return fmt.Errorf("pin %s: %w", name, err)
		}
	}
	return nil
}

// replaceLink pins l at dir/link_<program>, in place of the link an earlier
// agent pinned there. The new program is attached already, so the hook is
// never left without one; for a moment both run, and an event can be
// reported twice.
func replaceLink(dir string, h hook, l link.Link) error {
	if dir == "" {
		return nil
	}
	path := filepath.Join(dir, "link_"+h.program)
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

// dropStaleLinks removes pinned detection links of programs this agent did
// not attach, such as a fallback an earlier version used.
func (s *Sensor) dropStaleLinks(attached map[string]bool) {
	if s.detectDir == "" {
		return
	}
	entries, err := os.ReadDir(s.detectDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if prog, ok := strings.CutPrefix(name, "link_"); ok && !attached[prog] {
			_ = os.Remove(filepath.Join(s.detectDir, name))
		}
	}
}

// KeepsRecording reports whether detection is pinned, so that it goes on
// recording if the agent dies without unpinning it.
func (s *Sensor) KeepsRecording() bool { return s.detectDir != "" }

// Backlog reports whether the ring buffer was adopted from an earlier agent,
// and so may hold events recorded while no agent was reading.
func (s *Sensor) Backlog() bool { return s.backlog }

// FreshStart says why pinned detection maps could not be adopted, when they
// could not; empty otherwise.
func (s *Sensor) FreshStart() string { return s.freshStart }

// UnpinDetection removes the detection pins, so that the programs detach
// when the agent closes its links. It is the end of a planned stop.
func (s *Sensor) UnpinDetection() {
	if s.detectDir != "" {
		unpinAll(s.detectDir)
	}
}

// DetectionOff removes detection pinned in dir by an agent that is gone,
// which detaches its programs and frees its ring buffer. It reports whether
// anything was pinned.
func DetectionOff(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	unpinAll(dir)
	if _, err := os.Stat(dir); err == nil {
		return len(entries) > 0, fmt.Errorf("%s could not be removed completely", dir)
	}
	return len(entries) > 0, nil
}

// Own reports whether an event is the agent's own. The programs an earlier
// agent left attached do not know this agent and report it until their links
// are replaced; such events are dropped. The pid in the header is in the
// agent's own pid namespace, the one the sensor reports in.
func (s *Sensor) Own(h *events.Header) bool {
	return h.StartTimeNS == s.self.StartNS && h.PID == uint32(os.Getpid())
}

// layoutPin holds events.LayoutVersion next to the pinned ring buffer.
const layoutPin = "layout"

// pinnedLayout reads the record layout a pinned ring buffer was written in.
func pinnedLayout(dir string) (uint32, bool) {
	if dir == "" {
		return 0, false
	}
	m, err := ebpf.LoadPinnedMap(filepath.Join(dir, layoutPin), nil)
	if err != nil {
		return 0, false
	}
	defer func() { _ = m.Close() }()
	var v uint32
	if err := m.Lookup(uint32(0), &v); err != nil {
		return 0, false
	}
	return v, true
}

// hasPins reports whether any of names is pinned in dir.
func hasPins(dir string, names []string) bool {
	if dir == "" {
		return false
	}
	for _, n := range names {
		if _, err := os.Stat(filepath.Join(dir, n)); err == nil {
			return true
		}
	}
	return false
}

// pinLayout pins the record layout this version writes.
func pinLayout(dir string) error {
	if dir == "" {
		return nil
	}
	m, err := ebpf.NewMap(&ebpf.MapSpec{Name: "tephra_layout", Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	if err != nil {
		return fmt.Errorf("layout map: %w", err)
	}
	defer func() { _ = m.Close() }()
	if err := m.Put(uint32(0), uint32(events.LayoutVersion)); err != nil {
		return fmt.Errorf("layout map: %w", err)
	}
	path := filepath.Join(dir, layoutPin)
	_ = os.Remove(path)
	if err := m.Pin(path); err != nil {
		return fmt.Errorf("pin %s: %w", path, err)
	}
	return nil
}
