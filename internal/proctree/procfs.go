// SPDX-License-Identifier: Apache-2.0

package proctree

import (
	"golang.org/x/sys/unix"

	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Naved124/tephra/internal/k8s"
)

// ProcFS reads process state from a mounted /proc. With hostPID the pids it
// shows are the node's, the same numbers the kernel programs report.
type ProcFS struct {
	Root string // normally "/proc"
}

// Seed walks /proc once and adds every process that events have not already
// described. It returns the number of processes read.
func (t *Tree) Seed(fs ProcFS) (int, error) {
	entries, err := os.ReadDir(fs.Root)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", fs.Root, err)
	}

	var procs []Proc
	ppid := make(map[uint32]uint32)
	start := make(map[uint32]uint64)
	for _, e := range entries {
		pid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		p, parent, err := fs.Read(uint32(pid))
		if err != nil {
			continue // exited during the scan
		}
		procs = append(procs, p)
		ppid[p.Key.PID] = parent
		start[p.Key.PID] = p.Key.StartNS
	}
	// Parents first is not guaranteed by pid order, so link in a second
	// pass.
	for _, p := range procs {
		parent := ppid[p.Key.PID]
		if s, ok := start[parent]; ok {
			p.Parent = Key{parent, s}
		} else {
			p.Parent = Key{PID: parent}
		}
		t.Add(p)
	}
	return len(procs), nil
}

// Lookup adds a single process from /proc, for a pid that events refer to but
// that was never seen starting. The parent link is resolved if the parent is
// already in the tree.
func (t *Tree) Lookup(fs ProcFS, pid uint32) (Proc, bool) {
	if pid == 0 {
		return Proc{}, false
	}
	p, parent, err := fs.Read(pid)
	if err != nil {
		return Proc{}, false
	}
	p.Parent = Key{PID: parent}
	t.mu.Lock()
	if pp, ok := t.byPID[parent]; ok {
		p.Parent = pp.Key
	}
	t.mu.Unlock()
	return t.Add(p), true
}

// ParentOf returns the current parent pid of a live process, checking the
// start time so that a reused pid is not mistaken for it.
func (fs ProcFS) ParentOf(k Key) (uint32, bool) {
	stat, err := os.ReadFile(filepath.Join(fs.Root, strconv.FormatUint(uint64(k.PID), 10), "stat"))
	if err != nil {
		return 0, false
	}
	_, ppid, ticks, err := parseStat(stat)
	if err != nil || ticks != k.StartNS/nsPerTick {
		return 0, false
	}
	return ppid, true
}

// Read returns one process and its parent's pid. The start time is rounded
// down to the clock tick /proc reports.
func (fs ProcFS) Read(pid uint32) (Proc, uint32, error) {
	dir := filepath.Join(fs.Root, strconv.FormatUint(uint64(pid), 10))

	stat, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return Proc{}, 0, err
	}
	comm, ppid, ticks, err := parseStat(stat)
	if err != nil {
		return Proc{}, 0, fmt.Errorf("%s/stat: %w", dir, err)
	}

	p := Proc{
		Key:  Key{pid, ticks * nsPerTick},
		Comm: comm,
	}
	// Kernel threads have no exe link and an empty cmdline; that is not
	// an error.
	if exe, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
		p.Image = strings.TrimSuffix(exe, " (deleted)")
		var st unix.Stat_t
		if unix.Stat(filepath.Join(dir, "exe"), &st) == nil {
			p.ExeDev = unix.Major(st.Dev)<<20 | unix.Minor(st.Dev)
			p.ExeInode = st.Ino
		}
	}
	if cmdline, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil && len(cmdline) > 0 {
		p.Argv = strings.Split(strings.TrimSuffix(string(cmdline), "\x00"), "\x00")
	}
	if status, err := os.ReadFile(filepath.Join(dir, "status")); err == nil {
		p.UID = parseUID(status)
	}
	if cg, err := os.ReadFile(filepath.Join(dir, "cgroup")); err == nil {
		p.ContainerID = k8s.ContainerID(cgroupV2Path(cg))
	}
	return p, ppid, nil
}

// parseStat extracts comm, ppid and starttime (in clock ticks) from
// /proc/<pid>/stat. comm is in parentheses and may itself contain spaces and
// parentheses, so fields are counted from the last ')'.
func parseStat(b []byte) (comm string, ppid uint32, startTicks uint64, err error) {
	open := bytes.IndexByte(b, '(')
	end := bytes.LastIndexByte(b, ')')
	if open < 0 || end < open {
		return "", 0, 0, errors.New("no comm field")
	}
	comm = string(b[open+1 : end])
	// After ')': state(3) ppid(4) ... starttime(22).
	f := strings.Fields(string(b[end+1:]))
	if len(f) < 20 {
		return "", 0, 0, fmt.Errorf("%d fields after comm, want at least 20", len(f))
	}
	pp, err := strconv.ParseUint(f[1], 10, 32)
	if err != nil {
		return "", 0, 0, fmt.Errorf("ppid: %w", err)
	}
	startTicks, err = strconv.ParseUint(f[19], 10, 64)
	if err != nil {
		return "", 0, 0, fmt.Errorf("starttime: %w", err)
	}
	return comm, uint32(pp), startTicks, nil
}

// parseUID returns the real uid from /proc/<pid>/status.
func parseUID(status []byte) uint32 {
	for _, line := range strings.Split(string(status), "\n") {
		if rest, ok := strings.CutPrefix(line, "Uid:"); ok {
			if f := strings.Fields(rest); len(f) > 0 {
				uid, _ := strconv.ParseUint(f[0], 10, 32)
				return uint32(uid)
			}
		}
	}
	return 0
}

// cgroupV2Path returns the unified-hierarchy path from /proc/<pid>/cgroup,
// the line of the form "0::/path".
func cgroupV2Path(b []byte) string {
	for _, line := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			return rest
		}
	}
	return ""
}
