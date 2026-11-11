// SPDX-License-Identifier: Apache-2.0

// Package events holds the Go mirrors of the kernel event structs and the
// decoder that turns ring buffer records into them.
package events

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Type is enum event_type in bpf/common.h.
type Type uint32

// Event types. Values are part of the kernel/agent contract.
const (
	TypeExec Type = 1
	TypeFork Type = 2
	TypeExit Type = 3
)

// Types lists every event type the agent knows.
var Types = []Type{TypeExec, TypeFork, TypeExit}

func (t Type) String() string {
	switch t {
	case TypeExec:
		return "exec"
	case TypeFork:
		return "fork"
	case TypeExit:
		return "exit"
	}
	return fmt.Sprintf("unknown(%d)", uint32(t))
}

// Exec flag bits in Header.Flags, EXEC_F_* in bpf/common.h.
const (
	ExecStdinSock  = 1 << 0
	ExecStdoutSock = 1 << 1
	ExecUnlinked   = 1 << 2
	ExecSetuid     = 1 << 3
	ExecArgvTrunc  = 1 << 4
)

// Header is struct event_hdr. Pids are in the node's pid namespace.
type Header struct {
	TSBootNS    uint64
	StartTimeNS uint64
	CgroupID    uint64
	Type        Type
	Size        uint32
	PID         uint32
	TID         uint32
	PPID        uint32
	UID         uint32
	GID         uint32
	PidNS       uint32
	MntNS       uint32
	Flags       uint32
	Comm        string
}

// Event is any decoded record.
type Event interface {
	Hdr() *Header
}

// Hdr returns the header itself, so every event embedding it is an Event.
func (h *Header) Hdr() *Header { return h }

// Exec is struct exec_event.
type Exec struct {
	Header
	Inode        uint64
	Dev          uint32
	CapEffective uint64
	Path         string
	Argv         []string
}

// Fork is struct fork_event. The header describes the task that called fork.
type Fork struct {
	Header
	ChildPID      uint32
	ParentPID     uint32
	ChildStartNS  uint64
	ParentStartNS uint64
}

// Exit is struct exit_event.
type Exit struct {
	Header
	// Status is the raw wait status: code << 8 | signal.
	Status uint32
}

// Code is the exit code passed to exit().
func (e *Exit) Code() uint32 { return (e.Status >> 8) & 0xff }

// Signal is the signal that killed the process, or 0.
func (e *Exit) Signal() uint32 { return e.Status & 0x7f }

var le = binary.LittleEndian

// Decode parses one ring buffer record.
func Decode(raw []byte) (Event, error) {
	if len(raw) < hdrSize {
		return nil, fmt.Errorf("record of %d bytes is shorter than the header", len(raw))
	}
	h := Header{
		TSBootNS:    le.Uint64(raw[hdrTSBoot:]),
		StartTimeNS: le.Uint64(raw[hdrStartTime:]),
		CgroupID:    le.Uint64(raw[hdrCgroupID:]),
		Type:        Type(le.Uint32(raw[hdrType:])),
		Size:        le.Uint32(raw[hdrRecSize:]),
		PID:         le.Uint32(raw[hdrPID:]),
		TID:         le.Uint32(raw[hdrTID:]),
		PPID:        le.Uint32(raw[hdrPPID:]),
		UID:         le.Uint32(raw[hdrUID:]),
		GID:         le.Uint32(raw[hdrGID:]),
		PidNS:       le.Uint32(raw[hdrPidNS:]),
		MntNS:       le.Uint32(raw[hdrMntNS:]),
		Flags:       le.Uint32(raw[hdrFlags:]),
		Comm:        cstr(raw[hdrComm : hdrComm+commLen]),
	}
	// The ring buffer pads records to 8 bytes, so the sample may be longer
	// than the record, never shorter.
	if int(h.Size) > len(raw) {
		return nil, fmt.Errorf("%s record claims %d bytes, got %d", h.Type, h.Size, len(raw))
	}
	raw = raw[:h.Size]

	switch h.Type {
	case TypeExec:
		return decodeExec(h, raw)
	case TypeFork:
		if len(raw) < forkSize {
			return nil, fmt.Errorf("fork record of %d bytes, want %d", len(raw), forkSize)
		}
		return &Fork{
			Header:        h,
			ChildPID:      le.Uint32(raw[forkChildPID:]),
			ParentPID:     le.Uint32(raw[forkParentPID:]),
			ChildStartNS:  le.Uint64(raw[forkChildStart:]),
			ParentStartNS: le.Uint64(raw[forkParentStart:]),
		}, nil
	case TypeExit:
		if len(raw) < exitSize {
			return nil, fmt.Errorf("exit record of %d bytes, want %d", len(raw), exitSize)
		}
		return &Exit{Header: h, Status: le.Uint32(raw[exitCode:])}, nil
	}
	return nil, fmt.Errorf("unknown event type %d", uint32(h.Type))
}

func decodeExec(h Header, raw []byte) (Event, error) {
	if len(raw) < execArgv {
		return nil, fmt.Errorf("exec record of %d bytes, want at least %d", len(raw), execArgv)
	}
	n := int(le.Uint32(raw[execArgvLen:]))
	if n > argvLen || execArgv+n > len(raw) {
		return nil, fmt.Errorf("exec record of %d bytes cannot hold argv_len %d", len(raw), n)
	}
	return &Exec{
		Header:       h,
		Inode:        le.Uint64(raw[execInode:]),
		Dev:          le.Uint32(raw[execDev:]),
		CapEffective: le.Uint64(raw[execCapEff:]),
		Path:         cstr(raw[execPath : execPath+pathLen]),
		Argv:         splitArgv(raw[execArgv : execArgv+n]),
	}, nil
}

// cstr returns the bytes before the first NUL.
func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// splitArgv splits a NUL-separated argument block. A truncated block may end
// without a NUL; the partial last argument is kept.
func splitArgv(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	if b[len(b)-1] == 0 {
		b = b[:len(b)-1]
	}
	parts := bytes.Split(b, []byte{0})
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = string(p)
	}
	return out
}
