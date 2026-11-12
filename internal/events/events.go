// SPDX-License-Identifier: Apache-2.0

// Package events holds the Go mirrors of the kernel event structs and the
// decoder that turns ring buffer records into them.
package events

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
)

// Type is enum event_type in bpf/common.h.
type Type uint32

// Event types. Values are part of the kernel/agent contract.
const (
	TypeExec Type = 1
	TypeFork Type = 2
	TypeExit Type = 3
	// TypeConnect and TypeAccept carry a Net event.
	TypeConnect     Type = 4
	TypeAccept      Type = 5
	TypeUnixConnect Type = 6
	TypeFileOpen    Type = 7
	TypePtrace      Type = 8
	TypeMemfd       Type = 9
	TypeModuleLoad  Type = 10
	TypeBPFLoad     Type = 11
	TypeCredChange  Type = 12
	TypeMount       Type = 13
	TypeSetns       Type = 14
	// TypeFileChange is a watched name removed, renamed, replaced or
	// created as a link; TypeFileDenied an open the kernel refused.
	TypeFileChange Type = 15
	TypeFileDenied Type = 16
)

// Types lists every event type the agent knows.
var Types = []Type{
	TypeExec, TypeFork, TypeExit, TypeConnect, TypeAccept, TypeUnixConnect, TypeFileOpen,
	TypePtrace, TypeMemfd, TypeModuleLoad, TypeBPFLoad, TypeCredChange, TypeMount, TypeSetns,
	TypeFileChange, TypeFileDenied,
}

// ParseType is the inverse of Type.String.
func ParseType(s string) (Type, bool) {
	for _, t := range Types {
		if t.String() == s {
			return t, true
		}
	}
	return 0, false
}

func (t Type) String() string {
	switch t {
	case TypeExec:
		return "exec"
	case TypeFork:
		return "fork"
	case TypeExit:
		return "exit"
	case TypeConnect:
		return "connect"
	case TypeAccept:
		return "accept"
	case TypeUnixConnect:
		return "unix_connect"
	case TypeFileOpen:
		return "file_open"
	case TypePtrace:
		return "ptrace"
	case TypeMemfd:
		return "memfd"
	case TypeModuleLoad:
		return "module_load"
	case TypeBPFLoad:
		return "bpf_load"
	case TypeCredChange:
		return "cred_change"
	case TypeMount:
		return "mount"
	case TypeSetns:
		return "setns"
	case TypeFileChange:
		return "file_change"
	case TypeFileDenied:
		return "file_denied"
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
	ExecEnvTrunc   = 1 << 5
)

// File flag bits in Header.Flags, FILE_F_* in bpf/common.h.
const (
	FileByInode = 1 << 0
	FileByName  = 1 << 1
	FileByPath  = 1 << 2
	FileNoPath  = 1 << 3
	// FileKernelCreds marks an open made under credentials the kernel
	// substituted, such as overlayfs opening a backing file.
	FileKernelCreds = 1 << 4
)

// FileOps are the operations of a file_change, enum file_op in bpf/common.h,
// by value.
var FileOps = [...]string{"", "unlink", "rename_from", "rename_to", "link", "symlink", "truncate"}

// Flag bits in Header.Flags of a file_denied, DENIED_F_* in bpf/common.h.
const (
	DeniedCwdCut = 1 << 0
	DeniedNoCwd  = 1 << 1
)

// CredInExec in Header.Flags of a cred_change: the change was made by an
// exec, as a setuid binary does.
const CredInExec = 1 << 0

// MountDeeper in Header.Flags of a mount: the target has more parent
// directories than were captured.
const MountDeeper = 1 << 0

// NSNames are the namespace kinds of a setns event, by bit position.
var NSNames = [...]string{"mnt", "pid", "net", "uts", "ipc", "cgroup", "time"}

// Address families and open flags as the kernel numbers them.
const (
	AFInet  = 2
	AFInet6 = 10

	OAccMode = 0o3
	OCreat   = 0o100
	OTrunc   = 0o1000
	OAppend  = 0o2000
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
	// Env holds only the variables on the kernel's allowlist, as
	// NAME=value.
	Env []string
}

// Net is struct net_event, for connect and accept. Local is the socket's own
// side, Remote the peer.
type Net struct {
	Header
	Family uint16
	Proto  uint16
	Local  netip.AddrPort
	Remote netip.AddrPort
}

// UnixConnect is struct unix_event. An abstract address is rendered with a
// leading "@", as ss and netstat print it.
type UnixConnect struct {
	Header
	Path string
}

// FileOpen is struct file_event.
type FileOpen struct {
	Header
	Inode     uint64
	Dev       uint32
	OpenFlags uint32
	WatchBits uint32
	Path      string
}

// FileChange is struct file_event with type file_change: something was done
// to a watched name without opening it.
type FileChange struct {
	Header
	// Inode and Dev are zero for a name that did not exist before.
	Inode uint64
	Dev   uint32
	// Op is one of FileOps.
	Op   string
	Path string
}

// FileDenied is struct denied_event: an open the kernel refused.
type FileDenied struct {
	Header
	// Errno is the positive error number: EACCES, EPERM or EROFS.
	Errno     uint32
	OpenFlags uint32
	// Name is the path as the caller passed it. Cwd is the working
	// directory when Name is relative to it, and empty otherwise.
	Name string
	Cwd  string
}

// Write reports whether the refused open asked to change or create the file.
func (f *FileDenied) Write() bool { return f.OpenFlags&(OAccMode|OTrunc|OCreat) != 0 }

// Ptrace is struct ptrace_event: attach-level access to another process.
type Ptrace struct {
	Header
	TargetPID     uint32
	TargetStartNS uint64
	Mode          uint32
}

// Memfd is struct memfd_event.
type Memfd struct {
	Header
	MemfdFlags uint32
}

// ModuleLoad is struct module_event.
type ModuleLoad struct {
	Header
	Name string
}

// BPFLoad is struct bpf_event.
type BPFLoad struct {
	Header
	Cmd      uint32
	ProgType uint32
	Name     string
}

// CredChange is struct cred_event. The header's uid and gid are the ones
// before the change.
type CredChange struct {
	Header
	OldUID, NewUID   uint32
	OldEUID, NewEUID uint32
	OldGID, NewGID   uint32
	OldCap, NewCap   uint64
}

// Mount is struct mount_event. Target is the mount point within the
// filesystem it is on; it starts with ".../" when its upper directories were
// not captured.
type Mount struct {
	Header
	MntFlags uint64
	FSType   string
	Target   string
}

// Setns is struct setns_event.
type Setns struct {
	Header
	// Changed lists the namespaces that were switched, by kind; Inum is
	// the inode number of each namespace the task is in afterwards.
	Changed []string
	Inum    map[string]uint32
}

// Write reports whether the open can change the file.
func (f *FileOpen) Write() bool { return f.OpenFlags&(OAccMode|OTrunc) != 0 }

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
	case TypeConnect, TypeAccept:
		return decodeNet(h, raw)
	case TypeUnixConnect:
		if len(raw) < unixSize {
			return nil, fmt.Errorf("unix_connect record of %d bytes, want %d", len(raw), unixSize)
		}
		n := int(le.Uint32(raw[unixPathLen:]))
		if n > unixPathMax {
			return nil, fmt.Errorf("unix_connect record claims a path of %d bytes", n)
		}
		return &UnixConnect{Header: h, Path: sunPath(raw[unixPath : unixPath+n])}, nil
	case TypeFileOpen:
		if len(raw) < filePath {
			return nil, fmt.Errorf("file_open record of %d bytes, want at least %d", len(raw), filePath)
		}
		n := int(le.Uint32(raw[filePathLen:]))
		if n > pathLen || filePath+n > len(raw) {
			return nil, fmt.Errorf("file_open record of %d bytes cannot hold path_len %d", len(raw), n)
		}
		return &FileOpen{
			Header:    h,
			Inode:     le.Uint64(raw[fileInode:]),
			Dev:       le.Uint32(raw[fileDev:]),
			OpenFlags: le.Uint32(raw[fileOpenFlags:]),
			WatchBits: le.Uint32(raw[fileWatchBits:]),
			Path:      cstr(raw[filePath : filePath+n]),
		}, nil
	case TypeFileChange:
		if len(raw) < filePath {
			return nil, short(h, raw, filePath)
		}
		n := int(le.Uint32(raw[filePathLen:]))
		if n > pathLen || filePath+n > len(raw) {
			return nil, fmt.Errorf("file_change record of %d bytes cannot hold path_len %d", len(raw), n)
		}
		op := le.Uint32(raw[fileOpenFlags:])
		if op == 0 || int(op) >= len(FileOps) {
			return nil, fmt.Errorf("file_change record with unknown operation %d", op)
		}
		return &FileChange{
			Header: h,
			Inode:  le.Uint64(raw[fileInode:]),
			Dev:    le.Uint32(raw[fileDev:]),
			Op:     FileOps[op],
			Path:   cstr(raw[filePath : filePath+n]),
		}, nil
	case TypeFileDenied:
		if len(raw) < deniedCwd {
			return nil, short(h, raw, deniedCwd)
		}
		d := &FileDenied{
			Header:    h,
			Errno:     le.Uint32(raw[deniedError:]),
			OpenFlags: le.Uint32(raw[deniedOpenFlags:]),
			Name:      cstr(raw[deniedName:deniedCwd]),
		}
		if n := int(le.Uint32(raw[deniedCwdLen:])); n > 0 {
			if n > pathLen || deniedCwd+n > len(raw) {
				return nil, fmt.Errorf("file_denied record of %d bytes cannot hold cwd_len %d", len(raw), n)
			}
			d.Cwd = cstr(raw[deniedCwd : deniedCwd+n])
		}
		return d, nil
	case TypePtrace:
		if len(raw) < ptraceSize {
			return nil, short(h, raw, ptraceSize)
		}
		return &Ptrace{Header: h, TargetPID: le.Uint32(raw[hdrSize:]), Mode: le.Uint32(raw[hdrSize+4:]), TargetStartNS: le.Uint64(raw[hdrSize+8:])}, nil
	case TypeMemfd:
		if len(raw) < memfdSize {
			return nil, short(h, raw, memfdSize)
		}
		return &Memfd{Header: h, MemfdFlags: le.Uint32(raw[hdrSize:])}, nil
	case TypeModuleLoad:
		if len(raw) < moduleSize {
			return nil, short(h, raw, moduleSize)
		}
		return &ModuleLoad{Header: h, Name: cstr(raw[hdrSize:moduleSize])}, nil
	case TypeBPFLoad:
		if len(raw) < bpfSize {
			return nil, short(h, raw, bpfSize)
		}
		return &BPFLoad{Header: h, Cmd: le.Uint32(raw[hdrSize:]), ProgType: le.Uint32(raw[hdrSize+4:]), Name: cstr(raw[hdrSize+8 : bpfSize])}, nil
	case TypeCredChange:
		if len(raw) < credSize {
			return nil, short(h, raw, credSize)
		}
		return &CredChange{
			Header: h,
			OldUID: le.Uint32(raw[hdrSize:]), NewUID: le.Uint32(raw[hdrSize+4:]),
			OldEUID: le.Uint32(raw[hdrSize+8:]), NewEUID: le.Uint32(raw[hdrSize+12:]),
			OldGID: le.Uint32(raw[hdrSize+16:]), NewGID: le.Uint32(raw[hdrSize+20:]),
			OldCap: le.Uint64(raw[hdrSize+24:]), NewCap: le.Uint64(raw[hdrSize+32:]),
		}, nil
	case TypeMount:
		return decodeMount(h, raw)
	case TypeSetns:
		if len(raw) < setnsSize {
			return nil, short(h, raw, setnsSize)
		}
		s := &Setns{Header: h, Inum: map[string]uint32{}}
		changed := le.Uint32(raw[hdrSize:])
		for i, name := range NSNames {
			s.Inum[name] = le.Uint32(raw[hdrSize+8+4*i:])
			if changed&(1<<i) != 0 {
				s.Changed = append(s.Changed, name)
			}
		}
		return s, nil
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
	// env is one fixed slot per allowlisted name, all sent or none.
	envN := int(le.Uint32(raw[execEnvLen:]))
	if envN != 0 && (envN != envLen || execEnv+envN > len(raw)) {
		return nil, fmt.Errorf("exec record of %d bytes cannot hold env_len %d", len(raw), envN)
	}
	var env []string
	for off := execEnv; off < execEnv+envN; off += envVarLen {
		if v := cstr(raw[off : off+envVarLen]); v != "" {
			env = append(env, v)
		}
	}
	return &Exec{
		Env:          env,
		Header:       h,
		Inode:        le.Uint64(raw[execInode:]),
		Dev:          le.Uint32(raw[execDev:]),
		CapEffective: le.Uint64(raw[execCapEff:]),
		Path:         cstr(raw[execPath : execPath+pathLen]),
		Argv:         splitArgv(raw[execArgv : execArgv+n]),
	}, nil
}

func short(h Header, raw []byte, want int) error {
	return fmt.Errorf("%s record of %d bytes, want %d", h.Type, len(raw), want)
}

func decodeMount(h Header, raw []byte) (Event, error) {
	if len(raw) < mountSize {
		return nil, short(h, raw, mountSize)
	}
	n := int(le.Uint32(raw[hdrSize+8:]))
	if n > mountComponents {
		return nil, fmt.Errorf("mount record claims %d path components", n)
	}
	// Components are stored leaf first.
	target := ""
	for i := 0; i < n; i++ {
		off := mountComp + i*mountComponentLen
		target = "/" + cstr(raw[off:off+mountComponentLen]) + target
	}
	switch {
	case h.Flags&MountDeeper != 0:
		target = "..." + target
	case target == "":
		target = "/"
	}
	return &Mount{
		Header:   h,
		MntFlags: le.Uint64(raw[hdrSize:]),
		FSType:   cstr(raw[hdrSize+16 : hdrSize+48]),
		Target:   target,
	}, nil
}

func decodeNet(h Header, raw []byte) (Event, error) {
	if len(raw) < netSize {
		return nil, fmt.Errorf("%s record of %d bytes, want %d", h.Type, len(raw), netSize)
	}
	n := &Net{
		Header: h,
		Family: le.Uint16(raw[netFamily:]),
		Proto:  le.Uint16(raw[netProto:]),
	}
	var local, remote netip.Addr
	switch n.Family {
	case AFInet:
		local = netip.AddrFrom4([4]byte(raw[netLAddr : netLAddr+4]))
		remote = netip.AddrFrom4([4]byte(raw[netRAddr : netRAddr+4]))
	case AFInet6:
		// An IPv4 peer on an IPv6 socket is reported as IPv4.
		local = netip.AddrFrom16([16]byte(raw[netLAddr : netLAddr+16])).Unmap()
		remote = netip.AddrFrom16([16]byte(raw[netRAddr : netRAddr+16])).Unmap()
	default:
		return nil, fmt.Errorf("%s record with address family %d", h.Type, n.Family)
	}
	n.Local = netip.AddrPortFrom(local, le.Uint16(raw[netLPort:]))
	n.Remote = netip.AddrPortFrom(remote, le.Uint16(raw[netRPort:]))
	return n, nil
}

// unixPath renders a sockaddr_un path. A filesystem path ends at its first
// NUL; an abstract one starts with a NUL and uses every byte.
func sunPath(b []byte) string {
	if len(b) > 0 && b[0] == 0 {
		return "@" + string(bytes.TrimRight(b[1:], "\x00"))
	}
	return cstr(b)
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
