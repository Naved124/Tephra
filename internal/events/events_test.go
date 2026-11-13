// SPDX-License-Identifier: Apache-2.0

package events_test

import (
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/cilium/ebpf/btf"

	"github.com/Naved124/tephra/internal/events"
	"github.com/Naved124/tephra/internal/loader"
)

// The decoder's offsets must match the structs the kernel programs were
// compiled with. A mismatch fails here, before anything is loaded.
func TestLayoutMatchesBTF(t *testing.T) {
	spec, err := loader.Spec()
	if err != nil {
		t.Fatalf("load embedded spec: %v", err)
	}

	for name, want := range events.Layout {
		var st *btf.Struct
		if err := spec.Types.TypeByName(name, &st); err != nil {
			t.Errorf("struct %s not in BTF: %v", name, err)
			continue
		}
		if int(st.Size) != want.Size {
			t.Errorf("sizeof(struct %s): C %d, Go %d", name, st.Size, want.Size)
		}
		if len(st.Members) != len(want.Fields) {
			t.Errorf("struct %s: C has %d members, Go table has %d", name, len(st.Members), len(want.Fields))
		}
		for _, m := range st.Members {
			f, ok := want.Fields[m.Name]
			if !ok {
				t.Errorf("struct %s: member %s missing from the Go table", name, m.Name)
				continue
			}
			size, err := btf.Sizeof(m.Type)
			if err != nil {
				t.Errorf("struct %s.%s: %v", name, m.Name, err)
				continue
			}
			if off := int(m.Offset.Bytes()); off != f.Off || size != f.Size {
				t.Errorf("struct %s.%s: C offset %d size %d, Go offset %d size %d", name, m.Name, off, size, f.Off, f.Size)
			}
		}
	}
}

func header(typ events.Type, size int) []byte {
	b := make([]byte, size)
	le := binary.LittleEndian
	le.PutUint64(b[0:], 1000) // ts_boot_ns
	le.PutUint64(b[8:], 500)  // start_time_ns
	le.PutUint64(b[16:], 77)  // cgroup_id
	le.PutUint32(b[24:], uint32(typ))
	le.PutUint32(b[28:], uint32(size))
	le.PutUint32(b[32:], 4242) // pid
	le.PutUint32(b[36:], 4243) // tid
	le.PutUint32(b[40:], 1)    // ppid
	le.PutUint32(b[44:], 33)   // uid
	le.PutUint32(b[48:], 34)   // gid
	le.PutUint32(b[52:], 11)   // pid_ns
	le.PutUint32(b[56:], 12)   // mnt_ns
	copy(b[64:], "ls")
	return b
}

func TestDecodeExec(t *testing.T) {
	argv := "ls\x00-la\x00/tmp\x00"
	raw := header(events.TypeExec, 376+len(argv))
	le := binary.LittleEndian
	le.PutUint32(raw[60:], events.ExecStdinSock|events.ExecArgvTrunc)
	le.PutUint64(raw[80:], 9001)     // inode
	le.PutUint32(raw[88:], 0x800001) // dev
	le.PutUint32(raw[92:], uint32(len(argv)))
	le.PutUint64(raw[96:], 0x1ffffffff)                // cap_effective
	le.PutUint64(raw[112:], 1_800_000_000_000_000_123) // ctime_ns
	copy(raw[120:], "/usr/bin/ls")
	copy(raw[376:], argv)
	// The ring buffer rounds samples up to 8 bytes.
	raw = append(raw, 0xff, 0xff, 0xff)

	ev, err := events.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := ev.(*events.Exec)
	if !ok {
		t.Fatalf("decoded %T, want *events.Exec", ev)
	}
	want := &events.Exec{
		Header: events.Header{
			TSBootNS: 1000, StartTimeNS: 500, CgroupID: 77,
			Type: events.TypeExec, Size: uint32(376 + len(argv)),
			PID: 4242, TID: 4243, PPID: 1, UID: 33, GID: 34, PidNS: 11, MntNS: 12,
			Flags: events.ExecStdinSock | events.ExecArgvTrunc, Comm: "ls",
		},
		Inode: 9001, Dev: 0x800001, CapEffective: 0x1ffffffff, CtimeNS: 1_800_000_000_000_000_123,
		Path: "/usr/bin/ls", Argv: []string{"ls", "-la", "/tmp"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

func TestDecodeExecArgvEdges(t *testing.T) {
	for name, tc := range map[string]struct {
		argv string
		want []string
	}{
		"empty":            {"", nil},
		"truncated":        {"sh\x00-c\x00echo hel", []string{"sh", "-c", "echo hel"}},
		"empty argument":   {"printf\x00\x00x\x00", []string{"printf", "", "x"}},
		"trailing empty":   {"a\x00\x00", []string{"a", ""}},
		"single unclosed":  {"a", []string{"a"}},
		"only a separator": {"\x00", []string{""}},
	} {
		raw := header(events.TypeExec, 376+len(tc.argv))
		binary.LittleEndian.PutUint32(raw[92:], uint32(len(tc.argv)))
		copy(raw[376:], tc.argv)
		ev, err := events.Decode(raw)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got := ev.(*events.Exec).Argv; !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: argv %q, want %q", name, got, tc.want)
		}
	}
}

func TestDecodeForkExit(t *testing.T) {
	raw := header(events.TypeFork, 104)
	le := binary.LittleEndian
	le.PutUint32(raw[80:], 5000)
	le.PutUint32(raw[84:], 4242)
	le.PutUint64(raw[88:], 600)
	le.PutUint64(raw[96:], 500)
	ev, err := events.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	f := ev.(*events.Fork)
	if f.ChildPID != 5000 || f.ParentPID != 4242 || f.ChildStartNS != 600 || f.ParentStartNS != 500 {
		t.Errorf("fork decoded as %+v", f)
	}

	raw = header(events.TypeExit, 88)
	le.PutUint32(raw[80:], 3<<8)
	ev, err = events.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if x := ev.(*events.Exit); x.Code() != 3 || x.Signal() != 0 {
		t.Errorf("exit code %d signal %d, want 3 and 0", x.Code(), x.Signal())
	}
	le.PutUint32(raw[80:], 9)
	ev, _ = events.Decode(raw)
	if x := ev.(*events.Exit); x.Code() != 0 || x.Signal() != 9 {
		t.Errorf("exit code %d signal %d, want 0 and 9", x.Code(), x.Signal())
	}
}

// Malformed records must be rejected, not sliced out of range.
func TestDecodeRejects(t *testing.T) {
	short := header(events.TypeExec, 376)[:79]
	claimsMore := header(events.TypeExec, 376)
	binary.LittleEndian.PutUint32(claimsMore[28:], 4096)
	execTooShort := header(events.TypeExec, 200)
	argvOverrun := header(events.TypeExec, 376+4)
	binary.LittleEndian.PutUint32(argvOverrun[92:], 900)
	argvHuge := header(events.TypeExec, 376)
	binary.LittleEndian.PutUint32(argvHuge[92:], 0xffffffff)
	envOverrun := header(events.TypeExec, 376+1024+4)
	binary.LittleEndian.PutUint32(envOverrun[104:], 900)
	netShort := header(events.TypeConnect, 100)
	netFamily := header(events.TypeAccept, 120)
	binary.LittleEndian.PutUint16(netFamily[80:], 17)
	unixHuge := header(events.TypeUnixConnect, 192)
	binary.LittleEndian.PutUint32(unixHuge[80:], 500)
	fileOverrun := header(events.TypeFileOpen, 104+8)
	binary.LittleEndian.PutUint32(fileOverrun[100:], 200)
	forkShort := header(events.TypeFork, 90)
	unknown := header(events.Type(31), 80)

	for name, raw := range map[string][]byte{
		"shorter than header":     short,
		"size beyond sample":      claimsMore,
		"exec without fixed part": execTooShort,
		"argv_len beyond record":  argvOverrun,
		"argv_len overflow":       argvHuge,
		"short fork":              forkShort,
		"env_len beyond record":   envOverrun,
		"short connect":           netShort,
		"unknown address family":  netFamily,
		"unix path too long":      unixHuge,
		"path_len beyond record":  fileOverrun,
		"unknown type":            unknown,
		"empty":                   nil,
	} {
		if ev, err := events.Decode(raw); err == nil {
			t.Errorf("%s: decoded %+v, want an error", name, ev)
		}
	}
}

// With captured variables the whole of argv is sent, then the variables.
func TestDecodeExecEnv(t *testing.T) {
	argv := "sh\x00"
	raw := header(events.TypeExec, 376+1024+768)
	le := binary.LittleEndian
	le.PutUint32(raw[60:], events.ExecEnvTrunc)
	le.PutUint32(raw[92:], uint32(len(argv)))
	le.PutUint32(raw[104:], 768)
	copy(raw[376:], argv)
	copy(raw[376+1024:], "LD_PRELOAD=/tmp/x.so")
	copy(raw[376+1024+256:], "LD_AUDIT=/tmp/a.so")
	ev, err := events.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	x := ev.(*events.Exec)
	if want := []string{"LD_PRELOAD=/tmp/x.so", "LD_AUDIT=/tmp/a.so"}; !reflect.DeepEqual(x.Env, want) {
		t.Errorf("env %q, want %q", x.Env, want)
	}
	if !reflect.DeepEqual(x.Argv, []string{"sh"}) {
		t.Errorf("argv %q", x.Argv)
	}
}

func TestDecodeNet(t *testing.T) {
	le := binary.LittleEndian
	raw := header(events.TypeConnect, 120)
	le.PutUint16(raw[80:], events.AFInet)
	le.PutUint16(raw[82:], 40000) // lport
	le.PutUint16(raw[84:], 443)   // rport
	le.PutUint16(raw[86:], 6)     // tcp
	copy(raw[88:], []byte{10, 244, 1, 5})
	copy(raw[104:], []byte{10, 96, 0, 1})
	ev, err := events.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	n := ev.(*events.Net)
	if n.Local.String() != "10.244.1.5:40000" || n.Remote.String() != "10.96.0.1:443" || n.Proto != 6 {
		t.Errorf("connect decoded as %s -> %s proto %d", n.Local, n.Remote, n.Proto)
	}

	raw = header(events.TypeAccept, 120)
	le.PutUint16(raw[80:], events.AFInet6)
	le.PutUint16(raw[82:], 8080)
	le.PutUint16(raw[84:], 51000)
	copy(raw[88:], []byte{0xfd, 0, 0x10, 0x96, 15: 1})
	copy(raw[104:], []byte{0xfd, 0, 0x10, 0x96, 15: 2})
	ev, err = events.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	n = ev.(*events.Net)
	if n.Local.String() != "[fd00:1096::1]:8080" || n.Remote.String() != "[fd00:1096::2]:51000" {
		t.Errorf("accept decoded as %s <- %s", n.Local, n.Remote)
	}

	// An IPv4 peer on an IPv6 socket is reported as IPv4.
	copy(raw[104:], []byte{10: 0xff, 0xff, 192, 0, 2, 7})
	ev, _ = events.Decode(raw)
	if got := ev.(*events.Net).Remote.Addr().String(); got != "192.0.2.7" {
		t.Errorf("v4-mapped peer decoded as %s", got)
	}
}

func TestDecodeUnixAndFile(t *testing.T) {
	le := binary.LittleEndian
	for path, want := range map[string]string{
		"/run/containerd/containerd.sock\x00": "/run/containerd/containerd.sock",
		"\x00abstract-name":                   "@abstract-name",
	} {
		raw := header(events.TypeUnixConnect, 192)
		le.PutUint32(raw[80:], uint32(len(path)))
		copy(raw[84:], path)
		ev, err := events.Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := ev.(*events.UnixConnect).Path; got != want {
			t.Errorf("unix path %q, want %q", got, want)
		}
	}

	path := "/etc/shadow\x00"
	raw := header(events.TypeFileOpen, 104+len(path))
	le.PutUint32(raw[60:], events.FileByInode)
	le.PutUint64(raw[80:], 1234)
	le.PutUint32(raw[88:], 0x800001)
	le.PutUint32(raw[92:], 0o1|events.OTrunc)
	le.PutUint32(raw[96:], 3)
	le.PutUint32(raw[100:], uint32(len(path)))
	copy(raw[104:], path)
	ev, err := events.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	f := ev.(*events.FileOpen)
	if f.Path != "/etc/shadow" || f.Inode != 1234 || f.Dev != 0x800001 || !f.Write() || f.WatchBits != 3 || f.Flags != events.FileByInode {
		t.Errorf("file_open decoded as %+v", f)
	}
}

func TestDecodeFileChangeAndDenied(t *testing.T) {
	le := binary.LittleEndian
	path := "/etc/ld.so.preload\x00"
	raw := header(events.TypeFileChange, 104+len(path))
	le.PutUint32(raw[60:], events.FileByPath)
	le.PutUint32(raw[92:], 3) // FILE_OP_RENAME_TO
	le.PutUint32(raw[100:], uint32(len(path)))
	copy(raw[104:], path)
	ev, err := events.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if c := ev.(*events.FileChange); c.Path != "/etc/ld.so.preload" || c.Op != "rename_to" || c.Inode != 0 {
		t.Errorf("file_change decoded as %+v", c)
	}
	for _, op := range []uint32{0, 7} {
		le.PutUint32(raw[92:], op)
		if _, err := events.Decode(raw); err == nil {
			t.Errorf("file_change with operation %d accepted", op)
		}
	}

	// Without a working directory the record ends after the name.
	raw = header(events.TypeFileDenied, 96+256)
	le.PutUint32(raw[80:], 13)
	le.PutUint32(raw[84:], 0o101) // O_WRONLY|O_CREAT
	copy(raw[96:], "/etc/shadow\x00")
	ev, err = events.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if d := ev.(*events.FileDenied); d.Name != "/etc/shadow" || d.Errno != 13 || !d.Write() || d.Cwd != "" {
		t.Errorf("file_denied decoded as %+v", d)
	}

	raw = header(events.TypeFileDenied, 96+512)
	le.PutUint32(raw[80:], 30)
	le.PutUint32(raw[92:], 5)
	copy(raw[96:], "shadow\x00")
	copy(raw[96+256:], "/etc\x00")
	ev, err = events.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if d := ev.(*events.FileDenied); d.Name != "shadow" || d.Cwd != "/etc" || d.Write() {
		t.Errorf("file_denied with cwd decoded as %+v", d)
	}
	// A cwd_len the record cannot hold.
	short := raw[:96+256+2]
	if _, err := events.Decode(short); err == nil {
		t.Error("file_denied with a cwd past the end of the record accepted")
	}
}
