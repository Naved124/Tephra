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
	raw := header(events.TypeExec, 360+len(argv))
	le := binary.LittleEndian
	le.PutUint32(raw[60:], events.ExecStdinSock|events.ExecArgvTrunc)
	le.PutUint64(raw[80:], 9001)     // inode
	le.PutUint32(raw[88:], 0x800001) // dev
	le.PutUint32(raw[92:], uint32(len(argv)))
	le.PutUint64(raw[96:], 0x1ffffffff) // cap_effective
	copy(raw[104:], "/usr/bin/ls")
	copy(raw[360:], argv)
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
			Type: events.TypeExec, Size: uint32(360 + len(argv)),
			PID: 4242, TID: 4243, PPID: 1, UID: 33, GID: 34, PidNS: 11, MntNS: 12,
			Flags: events.ExecStdinSock | events.ExecArgvTrunc, Comm: "ls",
		},
		Inode: 9001, Dev: 0x800001, CapEffective: 0x1ffffffff,
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
		raw := header(events.TypeExec, 360+len(tc.argv))
		binary.LittleEndian.PutUint32(raw[92:], uint32(len(tc.argv)))
		copy(raw[360:], tc.argv)
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
	short := header(events.TypeExec, 360)[:79]
	claimsMore := header(events.TypeExec, 360)
	binary.LittleEndian.PutUint32(claimsMore[28:], 4096)
	execTooShort := header(events.TypeExec, 200)
	argvOverrun := header(events.TypeExec, 360+4)
	binary.LittleEndian.PutUint32(argvOverrun[92:], 900)
	argvHuge := header(events.TypeExec, 360)
	binary.LittleEndian.PutUint32(argvHuge[92:], 0xffffffff)
	forkShort := header(events.TypeFork, 90)
	unknown := header(events.Type(31), 80)

	for name, raw := range map[string][]byte{
		"shorter than header":     short,
		"size beyond sample":      claimsMore,
		"exec without fixed part": execTooShort,
		"argv_len beyond record":  argvOverrun,
		"argv_len overflow":       argvHuge,
		"short fork":              forkShort,
		"unknown type":            unknown,
		"empty":                   nil,
	} {
		if ev, err := events.Decode(raw); err == nil {
			t.Errorf("%s: decoded %+v, want an error", name, ev)
		}
	}
}
