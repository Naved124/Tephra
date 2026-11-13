// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Naved124/tephra/internal/export"
)

const seqRule = `
id: S1
title: download then run
level: high
tags: [attack.execution, attack.t1105]
sequence:
  by: process_tree
  window: 60s
  steps:
    - event: exec
      detection:
        tool:
          process.Image|endswith: [/curl, /wget]
        condition: tool
    - event: exec
      exe_changed: true
      detection:
        host:
          k8s.namespace: host
        condition: not host
`

var t0 = time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)

func seqExec(at time.Duration, tree, image string, changed time.Duration) *export.Record {
	return &export.Record{
		TS:   t0.Add(at).Format(tsLayout),
		Type: "exec",
		Process: export.Process{
			Image: image, Tree: tree,
			Exec: &export.Exec{ExeCtimeNS: uint64(t0.Add(changed).UnixNano())},
		},
		K8s: export.K8s{Namespace: "shop", Pod: "web"},
	}
}

func seqSet(t *testing.T, text string) *Set {
	t.Helper()
	rs, err := Parse("seq.yaml", []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	set, err := NewSet(rs)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func TestSequence(t *testing.T) {
	old := -24 * time.Hour
	cases := []struct {
		name string
		recs []*export.Record
		want int
	}{
		{"download then the new file", []*export.Record{
			seqExec(0, "a", "/usr/bin/wget", old),
			seqExec(time.Second, "a", "/bin/chmod", old),
			seqExec(2*time.Second, "a", "/tmp/tool", 1500*time.Millisecond),
		}, 1},
		{"an old binary after a download", []*export.Record{
			seqExec(0, "a", "/usr/bin/wget", old),
			seqExec(2*time.Second, "a", "/bin/ls", old),
		}, 0},
		{"new file, no download", []*export.Record{
			seqExec(2*time.Second, "a", "/tmp/tool", time.Second),
		}, 0},
		{"another process tree", []*export.Record{
			seqExec(0, "a", "/usr/bin/wget", old),
			seqExec(2*time.Second, "b", "/tmp/tool", time.Second),
		}, 0},
		{"outside the window", []*export.Record{
			seqExec(0, "a", "/usr/bin/wget", old),
			seqExec(61*time.Second, "a", "/tmp/tool", 60*time.Second),
		}, 0},
		{"a second download restarts the window", []*export.Record{
			seqExec(0, "a", "/usr/bin/wget", old),
			seqExec(50*time.Second, "a", "/usr/bin/curl", old),
			seqExec(100*time.Second, "a", "/tmp/tool", 51*time.Second),
		}, 1},
		{"fires once, then needs a new download", []*export.Record{
			seqExec(0, "a", "/usr/bin/wget", old),
			seqExec(2*time.Second, "a", "/tmp/tool", time.Second),
			seqExec(3*time.Second, "a", "/tmp/tool", time.Second),
		}, 1},
		{"no tree to group by", []*export.Record{
			seqExec(0, "", "/usr/bin/wget", old),
			seqExec(2*time.Second, "", "/tmp/tool", time.Second),
		}, 0},
	}
	for _, tc := range cases {
		set := seqSet(t, seqRule)
		got := 0
		for _, rec := range tc.recs {
			got += len(set.Match(rec))
		}
		if got != tc.want {
			t.Errorf("%s: fired %d times, want %d", tc.name, got, tc.want)
		}
	}
}

func TestSequenceByPod(t *testing.T) {
	set := seqSet(t, strings.Replace(seqRule, "by: process_tree", "by: pod", 1))
	a := seqExec(0, "a", "/usr/bin/wget", 0)
	b := seqExec(time.Second, "b", "/tmp/tool", time.Second)
	if n := len(set.Match(a)) + len(set.Match(b)); n != 1 {
		t.Errorf("two trees of one pod: fired %d times, want 1", n)
	}
	other := seqExec(2*time.Second, "b", "/tmp/tool", time.Second)
	other.K8s.Pod = "db"
	set.Match(seqExec(0, "a", "/usr/bin/wget", 0))
	if n := len(set.Match(other)); n != 0 {
		t.Errorf("another pod: fired %d times, want 0", n)
	}
}

func TestSequenceStateIsBounded(t *testing.T) {
	set := seqSet(t, seqRule)
	set.SetSequenceCap(100)
	for i := 0; i < 1000; i++ {
		set.Match(seqExec(time.Duration(i)*time.Millisecond, fmt.Sprint("tree", i), "/usr/bin/wget", 0))
	}
	held, evicted := set.SequenceStats()
	if held != 100 || evicted != 900 {
		t.Errorf("held %d, evicted %d; want 100 and 900", held, evicted)
	}
	// The newest are the ones kept.
	if n := len(set.Match(seqExec(2*time.Second, "tree999", "/tmp/tool", time.Second))); n != 1 {
		t.Errorf("newest sequence was dropped")
	}
	if n := len(set.Match(seqExec(2*time.Second, "tree0", "/tmp/tool", time.Second))); n != 0 {
		t.Errorf("oldest sequence survived")
	}
}

func TestSequenceEventTypesAndWatches(t *testing.T) {
	set := seqSet(t, `
id: S2
title: token then api
level: high
tags: [attack.credential_access, attack.t1528]
sequence:
  by: pod
  window: 30s
  steps:
    - event: file_open
      detection:
        token:
          file.path: /var/run/secrets/kubernetes.io/serviceaccount/token
        condition: token
    - event: connect
      detection:
        api:
          network.is_k8s_api: true
        condition: api
`)
	var names []string
	for _, typ := range set.EventTypes() {
		names = append(names, typ.String())
	}
	if got := strings.Join(names, ","); got != "connect,unix_connect,file_open" {
		t.Errorf("event types %s", got)
	}
	if ws := set.Watches(); len(ws) != 1 || ws[0].Path != "/var/run/secrets/kubernetes.io/serviceaccount/token" {
		t.Errorf("watches %+v", ws)
	}
}

func TestSequenceErrors(t *testing.T) {
	head := "id: S\ntitle: t\nlevel: high\n"
	step := "    - event: exec\n      detection:\n        a:\n          process.Image: /x\n        condition: a\n"
	for name, tc := range map[string]struct{ text, want string }{
		"both forms":    {head + "event: exec\nsequence:\n  by: pod\n  window: 5s\n  steps:\n" + step + step, "either sequence, or event and detection"},
		"bad by":        {head + "sequence:\n  by: node\n  window: 5s\n  steps:\n" + step + step, "not process_tree or pod"},
		"bad window":    {head + "sequence:\n  by: pod\n  window: 2h\n  steps:\n" + step + step, "not a duration from"},
		"one step":      {head + "sequence:\n  by: pod\n  window: 5s\n  steps:\n" + step, "2 to 4 steps"},
		"first changed": {head + "sequence:\n  by: pod\n  window: 5s\n  steps:\n    - event: exec\n      exe_changed: true\n      detection:\n        a:\n          process.Image: /x\n        condition: a\n" + step, "exe_changed applies to an exec step after the first"},
		"unwatched":     {head + "sequence:\n  by: pod\n  window: 5s\n  steps:\n" + step + "    - event: file_open\n      detection:\n        a:\n          file.write: true\n        condition: a\n", "no kernel watch covers"},
		"wrong field":   {head + "sequence:\n  by: pod\n  window: 5s\n  steps:\n" + step + "    - event: connect\n      detection:\n        a:\n          file.write: true\n        condition: a\n", "does not exist on connect events"},
	} {
		_, err := Parse("bad.yaml", []byte(tc.text))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %v, want one containing %q", name, err, tc.want)
		}
	}
}
