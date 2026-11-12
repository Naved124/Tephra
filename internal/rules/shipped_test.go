// SPDX-License-Identifier: Apache-2.0

package rules_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Naved124/tephra/internal/export"
	"github.com/Naved124/tephra/internal/filter"
	"github.com/Naved124/tephra/internal/rules"
)

const shipped = "../../rules"

func readEvents(t *testing.T, path string) []*export.Record {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("every shipped rule needs recorded events: %v", err)
	}
	defer func() { _ = f.Close() }()
	var out []*export.Record
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		rec := &export.Record{}
		dec := json.NewDecoder(bytes.NewReader(sc.Bytes()))
		// A misspelt field in a recorded event would silently test
		// nothing.
		dec.DisallowUnknownFields()
		if err := dec.Decode(rec); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		out = append(out, rec)
	}
	if len(out) == 0 {
		t.Fatalf("%s holds no events", path)
	}
	return out
}

// Every shipped rule fires on each of its matching events, and on none of
// its non-matching ones.
func TestShippedRules(t *testing.T) {
	set, err := rules.Load(shipped)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Rules) != 24 {
		t.Errorf("loaded %d rules, want R001 to R024", len(set.Rules))
	}
	for _, r := range set.Rules {
		if r.Description == "" || len(r.Tags) < 2 {
			t.Errorf("%s: needs a description, a tactic tag and a technique tag", r.ID)
		}
		for _, rec := range readEvents(t, filepath.Join(shipped, "testdata", r.ID+".match.jsonl")) {
			if rec.Type != r.Event {
				t.Errorf("%s: matching event has type %s, rule is for %s", r.ID, rec.Type, r.Event)
			}
			if !r.Matches(rec) {
				t.Errorf("%s did not fire on %s %q", r.ID, rec.Type, describe(rec))
			}
		}
		// Events the attack harness captured from a live detection.
		live := filepath.Join(shipped, "testdata", r.ID+".live.jsonl")
		if _, err := os.Stat(live); err == nil {
			for _, rec := range readEvents(t, live) {
				if !r.Matches(rec) {
					t.Errorf("%s did not fire on its live event %s %q", r.ID, rec.Type, describe(rec))
				}
			}
		}
		for _, rec := range readEvents(t, filepath.Join(shipped, "testdata", r.ID+".nomatch.jsonl")) {
			if rec.Type == r.Event && r.Matches(rec) {
				t.Errorf("%s fired on %s %q", r.ID, rec.Type, describe(rec))
			}
		}
	}
}

func describe(r *export.Record) string {
	s := r.Process.Image + " [" + r.Process.CommandLine + "]"
	if r.File != nil {
		s += " file " + r.File.Path
	}
	if r.Network != nil {
		s += " net " + r.Network.DestinationIP + r.Network.UnixPath
	}
	return s
}

// What the shipped rules ask of the kernel: the file watches below and no
// others. A change here changes what every node reports.
func TestShippedWatches(t *testing.T) {
	set, err := rules.Load(shipped)
	if err != nil {
		t.Fatal(err)
	}
	got := map[filter.Watch]bool{}
	for _, w := range set.Watches() {
		got[w] = true
	}
	rw := filter.Read | filter.Write
	want := []filter.Watch{
		{Kind: filter.Exact, Path: "/etc/shadow", Bits: rw},
		{Kind: filter.Prefix, Path: "/var/run/secrets/kubernetes.io/serviceaccount/", Bits: rw},
		{Kind: filter.Prefix, Path: "/run/secrets/kubernetes.io/serviceaccount/", Bits: rw},
		{Kind: filter.Exact, Path: "/etc/ld.so.preload", Bits: filter.Write},
		{Kind: filter.Prefix, Path: "/etc/cron.d/", Bits: filter.Write},
		{Kind: filter.Prefix, Path: "/etc/cron.hourly/", Bits: filter.Write},
		{Kind: filter.Prefix, Path: "/etc/cron.daily/", Bits: filter.Write},
		{Kind: filter.Prefix, Path: "/etc/cron.weekly/", Bits: filter.Write},
		{Kind: filter.Prefix, Path: "/etc/cron.monthly/", Bits: filter.Write},
		{Kind: filter.Prefix, Path: "/etc/crontabs/", Bits: filter.Write},
		{Kind: filter.Prefix, Path: "/var/spool/cron/", Bits: filter.Write},
		{Kind: filter.Exact, Path: "/etc/crontab", Bits: filter.Write},
		{Kind: filter.Name, Path: "authorized_keys", Bits: filter.Write},
		{Kind: filter.Name, Path: "authorized_keys2", Bits: filter.Write},
		{Kind: filter.Name, Path: "release_agent", Bits: filter.Write},
		{Kind: filter.Name, Path: "core_pattern", Bits: filter.Write},
		{Kind: filter.Name, Path: ".bash_history", Bits: filter.Write},
		{Kind: filter.Name, Path: ".zsh_history", Bits: filter.Write},
		{Kind: filter.Name, Path: ".ash_history", Bits: filter.Write},
		{Kind: filter.Name, Path: ".sh_history", Bits: filter.Write},
		// R024, refused opens only.
		{Kind: filter.Exact, Path: "/etc/shadow", Bits: filter.Denied},
		{Kind: filter.Exact, Path: "/etc/gshadow", Bits: filter.Denied},
		{Kind: filter.Exact, Path: "/etc/sudoers", Bits: filter.Denied},
		{Kind: filter.Exact, Path: "/etc/ld.so.preload", Bits: filter.Denied},
		{Kind: filter.Prefix, Path: "/etc/cron.d/", Bits: filter.Denied},
		{Kind: filter.Prefix, Path: "/var/spool/cron/", Bits: filter.Denied},
		{Kind: filter.Exact, Path: "/etc/crontab", Bits: filter.Denied},
		{Kind: filter.Name, Path: "authorized_keys", Bits: filter.Denied},
		{Kind: filter.Name, Path: "authorized_keys2", Bits: filter.Denied},
		{Kind: filter.Name, Path: "release_agent", Bits: filter.Denied},
		{Kind: filter.Name, Path: "core_pattern", Bits: filter.Denied},
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing watch %s %q bits %d", w.Kind, w.Path, w.Bits)
		}
		delete(got, w)
	}
	for w := range got {
		t.Errorf("unexpected watch %s %q bits %d", w.Kind, w.Path, w.Bits)
	}

	types := map[string]bool{}
	for _, typ := range set.EventTypes() {
		types[typ.String()] = true
	}
	for _, name := range []string{"exec", "connect", "unix_connect", "file_open", "file_change", "file_denied", "ptrace", "module_load", "bpf_load", "cred_change", "mount", "setns"} {
		if !types[name] {
			t.Errorf("event type %s not enabled by the shipped rules", name)
		}
	}
	for _, name := range []string{"accept", "memfd"} {
		if types[name] {
			t.Errorf("%s enabled, but no shipped rule uses it", name)
		}
	}
}
