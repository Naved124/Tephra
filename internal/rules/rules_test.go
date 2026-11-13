// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Naved124/tephra/internal/export"
	"github.com/Naved124/tephra/internal/filter"
)

// rule builds a rule file around a detection section.
func rule(event, detection string) string {
	return "id: T1\ntitle: test\nlevel: low\ntags: [attack.execution, attack.t1059.004]\nevent: " + event + "\ndetection:\n" + detection
}

func mustParse(t *testing.T, event, detection string) *Rule {
	t.Helper()
	rs, err := Parse("t.yaml", []byte(rule(event, detection)))
	if err != nil {
		t.Fatal(err)
	}
	return rs[0]
}

func execRec(image string, mut func(*export.Record)) *export.Record {
	r := &export.Record{
		Type:      "exec",
		Process:   export.Process{PID: 10, Image: image, CommandLine: image + " -x", UID: 33, Exec: &export.Exec{}},
		Ancestors: []string{"/usr/sbin/nginx", "/usr/bin/containerd-shim-runc-v2"},
		K8s:       export.K8s{Namespace: "shop", Pod: "web", Labels: map[string]string{"app": "web"}},
	}
	if mut != nil {
		mut(r)
	}
	return r
}

func TestModifiers(t *testing.T) {
	for _, tc := range []struct {
		name      string
		detection string
		rec       *export.Record
		want      bool
	}{
		{"equals", "  s:\n    process.Image: /bin/sh\n  condition: s", execRec("/bin/sh", nil), true},
		{"equals is exact", "  s:\n    process.Image: /bin/sh\n  condition: s", execRec("/bin/sh2", nil), false},
		{"list is any-of", "  s:\n    process.Image: [/bin/a, /bin/sh]\n  condition: s", execRec("/bin/sh", nil), true},
		{"startswith", "  s:\n    process.Image|startswith: /usr/\n  condition: s", execRec("/usr/bin/id", nil), true},
		{"endswith", "  s:\n    process.Image|endswith: [/zsh, /sh]\n  condition: s", execRec("/bin/sh", nil), true},
		{"contains", "  s:\n    process.CommandLine|contains: ' -x'\n  condition: s", execRec("/bin/sh", nil), true},
		{"in", "  s:\n    process.Image|in: [/bin/sh]\n  condition: s", execRec("/bin/sh", nil), true},
		{"re", "  s:\n    process.Image|re: '^/bin/(ba)?sh$'\n  condition: s", execRec("/bin/bash", nil), true},
		{"re no match", "  s:\n    process.Image|re: '^/bin/(ba)?sh$'\n  condition: s", execRec("/bin/bash2", nil), false},
		{"gt", "  s:\n    process.uid|gt: 32\n  condition: s", execRec("/bin/sh", nil), true},
		{"lt", "  s:\n    process.uid|lt: 33\n  condition: s", execRec("/bin/sh", nil), false},
		{"int equals", "  s:\n    process.uid: [0, 33]\n  condition: s", execRec("/bin/sh", nil), true},
		{"bool", "  s:\n    process.unlinked: false\n  condition: s", execRec("/bin/sh", nil), true},
		{"fields in a block are ANDed", "  s:\n    process.Image: /bin/sh\n    process.uid: 0\n  condition: s", execRec("/bin/sh", nil), false},
		{"ancestors any element", "  s:\n    ancestors|endswith: /nginx\n  condition: s", execRec("/bin/sh", nil), true},
		{"ancestors contains", "  s:\n    ancestors|contains: shim\n  condition: s", execRec("/bin/sh", nil), true},
		{"ancestors none", "  s:\n    ancestors: /usr/sbin/apache2\n  condition: s", execRec("/bin/sh", nil), false},
		{"label", "  s:\n    k8s.labels.app: web\n  condition: s", execRec("/bin/sh", nil), true},
		{"missing label never matches", "  s:\n    k8s.labels.tier|contains: ''\n  condition: s", execRec("/bin/sh", nil), false},
		{"absent container never matches", "  s:\n    container.name|startswith: ''\n  condition: s", execRec("/bin/sh", nil), false},
		{"env name", "  s:\n    process.env_names: LD_PRELOAD\n  condition: s",
			execRec("/bin/sh", func(r *export.Record) { r.Process.Env = map[string]string{"LD_PRELOAD": "/x.so"} }), true},
		{"env value", "  s:\n    process.env.LD_PRELOAD|startswith: /tmp/\n  condition: s",
			execRec("/bin/sh", func(r *export.Record) { r.Process.Env = map[string]string{"LD_PRELOAD": "/tmp/x.so"} }), true},
		{"and not", "  a:\n    process.Image: /bin/sh\n  b:\n    k8s.namespace: kube-system\n  condition: a and not b", execRec("/bin/sh", nil), true},
		{"or", "  a:\n    process.Image: /bin/zsh\n  b:\n    k8s.namespace: shop\n  condition: a or b", execRec("/bin/sh", nil), true},
		{"and binds tighter than or", "  a:\n    process.Image: /bin/sh\n  b:\n    process.uid: 0\n  c:\n    process.uid: 1\n  condition: a or b and c", execRec("/bin/sh", nil), true},
		{"parentheses", "  a:\n    process.Image: /bin/sh\n  b:\n    process.uid: 0\n  c:\n    process.uid: 1\n  condition: (a or b) and c", execRec("/bin/sh", nil), false},
		{"not not", "  a:\n    process.Image: /bin/sh\n  condition: not not a", execRec("/bin/sh", nil), true},
	} {
		r := mustParse(t, "exec", tc.detection)
		if got := r.Matches(tc.rec); got != tc.want {
			t.Errorf("%s: matched %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestNetworkAndFileFields(t *testing.T) {
	conn := &export.Record{Type: "connect", Network: &export.Network{
		Direction: "outbound", Family: "ipv6", Protocol: "tcp", DestinationIP: "fd00:10:96::1", DestinationPort: 443,
	}}
	for detection, want := range map[string]bool{
		"  s:\n    network.DestinationIp|cidr: fd00:10:96::/112\n  condition: s":             true,
		"  s:\n    network.DestinationIp|cidr: [10.0.0.0/8, 192.168.0.0/16]\n  condition: s": false,
		"  s:\n    network.DestinationIp: fd00:10:96:0::1\n  condition: s":                   true,
		"  s:\n    network.DestinationPort|in: [80, 443]\n  condition: s":                    true,
		"  s:\n    network.SourceIp|cidr: ::/0\n  condition: s":                              false, // unbound: absent
	} {
		if got := mustParse(t, "connect", detection).Matches(conn); got != want {
			t.Errorf("%q: matched %v, want %v", detection, got, want)
		}
	}

	// A file recognised by identity answers to both of its names.
	link := &export.Record{Type: "file_open", File: &export.File{Path: "/tmp/innocent", Target: "/etc/shadow", MatchedBy: "inode"}}
	for detection, want := range map[string]bool{
		"  s:\n    file.path: /etc/shadow\n  condition: s":                       true,
		"  s:\n    file.path|startswith: /tmp/\n  condition: s":                  true,
		"  s:\n    file.path|startswith: /var/spool/\n  condition: s":            false,
		"  s:\n    file.path: /etc/shadow\n    file.write: true\n  condition: s": false,
	} {
		if got := mustParse(t, "file_open", detection).Matches(link); got != want {
			t.Errorf("%q: matched %v, want %v", detection, got, want)
		}
	}
}

// An invalid rule is refused with the file and line of the problem.
func TestInvalidRules(t *testing.T) {
	head := "id: T1\ntitle: test\nlevel: low\ntags: [attack.execution]\nevent: exec\n"
	for _, tc := range []struct {
		name string
		yaml string
		line int
		msg  string
	}{
		{"unknown field", rule("exec", "  s:\n    process.Imagee: /bin/sh\n  condition: s"), 8, `unknown field "process.Imagee"`},
		{"unknown modifier", rule("exec", "  s:\n    process.Image|like: /bin/sh\n  condition: s"), 8, `unknown modifier "like"`},
		{"modifier on wrong type", rule("exec", "  s:\n    process.uid|startswith: 1\n  condition: s"), 8, "does not apply"},
		{"string for an integer", rule("exec", "  s:\n    process.uid: root\n  condition: s"), 8, "is not a integer"},
		{"integer for a string", rule("exec", "  s:\n    process.Image: 7\n  condition: s"), 8, "is not a string"},
		{"string for a boolean", rule("exec", "  s:\n    process.unlinked: 'yes'\n  condition: s"), 8, "is not a boolean"},
		{"bad regexp", rule("exec", "  s:\n    process.Image|re: '('\n  condition: s"), 8, "missing closing"},
		{"bad cidr", rule("connect", "  s:\n    network.DestinationIp|cidr: 10.0.0.0/40\n  condition: s"), 8, "is not a CIDR"},
		{"cidr on a string", rule("exec", "  s:\n    process.Image|cidr: 10.0.0.0/8\n  condition: s"), 8, "does not apply"},
		{"in without a list", rule("exec", "  s:\n    process.Image|in: /bin/sh\n  condition: s"), 8, "takes a list"},
		{"field of another event", rule("exec", "  s:\n    file.path: /etc/shadow\n  condition: s"), 8, "does not exist on exec events"},
		{"empty block", rule("exec", "  s: {}\n  condition: s"), 7, "non-empty mapping"},
		{"no condition", rule("exec", "  s:\n    process.uid: 0\n"), 7, "no condition"},
		{"undefined block", rule("exec", "  s:\n    process.uid: 0\n  condition: s and filter"), 9, `block "filter", which is not defined`},
		{"unused block", rule("exec", "  s:\n    process.uid: 0\n  f:\n    process.uid: 1\n  condition: s"), 9, `block "f" is not used`},
		{"condition syntax", rule("exec", "  s:\n    process.uid: 0\n  condition: s and"), 9, "ends where a block name is expected"},
		{"unbalanced", rule("exec", "  s:\n    process.uid: 0\n  condition: (s"), 9, "missing )"},
		{"bad level", strings.Replace(rule("exec", "  s:\n    process.uid: 0\n  condition: s"), "level: low", "level: severe", 1), 1, `level "severe"`},
		{"bad event", rule("execve", "  s:\n    process.uid: 0\n  condition: s"), 1, `event "execve"`},
		{"bad tag", strings.Replace(rule("exec", "  s:\n    process.uid: 0\n  condition: s"), "attack.t1059.004", "attack.T1059", 1), 1, `tag "attack.T1059"`},
		{"no id", "title: x\nlevel: low\nevent: exec\ndetection:\n  s:\n    process.uid: 0\n  condition: s\n", 1, "id is missing"},
		{"unknown key", head + "severity: low\n", 6, `unknown key "severity"`},
		{"duplicate key", head + "level: high\n", 6, `duplicate key "level"`},
		{"block action", head + "action: block\ndetection:\n  s:\n    process.uid: 0\n  condition: s\n", 8, "cannot judge process.uid"},
		{"unknown action", head + "action: kill\ndetection:\n  s:\n    process.uid: 0\n  condition: s\n", 6, "not alert or block"},
		{"sequence cannot block", "id: T1\ntitle: x\nlevel: low\naction: block\nsequence:\n  by: pod\n  window: 10s\n  steps:\n    - event: exec\n      detection:\n        s:\n          process.uid: 0\n        condition: s\n    - event: exec\n      detection:\n        s:\n          process.uid: 0\n        condition: s\n", 4, "block"},
		{"not yaml", "id: T1\n  title: [\n", 2, "invalid YAML"},
		{"second document", rule("exec", "  s:\n    process.uid: 0\n  condition: s") + "\n---\nid: T2\ntitle: x\nlevel: low\nevent: exec\ndetection:\n  s:\n    nope: 1\n  condition: s\n", 17, `unknown field "nope"`},
		// file_open rules the kernel could not filter for.
		{"file rule without a path", rule("file_open", "  s:\n    file.write: true\n  condition: s"), 7, "no kernel watch covers"},
		{"file path contains", rule("file_open", "  s:\n    file.path|contains: shadow\n  condition: s"), 7, "no kernel watch covers"},
		{"file path under not", rule("file_open", "  s:\n    file.path: /etc/shadow\n  condition: not s"), 7, "no kernel watch covers"},
		{"one alternative uncovered", rule("file_open", "  a:\n    file.path: /etc/shadow\n  b:\n    process.uid: 0\n  condition: a or b"), 7, "no kernel watch covers"},
		{"suffix inside a name", rule("file_open", "  s:\n    file.path|endswith: _history\n  condition: s"), 7, "no kernel watch covers"},
		{"relative path", rule("file_open", "  s:\n    file.path: etc/shadow\n  condition: s"), 7, "not an absolute path"},
		{"whole filesystem", rule("file_open", "  s:\n    file.path|startswith: /\n  condition: s"), 7, "every file open"},
	} {
		_, err := Parse("bad.yaml", []byte(tc.yaml))
		var re *Error
		if !errors.As(err, &re) {
			t.Errorf("%s: got %v, want a rules.Error", tc.name, err)
			continue
		}
		if re.File != "bad.yaml" || re.Line != tc.line || !strings.Contains(re.Msg, tc.msg) {
			t.Errorf("%s: got %q, want line %d and %q", tc.name, re.Error(), tc.line, tc.msg)
		}
	}
}

func TestFileWatchCompilation(t *testing.T) {
	rw := filter.Read | filter.Write
	for _, tc := range []struct {
		name      string
		detection string
		want      []filter.Watch
	}{
		{"exact", "  s:\n    file.path: [/etc/shadow, /etc/gshadow]\n  condition: s",
			[]filter.Watch{{Kind: filter.Exact, Path: "/etc/shadow", Bits: rw}, {Kind: filter.Exact, Path: "/etc/gshadow", Bits: rw}}},
		{"prefix, writes only", "  s:\n    file.path|startswith: /etc/cron.d/\n    file.write: true\n  condition: s",
			[]filter.Watch{{Kind: filter.Prefix, Path: "/etc/cron.d/", Bits: filter.Write}}},
		{"name", "  s:\n    file.path|endswith: /authorized_keys\n  condition: s",
			[]filter.Watch{{Kind: filter.Name, Path: "authorized_keys", Bits: rw}}},
		{"filter does not narrow", "  s:\n    file.path: /etc/shadow\n  f:\n    file.write: true\n  condition: s and not f",
			[]filter.Watch{{Kind: filter.Exact, Path: "/etc/shadow", Bits: rw}}},
		{"write in a sibling block", "  s:\n    file.path: /etc/crontab\n  w:\n    file.truncate: true\n  condition: s and w",
			[]filter.Watch{{Kind: filter.Exact, Path: "/etc/crontab", Bits: filter.Write}}},
		{"write in one alternative only", "  a:\n    file.path: /etc/a\n    file.write: true\n  b:\n    file.path: /etc/b\n  condition: a or b",
			[]filter.Watch{{Kind: filter.Exact, Path: "/etc/a", Bits: rw}, {Kind: filter.Exact, Path: "/etc/b", Bits: rw}}},
		{"a later path test covers", "  s:\n    file.path|contains: sha\n    file.path|startswith: /etc/\n  condition: s",
			[]filter.Watch{{Kind: filter.Prefix, Path: "/etc/", Bits: rw}}},
	} {
		got := mustParse(t, "file_open", tc.detection).watches
		if len(got) != len(tc.want) {
			t.Errorf("%s: watches %v, want %v", tc.name, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s: watch %d is %v, want %v", tc.name, i, got[i], tc.want[i])
			}
		}
	}
}

func TestLoadDirectory(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ok := rule("exec", "  s:\n    process.uid: 0\n  condition: s")
	write("a.yaml", ok)
	write("b.yml", strings.Replace(ok, "id: T1", "id: T2", 1))
	write("notes.txt", "not a rule")
	write("..data", "kubelet bookkeeping")
	if err := os.Mkdir(filepath.Join(dir, "testdata"), 0o700); err != nil {
		t.Fatal(err)
	}

	set, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Rules) != 2 {
		t.Fatalf("loaded %d rules, want 2", len(set.Rules))
	}
	rec := execRec("/bin/sh", func(r *export.Record) { r.Process.UID = 0 })
	matched := set.Match(rec)
	if len(matched) != 2 {
		t.Fatalf("matched %d rules, want 2", len(matched))
	}
	alert := matched[0].Alert(rec)
	if !alert.IsAlert() || alert.Rule.ID != "T1" || alert.Rule.Level != "low" || rec.Rule != nil || alert.Process.Image != "/bin/sh" {
		t.Errorf("alert %+v, event rule %+v", alert.Rule, rec.Rule)
	}
	// Rules for other event types are not consulted.
	if got := set.Match(&export.Record{Type: "exit"}); got != nil {
		t.Errorf("exit event matched %v", got)
	}

	write("c.yaml", ok)
	_, err = Load(dir)
	var re *Error
	if !errors.As(err, &re) || !strings.Contains(re.Msg, "already used") || !strings.HasSuffix(re.File, "c.yaml") {
		t.Errorf("duplicate id: got %v", err)
	}
}
