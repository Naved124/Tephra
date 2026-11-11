// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Naved124/tephra/internal/events"
	"github.com/Naved124/tephra/internal/filter"
)

func load(t *testing.T, body string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

func TestDefaults(t *testing.T) {
	for _, body := range []string{"", "# nothing set\n"} {
		c, err := load(t, body)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(c, Default()) {
			t.Errorf("empty file %q gave %+v", body, c)
		}
	}
	c, err := Load("")
	if err != nil || !c.Export.RawEvents || c.RingBufferSize != 16<<20 || len(c.NetIgnore) != 2 {
		t.Errorf("no file: %+v, %v", c, err)
	}
}

func TestLoad(t *testing.T) {
	c, err := load(t, `
events: [connect, file_open]
ring_buffer_size: 1048576
rules_dir: /etc/tephra/rules
net_ignore: [10.96.0.10/32]
k8s_api: ["10.96.0.1:443", "[fd00::1]:443"]
watch:
  - {path: /etc/kubernetes/, kind: prefix}
  - {path: /etc/sudoers, kind: exact, ops: [write]}
  - {path: id_rsa, kind: name, ops: [read]}
export:
  raw_events: false
  collector: tephra-collector:4317
`)
	if err != nil {
		t.Fatal(err)
	}
	if c.RulesDir != "/etc/tephra/rules" || c.Export.RawEvents || c.Export.Collector != "tephra-collector:4317" {
		t.Errorf("%+v", c)
	}
	// Keys left out keep their defaults.
	if c.Export.Queue != 8192 || c.MetricsAddr != ":9090" {
		t.Errorf("defaults lost: %+v", c)
	}
	if types, _ := c.EventTypes(); !reflect.DeepEqual(types, []events.Type{events.TypeConnect, events.TypeFileOpen}) {
		t.Errorf("event types %v", types)
	}
	if ws, _ := c.Watches(); !reflect.DeepEqual(ws, []filter.Watch{
		{Kind: filter.Prefix, Path: "/etc/kubernetes/", Bits: filter.Read | filter.Write},
		{Kind: filter.Exact, Path: "/etc/sudoers", Bits: filter.Write},
		{Kind: filter.Name, Path: "id_rsa", Bits: filter.Read},
	}) {
		t.Errorf("watches %v", ws)
	}
	if ps, _ := c.NetIgnorePrefixes(); len(ps) != 1 || ps[0].String() != "10.96.0.10/32" {
		t.Errorf("net ignore %v", ps)
	}
	if as, _ := c.APIServers(); len(as) != 2 || as[1].String() != "[fd00::1]:443" {
		t.Errorf("api servers %v", as)
	}
}

func TestInvalid(t *testing.T) {
	for body, want := range map[string]string{
		"clusterr: x\n":                                "clusterr",
		"events: [execve]\n":                           `unknown event type "execve"`,
		"ring_buffer_size: 1000000\n":                  "power of two",
		"net_ignore: [10.0.0.0]\n":                     "is not a CIDR",
		"k8s_api: [10.96.0.1]\n":                       "is not an address and port",
		"watch: [{path: etc, kind: exact}]\n":          "not an absolute path",
		"watch: [{path: /etc, kind: glob}]\n":          "is not exact, prefix or name",
		"watch: [{path: /, kind: prefix}]\n":           "every file open",
		"watch: [{path: /a, kind: exact, ops: [x]}]\n": "is not read or write",
		"export: {queue: 0}\n":                         "must be positive",
		"export: [1]\n":                                "cannot unmarshal",
	} {
		_, err := load(t, body)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want an error containing %q", body, err, want)
		}
	}
	if _, err := Load("/nonexistent/config.yaml"); err == nil {
		t.Error("missing file accepted")
	}
}
