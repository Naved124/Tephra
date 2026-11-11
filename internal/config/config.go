// SPDX-License-Identifier: Apache-2.0

// Package config reads the agent's configuration file.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"

	"go.yaml.in/yaml/v3"

	"github.com/Naved124/tephra/internal/events"
	"github.com/Naved124/tephra/internal/filter"
)

// Config is the agent configuration. The zero value is not usable; start
// from Default.
type Config struct {
	// Events lists the event types to capture. Empty means every type
	// when raw events are exported, and only what the rules need when
	// they are not. Exec, fork and exit are always captured.
	Events []string `yaml:"events"`
	// RingBufferSize is in bytes, a power of two. Read at start-up only.
	RingBufferSize uint32 `yaml:"ring_buffer_size"`
	// RulesDir holds the detection rules. Empty means no rules.
	RulesDir string `yaml:"rules_dir"`
	// NetIgnore lists destinations, as CIDRs, whose connections are
	// dropped in the kernel.
	NetIgnore []string `yaml:"net_ignore"`
	// Watch adds file watches to the ones the rules ask for.
	Watch []Watch `yaml:"watch"`
	// K8sAPI lists extra host:port addresses of the Kubernetes API, next
	// to the one in KUBERNETES_SERVICE_HOST.
	K8sAPI []string `yaml:"k8s_api"`
	// MetricsAddr is the listen address of /metrics; empty disables it.
	// Read at start-up only.
	MetricsAddr string `yaml:"metrics_addr"`
	Export      Export `yaml:"export"`
}

// Watch is one extra file watch.
type Watch struct {
	Path string `yaml:"path"`
	// Kind is exact, prefix or name.
	Kind string `yaml:"kind"`
	// Ops is read, write or both; empty means both.
	Ops []string `yaml:"ops"`
}

// Export says where records go besides stdout.
type Export struct {
	// RawEvents exports every event. When false only alerts leave the
	// agent.
	RawEvents bool `yaml:"raw_events"`
	// Collector is the host:port of the collector's gRPC service; empty
	// disables it. Read at start-up only.
	Collector string `yaml:"collector"`
	// Queue is the number of records buffered for the collector.
	Queue int `yaml:"queue"`
}

// Default returns the configuration used when no file is given.
func Default() *Config {
	return &Config{
		RingBufferSize: 16 << 20,
		// Loopback traffic never leaves the node and is most of the
		// connect volume on one.
		NetIgnore:   []string{"127.0.0.0/8", "::1/128"},
		MetricsAddr: ":9090",
		Export:      Export{RawEvents: true, Queue: 8192},
	}
}

// Load reads a configuration file over the defaults. An empty path gives
// the defaults. Unknown keys are errors.
func Load(path string) (*Config, error) {
	c := Default()
	if path == "" {
		return c, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	// A file with nothing in it, or only comments, is the defaults.
	if err := dec.Decode(c); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return c, nil
}

// Validate checks every value that is parsed later.
func (c *Config) Validate() error {
	if s := c.RingBufferSize; s == 0 || s&(s-1) != 0 || s%uint32(os.Getpagesize()) != 0 {
		return fmt.Errorf("ring_buffer_size %d is not a power of two multiple of the page size", s)
	}
	if c.Export.Queue <= 0 {
		return fmt.Errorf("export.queue must be positive")
	}
	if _, err := c.EventTypes(); err != nil {
		return err
	}
	if _, err := c.NetIgnorePrefixes(); err != nil {
		return err
	}
	if _, err := c.Watches(); err != nil {
		return err
	}
	_, err := c.APIServers()
	return err
}

// EventTypes returns the configured event types, or nil if none are named.
func (c *Config) EventTypes() ([]events.Type, error) {
	if len(c.Events) == 0 {
		return nil, nil
	}
	out := make([]events.Type, 0, len(c.Events))
	for _, name := range c.Events {
		t, ok := events.ParseType(name)
		if !ok {
			return nil, fmt.Errorf("events: unknown event type %q", name)
		}
		out = append(out, t)
	}
	return out, nil
}

// NetIgnorePrefixes parses NetIgnore.
func (c *Config) NetIgnorePrefixes() ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(c.NetIgnore))
	for _, s := range c.NetIgnore {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("net_ignore: %q is not a CIDR", s)
		}
		out = append(out, p)
	}
	return out, nil
}

// Watches converts Watch to kernel filter entries.
func (c *Config) Watches() ([]filter.Watch, error) {
	out := make([]filter.Watch, 0, len(c.Watch))
	for _, w := range c.Watch {
		fw := filter.Watch{Path: w.Path}
		switch w.Kind {
		case "exact":
			fw.Kind = filter.Exact
		case "prefix":
			fw.Kind = filter.Prefix
		case "name":
			fw.Kind = filter.Name
		default:
			return nil, fmt.Errorf("watch %q: kind %q is not exact, prefix or name", w.Path, w.Kind)
		}
		switch {
		case w.Path == "":
			return nil, fmt.Errorf("watch: path is empty")
		case fw.Kind == filter.Name && len(w.Path) > filter.MaxNameLen:
			return nil, fmt.Errorf("watch %q: a file name is at most %d bytes", w.Path, filter.MaxNameLen)
		case fw.Kind != filter.Name && w.Path[0] != '/':
			return nil, fmt.Errorf("watch %q: not an absolute path", w.Path)
		case fw.Kind == filter.Prefix && w.Path == "/":
			return nil, fmt.Errorf("watch \"/\" would report every file open on the node")
		}
		if len(w.Ops) == 0 {
			fw.Bits = filter.Read | filter.Write
		}
		for _, op := range w.Ops {
			switch op {
			case "read":
				fw.Bits |= filter.Read
			case "write":
				fw.Bits |= filter.Write
			default:
				return nil, fmt.Errorf("watch %q: op %q is not read or write", w.Path, op)
			}
		}
		out = append(out, fw)
	}
	return out, nil
}

// APIServers parses K8sAPI.
func (c *Config) APIServers() ([]netip.AddrPort, error) {
	out := make([]netip.AddrPort, 0, len(c.K8sAPI))
	for _, s := range c.K8sAPI {
		ap, err := netip.ParseAddrPort(s)
		if err != nil {
			return nil, fmt.Errorf("k8s_api: %q is not an address and port", s)
		}
		out = append(out, ap)
	}
	return out, nil
}
