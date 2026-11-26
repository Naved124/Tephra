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
	"strings"
	"time"

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
	// dropped in the kernel. Empty by default: loopback included, since a
	// session relayed through a local proxy, or reached through kubectl
	// port-forward, arrives on loopback (Phase 4 run 1, E02 and E12).
	NetIgnore []string `yaml:"net_ignore"`
	// Watch adds file watches to the ones the rules ask for.
	Watch []Watch `yaml:"watch"`
	// K8sAPI lists extra host:port addresses of the Kubernetes API, next
	// to the one in KUBERNETES_SERVICE_HOST.
	K8sAPI []string `yaml:"k8s_api"`
	// RuntimeBinaries lists the node's container runtime binaries, as
	// absolute paths in the node's root filesystem. Rules recognise the
	// runtime by the identity of these files.
	RuntimeBinaries []string `yaml:"runtime_binaries"`
	// MetricsAddr is the listen address of /metrics; empty disables it.
	// Read at start-up only.
	MetricsAddr string `yaml:"metrics_addr"`
	Export      Export `yaml:"export"`
	// Enforcement lets rules with "action: block" refuse what they
	// detect.
	Enforcement Enforcement `yaml:"enforcement"`
	// Tamper configures what happens when the agent is stopped by
	// anything other than Kubernetes.
	Tamper Tamper `yaml:"tamper"`
	// Blind configures what the kernel refuses while the sensor is
	// blind. Read at start-up only.
	Blind Blind `yaml:"blind"`
	// QuietConnections lets the kernel skip the connections of a process
	// that no loaded rule can fire on (rules.Set.Quiet), except connects
	// to a destination port a rule names or to the Kubernetes API. While
	// raw events are exported it applies to loopback connections only,
	// the ones that are not exported anyway (unless LoopbackEvents).
	QuietConnections bool `yaml:"quiet_connections"`
	// RingWakeup batches the kernel's wake-ups of the agent. Read at
	// start-up only.
	RingWakeup RingWakeup `yaml:"ring_wakeup"`
	// FileSummaryWindow: while the kernel's ring buffer is at least half
	// full, the opens of one watched file by one program in one pod are
	// sent once per window and counted in between, so a flood of them
	// cannot push other records out. The counts are reported with the
	// file's path once a window; opens of which no record got through
	// are reported through the rules. Zero turns it off.
	FileSummaryWindow time.Duration `yaml:"file_summary_window"`
}

// RingWakeup batches wake-ups. With Bytes zero the kernel wakes the agent for every record
// that finds it caught up. Otherwise it wakes it once Bytes wait unread, and
// the agent also reads every Interval, the longest a record can wait.
type RingWakeup struct {
	Bytes    uint32        `yaml:"bytes"`
	Interval time.Duration `yaml:"interval"`
}

// Tamper configures the agent's defence of its own sight. Read at start-up
// only.
type Tamper struct {
	// KeepRecording pins the detection programs and the ring buffer, so
	// that an agent killed, crashed or frozen leaves the kernel recording
	// for the next one to read. A stop by the container runtime, the way
	// Kubernetes stops pods, removes the pins.
	KeepRecording bool `yaml:"keep_recording"`
	// PinDir is the directory on a BPF filesystem that holds the pins.
	PinDir string `yaml:"pin_dir"`
}

// Blind configures blind mode. While the agent is gone, stopped or wedged,
// the kernel refuses a short list of actions to processes in pods, whatever
// the enforcement settings: the actions ordinary pods do not take and an
// attacker takes next, after blinding the sensor. Pods in
// Enforcement.ProtectNamespaces are left alone. It needs BPF LSM.
type Blind struct {
	// Mode is on (the default), dry_run (report what would be refused)
	// or off.
	Mode string `yaml:"mode"`
	// StaleAfter is how old the agent's heartbeat may get before the
	// sensor counts as blind. An agent that exits, or is sent SIGKILL or a
	// stop signal, blinds it at once.
	StaleAfter time.Duration `yaml:"stale_after"`
	// Actions refused: exec_unlinked, ptrace, module_load, mount.
	Actions []string `yaml:"actions"`
	// Files whose opens are refused.
	Files []BlindFile `yaml:"files"`
}

// BlindFile is a file blind mode protects.
type BlindFile struct {
	Path string `yaml:"path"`
	// Kind is exact (a full path, also watched by identity) or name (a
	// file name, wherever it is).
	Kind string `yaml:"kind"`
	// Ops is read or write, or both.
	Ops []string `yaml:"ops"`
}

// Values of Blind.Mode.
const (
	BlindOn     = "on"
	BlindDryRun = "dry_run"
	BlindOff    = "off"
)

// Enforcement configures refusal in the kernel. It applies only to pods
// that carry the opt-in label, and never to processes outside a pod.
type Enforcement struct {
	// Enabled loads the enforcement programs. Read at start-up only.
	Enabled bool `yaml:"enabled"`
	// DryRun reports what would be refused and refuses nothing. It is on
	// by default: refusal starts only when this is set to false.
	DryRun bool `yaml:"dry_run"`
	// OnAgentExit says what happens to refusals when the agent stops:
	// "pinned" keeps them in force, held by the kernel, until a new
	// agent takes over; "detach" ends them. Read at start-up only.
	OnAgentExit string `yaml:"on_agent_exit"`
	// Label is the pod label that opts a pod in, with the value "true".
	Label string `yaml:"label"`
	// ProtectNamespaces lists namespaces whose pods are never refused
	// anything, label or not. The agent's own namespace is always one.
	ProtectNamespaces []string `yaml:"protect_namespaces"`
	// PinDir is the directory on a BPF filesystem that holds the pins.
	// Read at start-up only.
	PinDir string `yaml:"pin_dir"`
}

// Values of Enforcement.OnAgentExit.
const (
	OnExitPinned = "pinned"
	OnExitDetach = "detach"
)

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
	// LoopbackEvents exports raw events of loopback connections. When
	// false, the default, they are judged by the rules and leave the
	// agent only as alerts: they are most of a node's connections and
	// never leave it.
	LoopbackEvents bool `yaml:"loopback_events"`
}

// Default returns the configuration used when no file is given.
func Default() *Config {
	return &Config{
		RingBufferSize: 16 << 20,
		RuntimeBinaries: []string{
			"/usr/bin/runc", "/usr/sbin/runc", "/usr/local/bin/runc", "/usr/local/sbin/runc",
			"/usr/bin/crun", "/usr/local/bin/crun",
			"/usr/bin/containerd", "/usr/local/bin/containerd",
			"/usr/bin/containerd-shim-runc-v2", "/usr/local/bin/containerd-shim-runc-v2",
			"/usr/bin/dockerd", "/usr/bin/crio", "/usr/bin/conmon", "/usr/libexec/crio/conmon",
			"/usr/bin/kubelet", "/usr/local/bin/kubelet",
			"/usr/lib/systemd/systemd", "/lib/systemd/systemd",
			// systemd 255 and later start every service through this
			// helper, which they execute by file descriptor.
			"/usr/lib/systemd/systemd-executor", "/lib/systemd/systemd-executor",
		},
		MetricsAddr:       ":9090",
		FileSummaryWindow: 10 * time.Second,
		Export:            Export{RawEvents: true, Queue: 8192},
		Enforcement: Enforcement{
			DryRun:            true,
			OnAgentExit:       OnExitPinned,
			Label:             "tephra.dev/enforce",
			ProtectNamespaces: []string{"kube-system"},
			PinDir:            "/sys/fs/bpf/tephra",
		},
		Tamper: Tamper{KeepRecording: true, PinDir: "/sys/fs/bpf/tephra/detect"},
		Blind: Blind{
			Mode:       BlindOn,
			StaleAfter: 12 * time.Second,
			Actions:    []string{"exec_unlinked", "ptrace", "module_load", "mount"},
			Files: []BlindFile{
				{Path: "/etc/shadow", Kind: "exact", Ops: []string{"read", "write"}},
				{Path: "/etc/ld.so.preload", Kind: "exact", Ops: []string{"write"}},
				{Path: "authorized_keys", Kind: "name", Ops: []string{"write"}},
				{Path: "release_agent", Kind: "name", Ops: []string{"write"}},
				{Path: "/proc/sys/kernel/core_pattern", Kind: "exact", Ops: []string{"write"}},
			},
		},
	}
}

// BlindActions are the actions blind mode can refuse, by name.
var BlindActions = map[string]bool{"exec_unlinked": true, "ptrace": true, "module_load": true, "mount": true}

// BlindWatches returns the file watches blind mode adds. They report
// nothing; they mark the files the kernel refuses while blind.
func (c *Config) BlindWatches() ([]filter.Watch, error) {
	if c.Blind.Mode == BlindOff {
		return nil, nil
	}
	out := make([]filter.Watch, 0, len(c.Blind.Files))
	for _, f := range c.Blind.Files {
		w := filter.Watch{Path: f.Path}
		switch f.Kind {
		case "exact":
			w.Kind = filter.Exact
			if len(f.Path) < 2 || f.Path[0] != '/' {
				return nil, fmt.Errorf("blind.files: %q is not an absolute path", f.Path)
			}
			if len(f.Path) > filter.MaxPathLen {
				return nil, fmt.Errorf("blind.files: %q is longer than %d bytes", f.Path, filter.MaxPathLen)
			}
		case "name":
			w.Kind = filter.Name
			if f.Path == "" || strings.Contains(f.Path, "/") || len(f.Path) > filter.MaxNameLen {
				return nil, fmt.Errorf("blind.files: %q is not a file name of at most %d bytes", f.Path, filter.MaxNameLen)
			}
		default:
			return nil, fmt.Errorf("blind.files %q: kind %q is not exact or name", f.Path, f.Kind)
		}
		if len(f.Ops) == 0 {
			return nil, fmt.Errorf("blind.files %q: ops is empty (read, write)", f.Path)
		}
		for _, op := range f.Ops {
			switch op {
			case "read":
				w.Bits |= filter.BlindRead
			case "write":
				w.Bits |= filter.BlindWrite
			default:
				return nil, fmt.Errorf("blind.files %q: op %q is not read or write", f.Path, op)
			}
		}
		out = append(out, w)
	}
	return out, nil
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
	for _, p := range c.RuntimeBinaries {
		if len(p) < 2 || p[0] != '/' {
			return fmt.Errorf("runtime_binaries: %q is not an absolute path", p)
		}
	}
	switch e := c.Enforcement; {
	case e.OnAgentExit != OnExitPinned && e.OnAgentExit != OnExitDetach:
		return fmt.Errorf("enforcement.on_agent_exit %q is not pinned or detach", e.OnAgentExit)
	case e.Label == "":
		return fmt.Errorf("enforcement.label is empty")
	case len(e.PinDir) < 2 || e.PinDir[0] != '/':
		return fmt.Errorf("enforcement.pin_dir %q is not an absolute path", e.PinDir)
	}
	if p := c.Tamper.PinDir; len(p) < 2 || p[0] != '/' {
		return fmt.Errorf("tamper.pin_dir %q is not an absolute path", p)
	}
	if w := c.FileSummaryWindow; w != 0 && w < time.Second {
		return fmt.Errorf("file_summary_window %s is under 1s (0 turns it off)", w)
	}
	switch b := c.Blind; {
	case b.Mode != BlindOn && b.Mode != BlindDryRun && b.Mode != BlindOff:
		return fmt.Errorf("blind.mode %q is not on, dry_run or off", b.Mode)
	case b.Mode != BlindOff && b.StaleAfter < 2*time.Second:
		return fmt.Errorf("blind.stale_after %s is under 2s: the agent's heartbeat is every second", b.StaleAfter)
	case b.Mode != BlindOff && !c.Tamper.KeepRecording:
		// Without the pinned signal record the agent cannot tell a stop
		// by Kubernetes from one by an attacker, and every stop would
		// leave the node blind.
		return fmt.Errorf("blind.mode %q needs tamper.keep_recording: a planned stop is told from an attack by the record of who sent the signal", b.Mode)
	}
	for _, a := range c.Blind.Actions {
		if !BlindActions[a] {
			return fmt.Errorf("blind.actions: %q is not exec_unlinked, ptrace, module_load or mount", a)
		}
	}
	if _, err := c.BlindWatches(); err != nil {
		return err
	}
	switch w := c.RingWakeup; {
	case w.Bytes == 0 && w.Interval != 0:
		return fmt.Errorf("ring_wakeup.interval is set but ring_wakeup.bytes is 0")
	case w.Bytes != 0 && (w.Interval < time.Millisecond || w.Interval > time.Second):
		return fmt.Errorf("ring_wakeup.interval %s is not between 1ms and 1s", w.Interval)
	case w.Bytes >= c.RingBufferSize:
		return fmt.Errorf("ring_wakeup.bytes %d is not below ring_buffer_size", w.Bytes)
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
