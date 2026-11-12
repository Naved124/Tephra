// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"

	"github.com/Naved124/tephra/internal/export"
)

// kind is the type of a field's value.
type kind int

const (
	kString kind = iota
	kStrings
	kBool
	kInt
	kIP
)

func (k kind) String() string {
	switch k {
	case kString:
		return "string"
	case kStrings:
		return "list of strings"
	case kBool:
		return "boolean"
	case kInt:
		return "integer"
	case kIP:
		return "IP address"
	}
	return "unknown"
}

// value is what a field holds in one record. ok is false when the record has
// no such field (a host process has no container, for example); nothing
// matches an absent field.
type value struct {
	s  string
	ss []string
	b  bool
	n  int64
	ok bool
}

func str(s string) value    { return value{s: s, ok: true} }
func boolean(b bool) value  { return value{b: b, ok: true} }
func integer(n int64) value { return value{n: n, ok: true} }

type getter func(*export.Record) value

type field struct {
	kind kind
	// events lists the event types that carry the field; nil means all.
	events []string
	get    getter
}

var (
	onExec = []string{"exec"}
	onNet  = []string{"connect", "accept"}
	onFile = []string{"file_open"}
	onExit = []string{"exit"}
)

// sub builds a field of one of the per-event objects: absent when the
// record has no such object.
func sub[T any](k kind, event string, pick func(*export.Record) *T, get func(*T) value) field {
	return field{kind: k, events: []string{event}, get: func(r *export.Record) value {
		if x := pick(r); x != nil {
			return get(x)
		}
		return value{}
	}}
}

func ptraceOf(r *export.Record) *export.Ptrace { return r.Ptrace }
func memfdOf(r *export.Record) *export.Memfd   { return r.Memfd }
func moduleOf(r *export.Record) *export.Module { return r.Module }
func bpfOf(r *export.Record) *export.BPF       { return r.BPF }
func credOf(r *export.Record) *export.Cred     { return r.Cred }
func mountOf(r *export.Record) *export.Mount   { return r.Mount }
func nsOf(r *export.Record) *export.Namespaces { return r.Namespaces }

func init() {
	for name, f := range map[string]field{
		"ptrace.target_pid":          sub(kInt, "ptrace", ptraceOf, func(p *export.Ptrace) value { return integer(int64(p.TargetPID)) }),
		"ptrace.target_image":        sub(kString, "ptrace", ptraceOf, func(p *export.Ptrace) value { return present(p.TargetImage) }),
		"ptrace.target_command_line": sub(kString, "ptrace", ptraceOf, func(p *export.Ptrace) value { return present(p.TargetCommandLine) }),
		"memfd.flags":                sub(kInt, "memfd", memfdOf, func(m *export.Memfd) value { return integer(int64(m.Flags)) }),
		"module.name":                sub(kString, "module_load", moduleOf, func(m *export.Module) value { return str(m.Name) }),
		"bpf.prog_type":              sub(kInt, "bpf_load", bpfOf, func(b *export.BPF) value { return integer(int64(b.ProgType)) }),
		"bpf.name":                   sub(kString, "bpf_load", bpfOf, func(b *export.BPF) value { return present(b.Name) }),
		"cred.old_uid":               sub(kInt, "cred_change", credOf, func(c *export.Cred) value { return integer(int64(c.OldUID)) }),
		"cred.new_uid":               sub(kInt, "cred_change", credOf, func(c *export.Cred) value { return integer(int64(c.NewUID)) }),
		"cred.old_euid":              sub(kInt, "cred_change", credOf, func(c *export.Cred) value { return integer(int64(c.OldEUID)) }),
		"cred.new_euid":              sub(kInt, "cred_change", credOf, func(c *export.Cred) value { return integer(int64(c.NewEUID)) }),
		"cred.old_gid":               sub(kInt, "cred_change", credOf, func(c *export.Cred) value { return integer(int64(c.OldGID)) }),
		"cred.new_gid":               sub(kInt, "cred_change", credOf, func(c *export.Cred) value { return integer(int64(c.NewGID)) }),
		"cred.in_exec":               sub(kBool, "cred_change", credOf, func(c *export.Cred) value { return boolean(c.InExec) }),
		"cred.caps_gained":           sub(kBool, "cred_change", credOf, func(c *export.Cred) value { return boolean(c.CapsGained) }),
		"mount.fstype":               sub(kString, "mount", mountOf, func(m *export.Mount) value { return str(m.FSType) }),
		"mount.target":               sub(kString, "mount", mountOf, func(m *export.Mount) value { return str(m.Target) }),
		"mount.flags":                sub(kInt, "mount", mountOf, func(m *export.Mount) value { return integer(int64(m.Flags)) }),
		"namespaces.changed":         sub(kStrings, "setns", nsOf, func(n *export.Namespaces) value { return value{ss: n.Changed, ok: true} }),
		"namespaces.host":            sub(kStrings, "setns", nsOf, func(n *export.Namespaces) value { return value{ss: n.Host, ok: true} }),
	} {
		fields[name] = f
	}
}

func execField(k kind, get func(*export.Exec) value) field {
	return field{kind: k, events: onExec, get: func(r *export.Record) value {
		if r.Process.Exec == nil {
			return value{}
		}
		return get(r.Process.Exec)
	}}
}

func netField(k kind, get func(*export.Network) value) field {
	return field{kind: k, events: onNet, get: func(r *export.Record) value {
		if r.Network == nil {
			return value{}
		}
		return get(r.Network)
	}}
}

func fileField(k kind, get func(*export.File) value) field {
	return field{kind: k, events: onFile, get: func(r *export.Record) value {
		if r.File == nil {
			return value{}
		}
		return get(r.File)
	}}
}

func parentField(k kind, get func(*export.Parent) value) field {
	return field{kind: k, get: func(r *export.Record) value {
		if r.Parent == nil {
			return value{}
		}
		return get(r.Parent)
	}}
}

func containerField(get func(*export.Container) string) field {
	return field{kind: kString, get: func(r *export.Record) value {
		if r.Container == nil {
			return value{}
		}
		return str(get(r.Container))
	}}
}

// present turns an empty string into an absent value, for optional fields.
func present(s string) value { return value{s: s, ok: s != ""} }

// fields are the dotted paths a rule may use. They are the names of the
// enriched event's JSON fields.
var fields = map[string]field{
	"node": {kind: kString, get: func(r *export.Record) value { return str(r.Node) }},

	"process.pid":            {kind: kInt, get: func(r *export.Record) value { return integer(int64(r.Process.PID)) }},
	"process.Image":          {kind: kString, get: func(r *export.Record) value { return str(r.Process.Image) }},
	"process.CommandLine":    {kind: kString, get: func(r *export.Record) value { return str(r.Process.CommandLine) }},
	"process.User":           {kind: kString, get: func(r *export.Record) value { return present(r.Process.User) }},
	"process.uid":            {kind: kInt, get: func(r *export.Record) value { return integer(int64(r.Process.UID)) }},
	"process.gid":            {kind: kInt, get: func(r *export.Record) value { return integer(int64(r.Process.GID)) }},
	"process.is_main_binary": {kind: kBool, get: func(r *export.Record) value { return boolean(r.Process.IsMainBinary) }},

	"process.stdin_is_socket":  execField(kBool, func(e *export.Exec) value { return boolean(e.StdinIsSocket) }),
	"process.stdout_is_socket": execField(kBool, func(e *export.Exec) value { return boolean(e.StdoutIsSocket) }),
	"process.unlinked":         execField(kBool, func(e *export.Exec) value { return boolean(e.Unlinked) }),
	"process.setuid":           execField(kBool, func(e *export.Exec) value { return boolean(e.Setuid) }),
	"process.argv_truncated":   execField(kBool, func(e *export.Exec) value { return boolean(e.ArgvTruncated) }),
	"process.env_truncated":    execField(kBool, func(e *export.Exec) value { return boolean(e.EnvTruncated) }),
	"process.cap_effective":    execField(kInt, func(e *export.Exec) value { return integer(int64(e.CapEffective)) }),
	"process.env_names":        execField(kStrings, func(e *export.Exec) value { return value{ss: e.EnvNames(), ok: true} }),

	"parent.pid":         parentField(kInt, func(p *export.Parent) value { return integer(int64(p.PID)) }),
	"parent.Image":       parentField(kString, func(p *export.Parent) value { return str(p.Image) }),
	"parent.CommandLine": parentField(kString, func(p *export.Parent) value { return str(p.CommandLine) }),
	"ancestors":          {kind: kStrings, get: func(r *export.Record) value { return value{ss: r.Ancestors, ok: true} }},

	"container.id":    containerField(func(c *export.Container) string { return c.ID }),
	"container.name":  containerField(func(c *export.Container) string { return c.Name }),
	"container.image": containerField(func(c *export.Container) string { return c.Image }),

	"k8s.namespace": {kind: kString, get: func(r *export.Record) value { return str(r.K8s.Namespace) }},
	"k8s.pod":       {kind: kString, get: func(r *export.Record) value { return present(r.K8s.Pod) }},

	"network.direction":       netField(kString, func(n *export.Network) value { return str(n.Direction) }),
	"network.family":          netField(kString, func(n *export.Network) value { return str(n.Family) }),
	"network.protocol":        netField(kString, func(n *export.Network) value { return present(n.Protocol) }),
	"network.SourceIp":        netField(kIP, func(n *export.Network) value { return present(n.SourceIP) }),
	"network.SourcePort":      netField(kInt, func(n *export.Network) value { return integer(int64(n.SourcePort)) }),
	"network.DestinationIp":   netField(kIP, func(n *export.Network) value { return present(n.DestinationIP) }),
	"network.DestinationPort": netField(kInt, func(n *export.Network) value { return integer(int64(n.DestinationPort)) }),
	"network.unix_path":       netField(kString, func(n *export.Network) value { return present(n.UnixPath) }),
	"network.is_k8s_api":      netField(kBool, func(n *export.Network) value { return boolean(n.IsK8sAPI) }),

	// Both names of the file: the path that was opened and, when the file
	// was recognised by identity, the watched path it is the same file as.
	// A test holds if either passes it.
	"file.path": fileField(kStrings, func(f *export.File) value {
		if f.Target != "" && f.Target != f.Path {
			return value{ss: []string{f.Path, f.Target}, ok: true}
		}
		return value{ss: []string{f.Path}, ok: true}
	}),
	"file.flags":      fileField(kInt, func(f *export.File) value { return integer(int64(f.Flags)) }),
	"file.write":      fileField(kBool, func(f *export.File) value { return boolean(f.Write) }),
	"file.truncate":   fileField(kBool, func(f *export.File) value { return boolean(f.Truncate) }),
	"file.matched_by": fileField(kString, func(f *export.File) value { return str(f.MatchedBy) }),

	"exit.code": {kind: kInt, events: onExit, get: func(r *export.Record) value {
		if r.Exit == nil {
			return value{}
		}
		return integer(int64(r.Exit.Code))
	}},
	"exit.signal": {kind: kInt, events: onExit, get: func(r *export.Record) value {
		if r.Exit == nil {
			return value{}
		}
		return integer(int64(r.Exit.Signal))
	}},
}

// Fields with a free last component.
const (
	labelPrefix = "k8s.labels."
	envPrefix   = "process.env."
)

// lookupField resolves a field name, including the two families whose last
// component is a key: k8s.labels.<label> and process.env.<variable>.
func lookupField(name string) (field, bool) {
	if f, ok := fields[name]; ok {
		return f, true
	}
	if key, ok := strings.CutPrefix(name, labelPrefix); ok && key != "" {
		return field{kind: kString, get: func(r *export.Record) value {
			v, ok := r.K8s.Labels[key]
			return value{s: v, ok: ok}
		}}, true
	}
	if key, ok := strings.CutPrefix(name, envPrefix); ok && key != "" {
		return execField(kString, func(e *export.Exec) value {
			v, ok := e.Env[key]
			return value{s: v, ok: ok}
		}), true
	}
	return field{}, false
}

func (f field) on(event string) bool {
	if f.events == nil {
		return true
	}
	for _, e := range f.events {
		if e == event {
			return true
		}
	}
	return false
}
