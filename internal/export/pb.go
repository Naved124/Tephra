// SPDX-License-Identifier: Apache-2.0

package export

import (
	tephrav1 "github.com/Naved124/tephra/api/tephra/v1"
)

// ToProto converts a record to its protobuf form. The two forms carry the
// same fields; a test round-trips every field to keep them so.
func ToProto(r *Record) *tephrav1.Record {
	p := &tephrav1.Record{
		Ts:        r.TS,
		Type:      r.Type,
		Node:      r.Node,
		Ancestors: r.Ancestors,
		Health:    r.Health,
		Process: &tephrav1.Process{
			Pid:          r.Process.PID,
			StartTimeNs:  r.Process.StartTimeNS,
			Image:        r.Process.Image,
			CommandLine:  r.Process.CommandLine,
			User:         r.Process.User,
			Uid:          r.Process.UID,
			Gid:          r.Process.GID,
			CgroupId:     r.Process.CgroupID,
			IsMainBinary: r.Process.IsMainBinary,
			Runtime:      r.Process.Runtime,
			Tree:         r.Process.Tree,
		},
		K8S: &tephrav1.K8S{Namespace: r.K8s.Namespace, Pod: r.K8s.Pod, Labels: r.K8s.Labels},
	}
	if x := r.Rule; x != nil {
		p.Rule = &tephrav1.Rule{Id: x.ID, Title: x.Title, Level: x.Level, Tags: x.Tags}
	}
	if x := r.Process.Exec; x != nil {
		p.Process.Exec = &tephrav1.Exec{
			StdinIsSocket: x.StdinIsSocket, StdoutIsSocket: x.StdoutIsSocket,
			Unlinked: x.Unlinked, Setuid: x.Setuid, ArgvTruncated: x.ArgvTruncated,
			Inode: x.Inode, Dev: x.Dev, CapEffective: x.CapEffective,
			Env: x.Env, EnvTruncated: x.EnvTruncated, ExeCtimeNs: x.ExeCtimeNS,
		}
	}
	if x := r.Parent; x != nil {
		p.Parent = &tephrav1.Parent{Pid: x.PID, Image: x.Image, CommandLine: x.CommandLine, Runtime: x.Runtime}
	}
	if x := r.Container; x != nil {
		p.Container = &tephrav1.Container{Id: x.ID, Name: x.Name, Image: x.Image}
	}
	if x := r.Exit; x != nil {
		p.Exit = &tephrav1.Exit{Code: x.Code, Signal: x.Signal}
	}
	if x := r.Network; x != nil {
		p.Network = &tephrav1.Network{
			Direction: x.Direction, Family: x.Family, Protocol: x.Protocol,
			SourceIp: x.SourceIP, SourcePort: uint32(x.SourcePort),
			DestinationIp: x.DestinationIP, DestinationPort: uint32(x.DestinationPort),
			UnixPath: x.UnixPath, IsK8SApi: x.IsK8sAPI,
		}
	}
	if x := r.File; x != nil {
		p.File = &tephrav1.File{
			Path: x.Path, Target: x.Target, Flags: x.Flags, Write: x.Write, Truncate: x.Truncate,
			Inode: x.Inode, Dev: x.Dev, MatchedBy: x.MatchedBy, Op: x.Op, Error: x.Error,
		}
	}
	if x := r.Ptrace; x != nil {
		p.Ptrace = &tephrav1.Ptrace{TargetPid: x.TargetPID, TargetImage: x.TargetImage, TargetCommandLine: x.TargetCommandLine, Mode: x.Mode}
	}
	if x := r.Memfd; x != nil {
		p.Memfd = &tephrav1.Memfd{Flags: x.Flags}
	}
	if x := r.Module; x != nil {
		p.Module = &tephrav1.Module{Name: x.Name}
	}
	if x := r.BPF; x != nil {
		p.Bpf = &tephrav1.Bpf{ProgType: x.ProgType, Name: x.Name}
	}
	if x := r.Cred; x != nil {
		p.Cred = &tephrav1.Cred{
			OldUid: x.OldUID, NewUid: x.NewUID, OldEuid: x.OldEUID, NewEuid: x.NewEUID, OldGid: x.OldGID, NewGid: x.NewGID,
			InExec: x.InExec, CapsGained: x.CapsGained, OldCapEffective: x.OldCapEffective, NewCapEffective: x.NewCapEffective,
		}
	}
	if x := r.Mount; x != nil {
		p.Mount = &tephrav1.Mount{Fstype: x.FSType, Flags: x.Flags, Target: x.Target}
	}
	if x := r.Namespaces; x != nil {
		p.Namespaces = &tephrav1.Namespaces{Changed: x.Changed, Host: x.Host}
	}
	if x := r.Enforce; x != nil {
		p.Enforce = &tephrav1.Enforce{Action: x.Action, Denied: x.Denied}
	}
	return p
}

// FromProto is the inverse of ToProto. Protobuf does not tell an empty list
// or map from an absent one; both come back as nil, which the JSON form
// omits either way.
func FromProto(p *tephrav1.Record) *Record {
	r := &Record{TS: p.GetTs(), Type: p.GetType(), Node: p.GetNode()}
	if len(p.GetAncestors()) > 0 {
		r.Ancestors = p.GetAncestors()
	}
	if len(p.GetHealth()) > 0 {
		r.Health = p.GetHealth()
	}
	if x := p.GetRule(); x != nil {
		r.Rule = &Rule{ID: x.GetId(), Title: x.GetTitle(), Level: x.GetLevel()}
		if len(x.GetTags()) > 0 {
			r.Rule.Tags = x.GetTags()
		}
	}
	if x := p.GetProcess(); x != nil {
		r.Process = Process{
			PID: x.GetPid(), StartTimeNS: x.GetStartTimeNs(), Image: x.GetImage(), CommandLine: x.GetCommandLine(),
			User: x.GetUser(), UID: x.GetUid(), GID: x.GetGid(), CgroupID: x.GetCgroupId(), IsMainBinary: x.GetIsMainBinary(), Runtime: x.GetRuntime(), Tree: x.GetTree(),
		}
		if e := x.GetExec(); e != nil {
			r.Process.Exec = &Exec{
				StdinIsSocket: e.GetStdinIsSocket(), StdoutIsSocket: e.GetStdoutIsSocket(),
				Unlinked: e.GetUnlinked(), Setuid: e.GetSetuid(), ArgvTruncated: e.GetArgvTruncated(),
				Inode: e.GetInode(), Dev: e.GetDev(), CapEffective: e.GetCapEffective(),
				EnvTruncated: e.GetEnvTruncated(), ExeCtimeNS: e.GetExeCtimeNs(),
			}
			if len(e.GetEnv()) > 0 {
				r.Process.Env = e.GetEnv()
			}
		}
	}
	if x := p.GetParent(); x != nil {
		r.Parent = &Parent{PID: x.GetPid(), Image: x.GetImage(), CommandLine: x.GetCommandLine(), Runtime: x.GetRuntime()}
	}
	if x := p.GetContainer(); x != nil {
		r.Container = &Container{ID: x.GetId(), Name: x.GetName(), Image: x.GetImage()}
	}
	if x := p.GetK8S(); x != nil {
		r.K8s = K8s{Namespace: x.GetNamespace(), Pod: x.GetPod()}
		if len(x.GetLabels()) > 0 {
			r.K8s.Labels = x.GetLabels()
		}
	}
	if x := p.GetExit(); x != nil {
		r.Exit = &Exit{Code: x.GetCode(), Signal: x.GetSignal()}
	}
	if x := p.GetNetwork(); x != nil {
		r.Network = &Network{
			Direction: x.GetDirection(), Family: x.GetFamily(), Protocol: x.GetProtocol(),
			SourceIP: x.GetSourceIp(), SourcePort: uint16(x.GetSourcePort()),
			DestinationIP: x.GetDestinationIp(), DestinationPort: uint16(x.GetDestinationPort()),
			UnixPath: x.GetUnixPath(), IsK8sAPI: x.GetIsK8SApi(),
		}
	}
	if x := p.GetFile(); x != nil {
		r.File = &File{
			Path: x.GetPath(), Target: x.GetTarget(), Flags: x.GetFlags(), Write: x.GetWrite(), Truncate: x.GetTruncate(),
			Inode: x.GetInode(), Dev: x.GetDev(), MatchedBy: x.GetMatchedBy(), Op: x.GetOp(), Error: x.GetError(),
		}
	}
	if x := p.GetPtrace(); x != nil {
		r.Ptrace = &Ptrace{TargetPID: x.GetTargetPid(), TargetImage: x.GetTargetImage(), TargetCommandLine: x.GetTargetCommandLine(), Mode: x.GetMode()}
	}
	if x := p.GetMemfd(); x != nil {
		r.Memfd = &Memfd{Flags: x.GetFlags()}
	}
	if x := p.GetModule(); x != nil {
		r.Module = &Module{Name: x.GetName()}
	}
	if x := p.GetBpf(); x != nil {
		r.BPF = &BPF{ProgType: x.GetProgType(), Name: x.GetName()}
	}
	if x := p.GetCred(); x != nil {
		r.Cred = &Cred{
			OldUID: x.GetOldUid(), NewUID: x.GetNewUid(), OldEUID: x.GetOldEuid(), NewEUID: x.GetNewEuid(), OldGID: x.GetOldGid(), NewGID: x.GetNewGid(),
			InExec: x.GetInExec(), CapsGained: x.GetCapsGained(), OldCapEffective: x.GetOldCapEffective(), NewCapEffective: x.GetNewCapEffective(),
		}
	}
	if x := p.GetMount(); x != nil {
		r.Mount = &Mount{FSType: x.GetFstype(), Flags: x.GetFlags(), Target: x.GetTarget()}
	}
	if x := p.GetNamespaces(); x != nil {
		r.Namespaces = &Namespaces{}
		if len(x.GetChanged()) > 0 {
			r.Namespaces.Changed = x.GetChanged()
		}
		if len(x.GetHost()) > 0 {
			r.Namespaces.Host = x.GetHost()
		}
	}
	if x := p.GetEnforce(); x != nil {
		r.Enforce = &Enforce{Action: x.GetAction(), Denied: x.GetDenied()}
	}
	return r
}

// MarshalLine encodes a record as the JSON line that stdout and the log
// store both carry, without the trailing newline.
func MarshalLine(r *Record) ([]byte, error) {
	var buf lineBuffer
	enc := newEncoder(&buf)
	if err := enc.Encode(r); err != nil {
		return nil, err
	}
	return buf.trimmed(), nil
}
