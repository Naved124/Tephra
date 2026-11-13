// SPDX-License-Identifier: Apache-2.0

package events

// Byte offsets of every field the decoder reads, mirroring the structs in
// bpf/common.h. TestLayoutMatchesBTF compares this table with the BTF of the
// compiled object and fails the build if either side moves.

// Field is one struct member: its byte offset and size.
type Field struct {
	Off  int
	Size int
}

// Struct is the layout of one C struct.
type Struct struct {
	Size   int
	Fields map[string]Field
}

const (
	hdrSize   = 80
	commLen   = 16
	pathLen   = 256
	argvLen   = 1024
	envVarLen = 256
	envLen    = 3 * envVarLen
	execSize  = hdrSize + 40 + pathLen + argvLen + envLen + envVarLen
	netSize   = hdrSize + 40
	unixSize  = hdrSize + 4 + unixPathMax
	fileSize  = hdrSize + 24 + pathLen

	unixPathMax = 108

	ptraceSize        = hdrSize + 16
	memfdSize         = hdrSize + 8
	moduleSize        = hdrSize + 56
	bpfSize           = hdrSize + 24
	credSize          = hdrSize + 40
	mountComponents   = 6
	mountComponentLen = 40
	mountComp         = hdrSize + 48
	mountSize         = mountComp + mountComponents*mountComponentLen
	setnsSize         = hdrSize + 8 + 4*8
	forkSize          = hdrSize + 24
	exitSize          = hdrSize + 8

	hdrTSBoot    = 0
	hdrStartTime = 8
	hdrCgroupID  = 16
	hdrType      = 24
	hdrRecSize   = 28
	hdrPID       = 32
	hdrTID       = 36
	hdrPPID      = 40
	hdrUID       = 44
	hdrGID       = 48
	hdrPidNS     = 52
	hdrMntNS     = 56
	hdrFlags     = 60
	hdrComm      = 64

	execInode   = hdrSize + 0
	execDev     = hdrSize + 8
	execArgvLen = hdrSize + 12
	execCapEff  = hdrSize + 16
	execEnvLen  = hdrSize + 24
	execCtime   = hdrSize + 32
	execPath    = hdrSize + 40
	execArgv    = execPath + pathLen
	execEnv     = execArgv + argvLen

	netFamily = hdrSize + 0
	netLPort  = hdrSize + 2
	netRPort  = hdrSize + 4
	netProto  = hdrSize + 6
	netLAddr  = hdrSize + 8
	netRAddr  = hdrSize + 24

	unixPathLen = hdrSize + 0
	unixPath    = hdrSize + 4

	fileInode     = hdrSize + 0
	fileDev       = hdrSize + 8
	fileOpenFlags = hdrSize + 12
	fileWatchBits = hdrSize + 16
	filePathLen   = hdrSize + 20
	filePath      = hdrSize + 24

	deniedError     = hdrSize + 0
	deniedOpenFlags = hdrSize + 4
	deniedNameLen   = hdrSize + 8
	deniedCwdLen    = hdrSize + 12
	deniedName      = hdrSize + 16
	deniedCwd       = deniedName + pathLen
	deniedSize      = deniedCwd + pathLen

	enforceAction  = hdrSize + 0
	enforcePathLen = hdrSize + 4
	enforceInode   = hdrSize + 8
	enforceDev     = hdrSize + 16
	enforcePath    = hdrSize + 24
	enforceSize    = enforcePath + pathLen

	forkChildPID    = hdrSize + 0
	forkParentPID   = hdrSize + 4
	forkChildStart  = hdrSize + 8
	forkParentStart = hdrSize + 16

	exitCode = hdrSize + 0
)

// Layout is keyed by C struct name.
var Layout = map[string]Struct{
	"event_hdr": {Size: hdrSize, Fields: map[string]Field{
		"ts_boot_ns":    {hdrTSBoot, 8},
		"start_time_ns": {hdrStartTime, 8},
		"cgroup_id":     {hdrCgroupID, 8},
		"type":          {hdrType, 4},
		"size":          {hdrRecSize, 4},
		"pid":           {hdrPID, 4},
		"tid":           {hdrTID, 4},
		"ppid":          {hdrPPID, 4},
		"uid":           {hdrUID, 4},
		"gid":           {hdrGID, 4},
		"pid_ns":        {hdrPidNS, 4},
		"mnt_ns":        {hdrMntNS, 4},
		"flags":         {hdrFlags, 4},
		"comm":          {hdrComm, commLen},
	}},
	"exec_event": {Size: execSize, Fields: map[string]Field{
		"h":             {0, hdrSize},
		"inode":         {execInode, 8},
		"dev":           {execDev, 4},
		"argv_len":      {execArgvLen, 4},
		"cap_effective": {execCapEff, 8},
		"env_len":       {execEnvLen, 4},
		"_pad":          {execEnvLen + 4, 4},
		"ctime_ns":      {execCtime, 8},
		"path":          {execPath, pathLen},
		"argv":          {execArgv, argvLen},
		"env":           {execEnv, envLen},
		"env_tmp":       {execEnv + envLen, envVarLen},
	}},
	"net_event": {Size: netSize, Fields: map[string]Field{
		"h":      {0, hdrSize},
		"family": {netFamily, 2},
		"lport":  {netLPort, 2},
		"rport":  {netRPort, 2},
		"proto":  {netProto, 2},
		"laddr":  {netLAddr, 16},
		"raddr":  {netRAddr, 16},
	}},
	"unix_event": {Size: unixSize, Fields: map[string]Field{
		"h":        {0, hdrSize},
		"path_len": {unixPathLen, 4},
		"path":     {unixPath, unixPathMax},
	}},
	"ptrace_event": {Size: ptraceSize, Fields: map[string]Field{
		"h": {0, hdrSize}, "target_pid": {hdrSize, 4}, "mode": {hdrSize + 4, 4}, "target_start_time_ns": {hdrSize + 8, 8},
	}},
	"memfd_event": {Size: memfdSize, Fields: map[string]Field{
		"h": {0, hdrSize}, "memfd_flags": {hdrSize, 4}, "_pad": {hdrSize + 4, 4},
	}},
	"module_event": {Size: moduleSize, Fields: map[string]Field{
		"h": {0, hdrSize}, "name": {hdrSize, 56},
	}},
	"bpf_event": {Size: bpfSize, Fields: map[string]Field{
		"h": {0, hdrSize}, "cmd": {hdrSize, 4}, "prog_type": {hdrSize + 4, 4}, "name": {hdrSize + 8, 16},
	}},
	"cred_event": {Size: credSize, Fields: map[string]Field{
		"h": {0, hdrSize}, "old_uid": {hdrSize, 4}, "new_uid": {hdrSize + 4, 4},
		"old_euid": {hdrSize + 8, 4}, "new_euid": {hdrSize + 12, 4},
		"old_gid": {hdrSize + 16, 4}, "new_gid": {hdrSize + 20, 4},
		"old_cap_effective": {hdrSize + 24, 8}, "new_cap_effective": {hdrSize + 32, 8},
	}},
	"mount_event": {Size: mountSize, Fields: map[string]Field{
		"h": {0, hdrSize}, "mnt_flags": {hdrSize, 8}, "ncomp": {hdrSize + 8, 4}, "_pad": {hdrSize + 12, 4},
		"fstype": {hdrSize + 16, 32}, "comp": {mountComp, mountComponents * mountComponentLen},
	}},
	"setns_event": {Size: setnsSize, Fields: map[string]Field{
		"h": {0, hdrSize}, "changed": {hdrSize, 4}, "_pad": {hdrSize + 4, 4}, "inum": {hdrSize + 8, 32},
	}},
	"file_event": {Size: fileSize, Fields: map[string]Field{
		"h":          {0, hdrSize},
		"inode":      {fileInode, 8},
		"dev":        {fileDev, 4},
		"open_flags": {fileOpenFlags, 4},
		"watch_bits": {fileWatchBits, 4},
		"path_len":   {filePathLen, 4},
		"path":       {filePath, pathLen},
	}},
	"enforce_event": {Size: enforceSize, Fields: map[string]Field{
		"h":        {0, hdrSize},
		"action":   {enforceAction, 4},
		"path_len": {enforcePathLen, 4},
		"inode":    {enforceInode, 8},
		"dev":      {enforceDev, 4},
		"_pad":     {enforceDev + 4, 4},
		"path":     {enforcePath, pathLen},
	}},
	"denied_event": {Size: deniedSize, Fields: map[string]Field{
		"h":          {0, hdrSize},
		"error":      {deniedError, 4},
		"open_flags": {deniedOpenFlags, 4},
		"name_len":   {deniedNameLen, 4},
		"cwd_len":    {deniedCwdLen, 4},
		"name":       {deniedName, pathLen},
		"cwd":        {deniedCwd, pathLen},
	}},
	"fork_event": {Size: forkSize, Fields: map[string]Field{
		"h":                    {0, hdrSize},
		"child_pid":            {forkChildPID, 4},
		"parent_pid":           {forkParentPID, 4},
		"child_start_time_ns":  {forkChildStart, 8},
		"parent_start_time_ns": {forkParentStart, 8},
	}},
	"exit_event": {Size: exitSize, Fields: map[string]Field{
		"h":         {0, hdrSize},
		"exit_code": {exitCode, 4},
		"_pad":      {exitCode + 4, 4},
	}},
}
