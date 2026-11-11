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
	execSize  = hdrSize + 32 + pathLen + argvLen + envLen + envVarLen
	netSize   = hdrSize + 40
	unixSize  = hdrSize + 4 + unixPathMax
	fileSize  = hdrSize + 24 + pathLen

	unixPathMax = 108
	forkSize    = hdrSize + 24
	exitSize    = hdrSize + 8

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
	execPath    = hdrSize + 32
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
	"file_event": {Size: fileSize, Fields: map[string]Field{
		"h":          {0, hdrSize},
		"inode":      {fileInode, 8},
		"dev":        {fileDev, 4},
		"open_flags": {fileOpenFlags, 4},
		"watch_bits": {fileWatchBits, 4},
		"path_len":   {filePathLen, 4},
		"path":       {filePath, pathLen},
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
