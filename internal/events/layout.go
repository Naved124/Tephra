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
	hdrSize  = 80
	commLen  = 16
	pathLen  = 256
	argvLen  = 1024
	execSize = hdrSize + 24 + pathLen + argvLen
	forkSize = hdrSize + 24
	exitSize = hdrSize + 8

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
	execPath    = hdrSize + 24
	execArgv    = execPath + pathLen

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
		"path":          {execPath, pathLen},
		"argv":          {execArgv, argvLen},
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
