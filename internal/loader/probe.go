// SPDX-License-Identifier: Apache-2.0

package loader

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"golang.org/x/sys/unix"
)

// Feature is one row of the start-up feature table.
type Feature struct {
	Name      string
	Available bool
	// Required features stop the agent when missing. Optional ones only
	// disable what depends on them.
	Required bool
	Detail   string
}

const (
	btfPath    = "/sys/kernel/btf/vmlinux"
	cgroupRoot = "/sys/fs/cgroup"
	lsmPath    = "/sys/kernel/security/lsm"
)

// Probe checks what the running kernel offers. The result is the authority on
// what can attach; version numbers in the design are only a guide.
func Probe() []Feature {
	return []Feature{
		probeKernel(),
		probeBTF(),
		probeCgroupV2(),
		probeErr("prog_type_tracing", true, features.HaveProgramType(ebpf.Tracing)),
		probeErr("map_type_ringbuf", true, features.HaveMapType(ebpf.RingBuf)),
		probeErr("prog_type_lsm", false, features.HaveProgramType(ebpf.LSM)),
		probeLSMList(),
	}
}

// CheckRequired returns an error naming every required feature that is missing.
func CheckRequired(fs []Feature) error {
	var missing []string
	for _, f := range fs {
		if f.Required && !f.Available {
			missing = append(missing, fmt.Sprintf("%s (%s)", f.Name, f.Detail))
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("kernel is missing required features: %s", strings.Join(missing, "; "))
	}
	return nil
}

func probeKernel() Feature {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return Feature{Name: "kernel", Detail: err.Error()}
	}
	return Feature{Name: "kernel", Available: true, Detail: unix.ByteSliceToString(u.Release[:])}
}

func probeBTF() Feature {
	f := Feature{Name: "btf", Required: true, Detail: btfPath}
	if _, err := os.Stat(btfPath); err != nil {
		f.Detail = err.Error()
		return f
	}
	f.Available = true
	return f
}

func probeCgroupV2() Feature {
	f := Feature{Name: "cgroup_v2", Required: true, Detail: cgroupRoot}
	var st unix.Statfs_t
	if err := unix.Statfs(cgroupRoot, &st); err != nil {
		f.Detail = err.Error()
		return f
	}
	if st.Type != unix.CGROUP2_SUPER_MAGIC {
		f.Detail = cgroupRoot + " is not a cgroup v2 mount; cgroup v1 nodes are not supported"
		return f
	}
	f.Available = true
	return f
}

// probeLSMList reports whether "bpf" is in the active LSM list, which decides
// if v2 enforcement can run. It is never required.
func probeLSMList() Feature {
	f := Feature{Name: "lsm_bpf_active"}
	b, err := os.ReadFile(lsmPath)
	if err != nil {
		f.Detail = err.Error()
		return f
	}
	list := strings.TrimSpace(string(b))
	f.Detail = list
	for _, name := range strings.Split(list, ",") {
		if name == "bpf" {
			f.Available = true
		}
	}
	return f
}

func probeErr(name string, required bool, err error) Feature {
	f := Feature{Name: name, Required: required}
	switch {
	case err == nil:
		f.Available = true
	case errors.Is(err, ebpf.ErrNotSupported):
		f.Detail = "not supported by this kernel"
	default:
		// The probe itself failed (usually missing privileges), so the
		// answer is unknown rather than "no".
		f.Detail = "probe failed: " + err.Error()
	}
	return f
}
