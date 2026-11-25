// SPDX-License-Identifier: Apache-2.0

// Package identity recognises what an executable is by its content, not by
// its name or path. A rule that matches "a shell" by the name of the binary
// misses a shell copied to /tmp/kworker; one that matches by identity does
// not.
//
// The catalogue is learned from the containers themselves: the first time a
// container's root filesystem is seen, the shells, interpreters, download
// tools and busybox that its image ships under their usual names are hashed,
// and each digest is remembered with its role. An executed file is then
// hashed once (cached by device, inode and change time) and looked up. A copy
// of a shell has the shell's digest under any name, in that container or any
// other on the node.
//
// What is hashed is the first MiB of the file. Appending bytes to a shell
// does not change its identity; editing its first MiB, or bringing a shell
// built elsewhere, does. That residual is covered by rules on behaviour
// (a socket as stdin and stdout, an executable that was not in the image),
// not by identity.
package identity

import (
	"crypto/sha256"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// Role is what an executable is, as far as rules care.
type Role string

// Roles. Busybox is resolved to the role of the applet it runs.
const (
	Unknown      Role = ""
	Shell        Role = "shell"
	Interpreter  Role = "interpreter"
	DownloadTool Role = "download_tool"
	busybox      Role = "busybox"
)

// prefix is how much of a file is hashed.
const prefix = 1 << 20

// Bounds on what is remembered; past them the oldest knowledge is dropped
// by starting again, which costs only rehashing.
const (
	maxDigests = 4096
	maxFiles   = 16384
	maxRoots   = 4096
)

// candidates names the files a container image ships under their usual
// names, by role, matched in the directories below.
var (
	candidateDirs = []string{"/bin", "/usr/bin", "/usr/local/bin", "/sbin", "/usr/sbin"}
	candidateRE   = []struct {
		re   *regexp.Regexp
		role Role
	}{
		{regexp.MustCompile(`^(busybox|toybox)$`), busybox},
		{regexp.MustCompile(`^(sh|bash|dash|ash|zsh|ksh|mksh|yash|fish|tcsh|csh)$`), Shell},
		{regexp.MustCompile(`^(python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|node|nodejs|php[0-9.]*|lua[0-9.]*|luajit|tclsh[0-9.]*|wish[0-9.]*|pwsh|Rscript)$`), Interpreter},
		{regexp.MustCompile(`^(curl|wget|wget2|aria2c|tftp|ftp|lftp|scp|sftp|rsync|socat|nc|ncat|netcat)$`), DownloadTool},
	}
)

// appletRole is the role of a busybox applet, by the name it is run as.
func appletRole(name string) Role {
	switch name {
	case "sh", "ash", "hush", "bash":
		return Shell
	case "wget", "tftp", "ftpget", "nc", "netcat":
		return DownloadTool
	}
	return Unknown
}

type fileKey struct {
	dev   uint32 // kernel encoding
	inode uint64
	ctime uint64
}

// Catalog is safe for concurrent use.
type Catalog struct {
	procRoot string

	mu      sync.Mutex
	digests map[[sha256.Size]byte]Role
	files   map[fileKey]Role
	roots   map[fileKey]bool
	errs    uint64
}

// New returns an empty catalogue that reads processes under procRoot
// (normally /proc).
func New(procRoot string) *Catalog {
	return &Catalog{
		procRoot: procRoot,
		digests:  map[[sha256.Size]byte]Role{},
		files:    map[fileKey]Role{},
		roots:    map[fileKey]bool{},
	}
}

// Stats reports the sizes of the catalogue and the read errors so far.
func (c *Catalog) Stats() (digests, files int, errs uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.digests), len(c.files), c.errs
}

// ObserveRoot learns the identities of the files the root filesystem of pid
// ships under their usual names. Each root is read once. It reports whether
// the root is known now: false when pid is gone before its root could be
// opened, so that the caller asks again through another process.
func (c *Catalog) ObserveRoot(pid uint32) bool {
	rootFD, err := unix.Open(filepath.Join(c.procRoot, strconv.FormatUint(uint64(pid), 10), "root"),
		unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false // gone
	}
	defer func() { _ = unix.Close(rootFD) }()
	var st unix.Stat_t
	if unix.Fstat(rootFD, &st) != nil {
		return false
	}
	root := fileKey{dev: kdev(st.Dev), inode: st.Ino}

	c.mu.Lock()
	if c.roots[root] {
		c.mu.Unlock()
		return true
	}
	if len(c.roots) >= maxRoots {
		c.roots = map[fileKey]bool{}
	}
	c.roots[root] = true
	c.mu.Unlock()

	found := map[[sha256.Size]byte]Role{}
	for _, dir := range candidateDirs {
		names, err := readDir(rootFD, dir)
		if err != nil {
			continue
		}
		for _, name := range names {
			role := Unknown
			for _, r := range candidateRE {
				if r.re.MatchString(name) {
					role = r.role
					break
				}
			}
			if role == Unknown {
				continue
			}
			sum, ok := hashAt(rootFD, path.Join(dir, name))
			if !ok {
				continue
			}
			// A shell name that is busybox underneath (Alpine's /bin/sh)
			// stays busybox, so its applet decides.
			if prev, seen := found[sum]; seen && prev == busybox {
				continue
			}
			found[sum] = role
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.digests)+len(found) > maxDigests {
		c.digests = map[[sha256.Size]byte]Role{}
	}
	for sum, role := range found {
		if prev, seen := c.digests[sum]; seen && prev == busybox {
			continue
		}
		c.digests[sum] = role
	}
	// Files identified before this root was read may now be known.
	if len(found) > 0 {
		c.files = map[fileKey]Role{}
	}
	return true
}

// Exe describes an executed file, as the exec event reports it.
type Exe struct {
	PID   uint32
	Path  string // as seen inside the process's root
	Dev   uint32 // kernel encoding
	Inode uint64
	Ctime uint64
	Argv  []string
	// RootPID is another process with the same root filesystem, used when
	// PID has already exited; zero if none is known.
	RootPID uint32
	// LiveRoot, if set, finds a live process with the same root when
	// neither PID nor RootPID can be read. It is asked only then: a short
	// shell that exits before its exec is handled is still identified.
	LiveRoot func() uint32
}

// Identify returns the role of an executed file. A file that cannot be read
// is Unknown, which no rule treats as safe.
func (c *Catalog) Identify(x Exe) Role {
	key := fileKey{dev: x.Dev, inode: x.Inode, ctime: x.Ctime}
	c.mu.Lock()
	role, cached := c.files[key]
	c.mu.Unlock()
	if !cached {
		sum, ok := c.hashExe(x)
		if !ok {
			c.mu.Lock()
			c.errs++
			c.mu.Unlock()
			return applet(Unknown, x.Argv)
		}
		c.mu.Lock()
		role = c.digests[sum]
		if len(c.files) >= maxFiles {
			c.files = map[fileKey]Role{}
		}
		c.files[key] = role
		c.mu.Unlock()
	}
	return applet(role, x.Argv)
}

// applet resolves busybox to the role of the applet it was asked to run:
// the name it was run as, or its first argument when run as busybox.
func applet(role Role, argv []string) Role {
	if role != busybox {
		return role
	}
	return appletRole(appletName(argv))
}

// appletName is the applet a multi-call binary runs: the name it was run
// as, or its first argument when run under its own name.
func appletName(argv []string) string {
	if len(argv) == 0 {
		return ""
	}
	name := path.Base(argv[0])
	if (name == "busybox" || name == "toybox") && len(argv) > 1 {
		name = path.Base(argv[1])
	}
	return name
}

// Applet returns the applet an executed file runs when the file is a
// multi-call binary (busybox, toybox), and "" otherwise. Every applet is the
// same file, so the file alone does not say which program runs. It answers
// from what Identify learned of the file, so it is asked after it.
func (c *Catalog) Applet(x Exe) string {
	c.mu.Lock()
	role := c.files[fileKey{dev: x.Dev, inode: x.Inode, ctime: x.Ctime}]
	c.mu.Unlock()
	if role != busybox {
		return ""
	}
	return appletName(x.Argv)
}

// hashExe hashes the executed file: through /proc/<pid>/exe while the
// process lives, else by its path under the root of another process of the
// same container. Either way the file opened must be the one executed.
func (c *Catalog) hashExe(x Exe) ([sha256.Size]byte, bool) {
	exe := filepath.Join(c.procRoot, strconv.FormatUint(uint64(x.PID), 10), "exe")
	if fd, err := unix.Open(exe, unix.O_RDONLY|unix.O_CLOEXEC, 0); err == nil {
		if sum, ok := hashFD(fd, x.Dev, x.Inode); ok {
			return sum, true
		}
	}
	pids := []uint32{x.PID, x.RootPID, 0}
	for i, pid := range pids {
		if i == 2 && x.LiveRoot != nil {
			pid = x.LiveRoot()
		}
		if pid == 0 || x.Path == "" || i > 0 && pid == x.PID || i == 2 && pid == x.RootPID {
			continue
		}
		rootFD, err := unix.Open(filepath.Join(c.procRoot, strconv.FormatUint(uint64(pid), 10), "root"),
			unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			continue
		}
		fd, err := unix.Openat2(rootFD, strings.TrimPrefix(x.Path, "/"), &unix.OpenHow{
			Flags:   unix.O_RDONLY | unix.O_CLOEXEC,
			Resolve: unix.RESOLVE_IN_ROOT,
		})
		_ = unix.Close(rootFD)
		if err != nil {
			continue
		}
		if sum, ok := hashFD(fd, x.Dev, x.Inode); ok {
			return sum, true
		}
	}
	return [sha256.Size]byte{}, false
}

// hashAt hashes a file under rootFD, resolving the path, symlinks included,
// inside that root.
func hashAt(rootFD int, name string) ([sha256.Size]byte, bool) {
	fd, err := unix.Openat2(rootFD, strings.TrimPrefix(name, "/"), &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT,
	})
	if err != nil {
		return [sha256.Size]byte{}, false
	}
	return hashFD(fd, 0, 0)
}

// hashFD hashes the first MiB of a regular file and closes fd. When dev and
// inode are given, the file must be that one.
func hashFD(fd int, dev uint32, inode uint64) ([sha256.Size]byte, bool) {
	f := os.NewFile(uintptr(fd), "exe")
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return [sha256.Size]byte{}, false
	}
	if inode != 0 && (st.Ino != inode || kdev(st.Dev) != dev) {
		return [sha256.Size]byte{}, false
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, prefix)); err != nil {
		return [sha256.Size]byte{}, false
	}
	var sum [sha256.Size]byte
	copy(sum[:], h.Sum(nil))
	return sum, true
}

// readDir lists a directory under rootFD.
func readDir(rootFD int, dir string) ([]string, error) {
	fd, err := unix.Openat2(rootFD, strings.TrimPrefix(dir, "/"), &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT,
	})
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), dir)
	defer func() { _ = f.Close() }()
	return f.Readdirnames(-1)
}

// kdev converts a user-space device number to the kernel encoding the BPF
// programs report (major << 20 | minor).
func kdev(dev uint64) uint32 {
	return unix.Major(dev)<<20 | unix.Minor(dev)
}
