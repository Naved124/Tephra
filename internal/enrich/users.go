// SPDX-License-Identifier: Apache-2.0

package enrich

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

const (
	// A passwd file is attacker-controlled when it comes from a
	// container; never read more than this.
	maxPasswdBytes = 1 << 20
	maxUserCache   = 4096
)

type userKey struct {
	mntNS uint32
	uid   uint32
}

// userCache resolves uids to names using the passwd file of the process's
// own mount namespace, reached through /proc/<pid>/root. Results, including
// misses, are cached per (mount namespace, uid).
type userCache struct {
	procRoot string

	mu    sync.Mutex
	names map[userKey]string
}

func newUserCache(procRoot string) *userCache {
	return &userCache{procRoot: procRoot, names: make(map[userKey]string)}
}

// name returns "" if the uid has no entry or the process is already gone.
func (c *userCache) name(pid, mntNS, uid uint32) string {
	k := userKey{mntNS, uid}
	c.mu.Lock()
	name, ok := c.names[k]
	c.mu.Unlock()
	if ok {
		return name
	}

	path := filepath.Join(c.procRoot, strconv.FormatUint(uint64(pid), 10), "root", "etc", "passwd")
	f, err := os.Open(path)
	if err != nil {
		// The process may have exited; do not cache that as "no name"
		// unless the file simply does not exist in that image.
		if !os.IsNotExist(err) {
			return ""
		}
	} else {
		name = lookupPasswd(io.LimitReader(f, maxPasswdBytes), uid)
		_ = f.Close()
	}

	c.mu.Lock()
	if len(c.names) >= maxUserCache {
		clear(c.names)
	}
	c.names[k] = name
	c.mu.Unlock()
	return name
}

// lookupPasswd finds the first passwd entry with the uid.
func lookupPasswd(r io.Reader, uid uint32) string {
	want := strconv.FormatUint(uint64(uid), 10)
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		// name:passwd:uid:gid:gecos:home:shell
		f := strings.SplitN(sc.Text(), ":", 4)
		if len(f) >= 3 && f[2] == want && f[0] != "" && !strings.HasPrefix(f[0], "#") {
			return f[0]
		}
	}
	return ""
}
