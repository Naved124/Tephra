// SPDX-License-Identifier: Apache-2.0

package loader

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"

	"github.com/Naved124/tephra/internal/filter"
)

// SetFilters makes the path, name and network filter maps hold exactly the
// given set. Entries that stay are not touched, so a reload leaves no window
// in which a watch is missing. The inode watches are separate: they depend
// on what each container's filesystem holds (PutInode).
func (s *Sensor) SetFilters(f filter.Set) error {
	paths := map[tephraPathKey]uint32{}
	names := map[tephraNameKey]uint32{}
	for _, w := range f.Watches {
		if w.Bits&(filter.Read|filter.Write|filter.Denied|filter.Block) == 0 {
			return fmt.Errorf("watch %q reports nothing", w.Path)
		}
		switch w.Kind {
		case filter.Exact, filter.Prefix:
			if w.Path == "" || w.Path[0] != '/' {
				return fmt.Errorf("watch %q is not an absolute path", w.Path)
			}
			paths[pathKey(w)] |= w.Bits
		case filter.Name:
			if w.Path == "" || len(w.Path) > filter.MaxNameLen {
				return fmt.Errorf("file name watch %q must be 1 to %d bytes", w.Path, filter.MaxNameLen)
			}
			var k tephraNameKey
			copyChars(k.Name[:], w.Path)
			names[k] |= w.Bits
		}
	}
	v4 := map[tephraIp4Key]uint8{}
	v6 := map[tephraIp6Key]uint8{}
	for _, p := range f.NetIgnore {
		p = p.Masked()
		if a := p.Addr(); a.Is4() {
			v4[tephraIp4Key{Prefixlen: uint32(p.Bits()), Addr: a.As4()}] = 1
		} else {
			v6[tephraIp6Key{Prefixlen: uint32(p.Bits()), Addr: a.As16()}] = 1
		}
	}

	if err := replace(s.coll.Maps["path_watch"], paths); err != nil {
		return fmt.Errorf("write path_watch map: %w", err)
	}
	if err := replace(s.coll.Maps["name_watch"], names); err != nil {
		return fmt.Errorf("write name_watch map: %w", err)
	}
	if err := replace(s.coll.Maps["net_ignore_v4"], v4); err != nil {
		return fmt.Errorf("write net_ignore_v4 map: %w", err)
	}
	if err := replace(s.coll.Maps["net_ignore_v6"], v6); err != nil {
		return fmt.Errorf("write net_ignore_v6 map: %w", err)
	}
	return nil
}

// pathKey builds the LPM key of a path watch. An exact path includes its
// terminating NUL, so "/etc/shadow" does not also match "/etc/shadow-". The
// kernel looks up at most MaxPathLen bytes; a longer watch is cut there and
// the agent's matcher checks the rest.
func pathKey(w filter.Watch) tephraPathKey {
	var k tephraPathKey
	n := copyChars(k.Path[:], w.Path)
	if w.Kind == filter.Exact && n < len(k.Path) {
		n++
	}
	k.Prefixlen = uint32(n * 8)
	return k
}

// copyChars copies s into a C char array and returns the bytes copied.
func copyChars(dst []int8, s string) int {
	n := 0
	for ; n < len(dst) && n < len(s); n++ {
		dst[n] = int8(s[n])
	}
	return n
}

// replace makes m hold exactly want.
func replace[K comparable, V any](m *ebpf.Map, want map[K]V) error {
	var (
		k     K
		v     V
		stale []K
	)
	it := m.Iterate()
	for it.Next(&k, &v) {
		if _, ok := want[k]; !ok {
			stale = append(stale, k)
		}
	}
	if err := it.Err(); err != nil {
		return err
	}
	for k, v := range want {
		if err := m.Put(k, v); err != nil {
			return err
		}
	}
	for _, k := range stale {
		if err := m.Delete(k); err != nil {
			return err
		}
	}
	return nil
}

// KernelDev converts a device number as stat reports it to the encoding the
// kernel keeps in super_block.s_dev, which is what the programs compare.
func KernelDev(major, minor uint32) uint32 {
	return major<<20 | minor
}

// PutInode watches one file by identity. dev is in the kernel's encoding.
func (s *Sensor) PutInode(dev uint32, inode uint64, bits uint32) error {
	return s.coll.Maps["inode_watch"].Put(tephraInodeKey{Inode: inode, Dev: dev}, bits)
}

// DeleteInode removes an identity watch; a missing entry is not an error.
func (s *Sensor) DeleteInode(dev uint32, inode uint64) error {
	err := s.coll.Maps["inode_watch"].Delete(tephraInodeKey{Inode: inode, Dev: dev})
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

// NetIgnored reports whether an address is covered by the ignore list, for
// tests and diagnostics.
func (s *Sensor) NetIgnored(a netip.Addr) bool {
	var v uint8
	if a.Is4() {
		return s.coll.Maps["net_ignore_v4"].Lookup(tephraIp4Key{Prefixlen: 32, Addr: a.As4()}, &v) == nil
	}
	return s.coll.Maps["net_ignore_v6"].Lookup(tephraIp6Key{Prefixlen: 128, Addr: a.As16()}, &v) == nil
}
