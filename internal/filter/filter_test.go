// SPDX-License-Identifier: Apache-2.0

package filter

import "testing"

func TestSetMatch(t *testing.T) {
	s := Set{Watches: []Watch{
		{Kind: Exact, Path: "/etc/shadow", Bits: Read | Write},
		{Kind: Exact, Path: "/etc/shadow", Bits: Denied},
		{Kind: Prefix, Path: "/etc/cron.d/", Bits: Write},
		{Kind: Name, Path: "authorized_keys", Bits: Denied},
	}}
	for path, want := range map[string]uint32{
		"/etc/shadow":                Read | Write | Denied,
		"/etc/shadow-":               0,
		"/etc/cron.d/job":            Write,
		"/etc/cron.d":                0,
		"/root/.ssh/authorized_keys": Denied,
		"authorized_keys":            Denied,
		"shadow":                     0,
		"":                           0,
	} {
		if got := s.Match(path); got != want {
			t.Errorf("Match(%q) = %d, want %d", path, got, want)
		}
	}
}
