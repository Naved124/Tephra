// SPDX-License-Identifier: Apache-2.0

package export

import "testing"

func TestNetworkLoopback(t *testing.T) {
	for n, want := range map[*Network]bool{
		nil:                                       false,
		{DestinationIP: "127.0.0.1"}:              true,
		{DestinationIP: "127.9.9.9"}:              true,
		{DestinationIP: "::1"}:                    true,
		{DestinationIP: "::ffff:127.0.0.1"}:       true,
		{DestinationIP: "10.0.0.1"}:               false,
		{Family: "unix", UnixPath: "/run/x.sock"}: false,
	} {
		if got := n.Loopback(); got != want {
			t.Errorf("%+v: loopback %v, want %v", n, got, want)
		}
	}
}
