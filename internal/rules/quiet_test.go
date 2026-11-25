// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"math/rand"
	"reflect"
	"testing"

	"github.com/Naved124/tephra/internal/export"
)

func shippedSet(t testing.TB) *Set {
	t.Helper()
	s, err := Load("../../rules")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func connRec(image, identity string, main, entrypoint bool, ns string) *export.Record {
	return &export.Record{
		Type:      "connect",
		Process:   export.Process{PID: 10, Image: image, Identity: identity, IsMainBinary: main},
		Parent:    &export.Parent{PID: 1, Image: "/bin/sh", ContainerFirst: entrypoint},
		Container: &export.Container{ID: "c1"},
		K8s:       export.K8s{Namespace: ns, Pod: "p"},
		Network:   &export.Network{Direction: "outbound", Family: "ipv4", Protocol: "tcp", DestinationIP: "10.0.0.9", DestinationPort: 80},
	}
}

func TestQuietShippedRules(t *testing.T) {
	s := shippedSet(t)
	for _, tc := range []struct {
		name    string
		rec     *export.Record
		out, in bool
	}{
		{"web server, the container's program", connRec("/usr/sbin/nginx", "", true, false, "shop"), true, true},
		{"load client, not an interpreter", connRec("/usr/bin/ab", "", false, false, "bench"), true, true},
		{"interpreter run by hand", connRec("/usr/bin/python3", "interpreter", false, false, "shop"), false, false},
		{"interpreter recognised by name only", connRec("/opt/py/python3.12", "", false, false, "shop"), false, false},
		{"interpreter that is the application", connRec("/usr/bin/python3", "interpreter", true, false, "shop"), true, true},
		{"interpreter started by the entrypoint", connRec("/usr/bin/python3", "interpreter", false, true, "shop"), true, true},
		{"interpreter on the node", connRec("/usr/bin/python3", "interpreter", false, false, "host"), true, true},
	} {
		out, in := s.Quiet(tc.rec)
		if out != tc.out || in != tc.in {
			t.Errorf("%s: Quiet = %v, %v; want %v, %v", tc.name, out, in, tc.out, tc.in)
		}
	}
	want := []uint16{3333, 4444, 5555, 6666, 7777, 14433, 14444, 45560, 45700}
	if got := s.AlwaysReportPorts(); !reflect.DeepEqual(got, want) {
		t.Errorf("AlwaysReportPorts = %v, want %v", got, want)
	}
}

func parse(t *testing.T, y string) *Set {
	t.Helper()
	rs, err := Parse("test.yaml", []byte(y))
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSet(rs)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A rule the kernel cannot check for itself keeps every process reported.
func TestQuietFailsOpen(t *testing.T) {
	nginx := connRec("/usr/sbin/nginx", "", true, false, "shop")
	for name, y := range map[string]string{
		"destination address": `
id: X1
title: t
level: low
event: connect
detection:
  sel: {network.DestinationIp|cidr: [203.0.113.0/24]}
  condition: sel
action: alert`,
		"parent's binary, which can change": `
id: X2
title: t
level: low
event: connect
detection:
  sel: {parent.Image: /usr/sbin/nginx}
  condition: sel
action: alert`,
		"a pod label, which can change": `
id: X3
title: t
level: low
event: connect
detection:
  sel: {k8s.labels.app: web}
  condition: sel
action: alert`,
		"not a fact that can change": `
id: X5
title: t
level: low
event: connect
detection:
  out: {network.direction: outbound}
  par: {parent.Image: /bin/sh}
  condition: out and not par
action: alert`,
		"a destination port range": `
id: X4
title: t
level: low
event: connect
detection:
  sel: {network.DestinationPort|gt: 1024}
  condition: sel
action: alert`,
	} {
		out, _ := parse(t, y).Quiet(nginx)
		if out {
			t.Errorf("%s: outbound quiet, want reported", name)
		}
	}
	// A destination port named by a rule is reported by the kernel, so
	// the rule does not keep the process reported.
	s := parse(t, `
id: X6
title: t
level: low
event: connect
detection:
  sel: {network.DestinationPort: [8443, 9443]}
  condition: sel
action: alert`)
	if out, _ := s.Quiet(nginx); !out {
		t.Error("a rule on named destination ports keeps the process reported")
	}
	if got := s.AlwaysReportPorts(); !reflect.DeepEqual(got, []uint16{8443, 9443}) {
		t.Errorf("AlwaysReportPorts = %v", got)
	}
}

// Soundness: whatever process facts and connection, when Quiet says a
// direction is quiet, no shipped rule fires on a connection in that
// direction that the kernel would skip, the ones not to an always-reported
// port or to the API.
func TestQuietIsSound(t *testing.T) {
	s := shippedSet(t)
	always := map[uint16]bool{}
	for _, p := range s.AlwaysReportPorts() {
		always[p] = true
	}
	rng := rand.New(rand.NewSource(7))
	pick := func(xs ...string) string { return xs[rng.Intn(len(xs))] }
	ports := []uint16{22, 80, 443, 3333, 4444, 6443, 8080, 14444, 45700, 53}
	quietSeen := 0
	for i := 0; i < 50000; i++ {
		rec := &export.Record{
			Process: export.Process{
				PID:          uint32(rng.Intn(100)),
				Image:        pick("/usr/sbin/nginx", "/usr/bin/python3", "/usr/bin/perl", "/bin/sh", "/usr/bin/curl", "/usr/local/bin/node", "/tmp/x"),
				Identity:     pick("", "interpreter", "shell", "download"),
				IsMainBinary: rng.Intn(2) == 0,
				Runtime:      rng.Intn(8) == 0,
				UID:          uint32(rng.Intn(2) * 1000),
			},
			Parent:    &export.Parent{PID: 1, Image: pick("/bin/sh", "/usr/sbin/nginx"), ContainerFirst: rng.Intn(2) == 0},
			Container: &export.Container{ID: "c1"},
			K8s:       export.K8s{Namespace: pick("shop", "host", "kube-system", "unknown"), Pod: "p"},
		}
		judged := *rec
		judged.Type = pick("connect", "accept")
		out, in := s.Quiet(&judged)
		for _, dir := range []struct {
			event, direction string
			quiet            bool
		}{{"connect", "outbound", out}, {"accept", "inbound", in}} {
			if !dir.quiet {
				continue
			}
			quietSeen++
			for k := 0; k < 8; k++ {
				c := *rec
				c.Type = dir.event
				port := ports[rng.Intn(len(ports))]
				api := dir.event == "connect" && rng.Intn(4) == 0
				c.Network = &export.Network{Direction: dir.direction, Family: pick("ipv4", "ipv6"), Protocol: pick("tcp", "udp"),
					DestinationIP: "10.0.0.1", DestinationPort: port, IsK8sAPI: api}
				if dir.event == "connect" && (always[port] || api) {
					continue // the kernel reports it
				}
				for _, r := range s.netRules(dir.event) {
					if r.Matches(&c) {
						t.Fatalf("rule %s fires on a connection the kernel would skip: %+v %+v", r.ID, c.Process, c.Network)
					}
				}
			}
		}
	}
	if quietSeen < 1000 {
		t.Fatalf("only %d quiet judgements: the test checks too little", quietSeen)
	}
}
