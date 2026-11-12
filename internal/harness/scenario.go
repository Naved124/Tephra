// SPDX-License-Identifier: Apache-2.0

// Package harness runs attack scenarios in the lab cluster, checks which
// alerts they produced, and writes the coverage report. It refuses to run
// against a cluster that is not marked as a lab.
package harness

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"go.yaml.in/yaml/v3"
)

// Scenario is one directory under attacks/.
type Scenario struct {
	ID    string   `yaml:"id"`
	Title string   `yaml:"title"`
	Tags  []string `yaml:"tags"`
	// Expect lists the rule IDs that must fire.
	Expect []string `yaml:"expect"`
	// Timeout bounds the wait for the alerts after the technique ran.
	Timeout time.Duration `yaml:"timeout"`
	// Run says where run.sh is executed.
	Run Target `yaml:"run"`
	// AlertPod is the pod the alerts must name; it defaults to the pod
	// run.sh is executed in. It differs when the technique is launched
	// from one pod and takes effect in another.
	AlertPod string `yaml:"alert_pod"`
	// Note is printed in the report, for scenarios that need a caveat.
	Note string `yaml:"note"`

	// Dir is where the scenario was read from.
	Dir string `yaml:"-"`
}

// Target is a container in the scenario's namespace.
type Target struct {
	Pod       string `yaml:"pod"`
	Container string `yaml:"container"`
}

var (
	scenarioIDRE = regexp.MustCompile(`^[AE]\d{2}$`)
	ruleIDRE     = regexp.MustCompile(`^R\d{3}$`)
)

// LoadScenario reads and checks one scenario directory.
func LoadScenario(dir string) (*Scenario, error) {
	path := filepath.Join(dir, "scenario.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := &Scenario{Dir: dir, Timeout: 30 * time.Second}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	switch {
	case !scenarioIDRE.MatchString(s.ID):
		return nil, fmt.Errorf("%s: id %q is not A or E followed by two digits", path, s.ID)
	case s.Title == "":
		return nil, fmt.Errorf("%s: title is missing", path)
	case len(s.Expect) == 0:
		return nil, fmt.Errorf("%s: expect lists no rule", path)
	case s.Run.Pod == "":
		return nil, fmt.Errorf("%s: run.pod is missing", path)
	case s.Timeout <= 0:
		return nil, fmt.Errorf("%s: timeout must be positive", path)
	}
	for _, r := range s.Expect {
		if !ruleIDRE.MatchString(r) {
			return nil, fmt.Errorf("%s: expected rule %q is not R followed by three digits", path, r)
		}
	}
	if s.AlertPod == "" {
		s.AlertPod = s.Run.Pod
	}
	for _, f := range []string{"target.yaml", "run.sh"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			return nil, fmt.Errorf("%s: scenario needs %s", dir, f)
		}
	}
	return s, nil
}

// LoadAll reads every scenario under root, in ID order. Directories without
// a scenario.yaml are ignored.
func LoadAll(root string) ([]*Scenario, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var out []*Scenario
	seen := map[string]string{}
	for _, e := range entries {
		dir := filepath.Join(root, e.Name())
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, "scenario.yaml")); err != nil {
			continue
		}
		s, err := LoadScenario(dir)
		if err != nil {
			return nil, err
		}
		if prev, dup := seen[s.ID]; dup {
			return nil, fmt.Errorf("scenario id %s is used by both %s and %s", s.ID, prev, dir)
		}
		seen[s.ID] = dir
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Select returns the scenarios with the given IDs, in the order asked for.
func Select(all []*Scenario, ids []string) ([]*Scenario, error) {
	byID := map[string]*Scenario{}
	for _, s := range all {
		byID[s.ID] = s
	}
	var out []*Scenario
	for _, id := range ids {
		s, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("no scenario %s", id)
		}
		out = append(out, s)
	}
	return out, nil
}
