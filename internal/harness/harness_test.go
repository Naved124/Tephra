// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Naved124/tephra/internal/rules"
)

func nodes(labels ...string) []byte {
	var items []string
	for i, l := range labels {
		items = append(items, `{"metadata":{"name":"n`+string(rune('0'+i))+`","labels":{`+l+`}},"status":{"nodeInfo":{"kernelVersion":"6.8.0"}}}`)
	}
	return []byte(`{"items":[` + strings.Join(items, ",") + `]}`)
}

// The harness runs attack techniques. It must refuse any cluster that is not
// marked as a lab on every node.
func TestLabGuard(t *testing.T) {
	lab := `"tephra.dev/lab":"true"`
	if k, err := checkLab(nodes(lab, lab, lab)); err != nil || k != "6.8.0" {
		t.Errorf("lab cluster refused: %v", err)
	}
	for name, raw := range map[string][]byte{
		"no label":            nodes(`"kubernetes.io/os":"linux"`),
		"one node unlabelled": nodes(lab, `"x":"y"`, lab),
		"label set to false":  nodes(`"tephra.dev/lab":"false"`),
		"label with no value": nodes(`"tephra.dev/lab":""`),
		"no nodes":            []byte(`{"items":[]}`),
		"not a node list":     []byte(`error from server`),
	} {
		if _, err := checkLab(raw); err == nil {
			t.Errorf("%s: accepted as a lab cluster", name)
		}
	}
}

func alert(rule, pod, container, image string, at time.Time) *Alert {
	a := &Alert{TS: at.UTC().Format("2006-01-02T15:04:05.000000Z"), Line: `{"rule":"` + rule + `"}`}
	a.Rule.ID = rule
	a.K8s.Pod = pod
	a.Process.Image = image
	if container != "" {
		a.Container = &struct {
			Name string `json:"name"`
		}{container}
	}
	return a
}

func TestJudge(t *testing.T) {
	start := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	s := &Scenario{ID: "A01", Expect: []string{"R001", "R002", "R003"}, AlertPod: "web"}
	rules, also := judge(s, []*Alert{
		// Wrong pod first, then the right one: the right one wins.
		alert("R001", "other", "c", "/bin/sh", start.Add(100*time.Millisecond)),
		alert("R001", "web", "web", "/bin/sh", start.Add(250*time.Millisecond)),
		// Fired, but without a container.
		alert("R002", "web", "", "/bin/sh", start.Add(300*time.Millisecond)),
		alert("R004", "web", "web", "/bin/wget", start),
		alert("R004", "web", "web", "/bin/wget", start),
	}, start)

	if rules[0].Verdict != Detected || rules[0].LatencyMS != 250 || rules[0].Event == "" {
		t.Errorf("R001: %+v", rules[0])
	}
	if rules[1].Verdict != Partial || rules[1].Why != "alert has no container" {
		t.Errorf("R002: %+v", rules[1])
	}
	if rules[2].Verdict != Missed {
		t.Errorf("R003: %+v", rules[2])
	}
	if len(also) != 1 || also[0] != "R004" {
		t.Errorf("also fired: %v", also)
	}
	if complete(rules) {
		t.Error("an incomplete result counted as complete")
	}

	res := &Result{Rules: rules}
	if res.Verdict() != Missed {
		t.Errorf("overall verdict %s, want missed", res.Verdict())
	}
	res.Rules = rules[:2]
	if res.Verdict() != Partial {
		t.Errorf("overall verdict %s, want partial", res.Verdict())
	}
	res.Rules = rules[:1]
	if res.Verdict() != Detected || !complete(res.Rules) {
		t.Errorf("overall verdict %s, want detected", res.Verdict())
	}
	res.Error = "boom"
	if res.Verdict() != "error" {
		t.Errorf("overall verdict %s, want error", res.Verdict())
	}
}

func writeScenario(t *testing.T, root, name, yaml string, files ...string) string {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range append([]string{"scenario.yaml"}, files...) {
		body := "#!/bin/sh\n"
		if f == "scenario.yaml" {
			body = yaml
		}
		if err := os.WriteFile(filepath.Join(dir, f), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestLoadScenarios(t *testing.T) {
	root := t.TempDir()
	good := "id: A02\ntitle: Second\nexpect: [R003]\nrun: {pod: victim}\n"
	writeScenario(t, root, "A02-second", good, "target.yaml", "run.sh")
	writeScenario(t, root, "A01-first", "id: A01\ntitle: First\ntags: [attack.execution]\nexpect: [R001, R002]\ntimeout: 45s\nrun: {pod: listener, container: c}\nalert_pod: web\n", "target.yaml", "run.sh", "cleanup.sh")
	if err := os.MkdirAll(filepath.Join(root, "fp"), 0o755); err != nil {
		t.Fatal(err)
	}

	all, err := LoadAll(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || all[0].ID != "A01" || all[1].ID != "A02" {
		t.Fatalf("loaded %v", all)
	}
	if a := all[0]; a.Timeout != 45*time.Second || a.AlertPod != "web" || a.Run.Container != "c" {
		t.Errorf("A01: %+v", a)
	}
	if a := all[1]; a.Timeout != 30*time.Second || a.AlertPod != "victim" {
		t.Errorf("A02 defaults: %+v", a)
	}
	if picked, err := Select(all, []string{"A02", "A01"}); err != nil || picked[0].ID != "A02" {
		t.Errorf("select: %v %v", picked, err)
	}
	if _, err := Select(all, []string{"A99"}); err == nil {
		t.Error("unknown scenario selected")
	}

	for name, tc := range map[string]struct {
		yaml  string
		files []string
		want  string
	}{
		"bad id":         {"id: X1\ntitle: t\nexpect: [R001]\nrun: {pod: p}\n", []string{"target.yaml", "run.sh"}, "id"},
		"no title":       {"id: A03\nexpect: [R001]\nrun: {pod: p}\n", []string{"target.yaml", "run.sh"}, "title"},
		"no expectation": {"id: A03\ntitle: t\nrun: {pod: p}\n", []string{"target.yaml", "run.sh"}, "expect"},
		"bad rule":       {"id: A03\ntitle: t\nexpect: [R1]\nrun: {pod: p}\n", []string{"target.yaml", "run.sh"}, "R1"},
		"no pod":         {"id: A03\ntitle: t\nexpect: [R001]\n", []string{"target.yaml", "run.sh"}, "run.pod"},
		"unknown key":    {"id: A03\ntitle: t\nexpect: [R001]\nrun: {pod: p}\nexpects: [R002]\n", []string{"target.yaml", "run.sh"}, "expects"},
		"no run.sh":      {"id: A03\ntitle: t\nexpect: [R001]\nrun: {pod: p}\n", []string{"target.yaml"}, "run.sh"},
		"duplicate id":   {good, []string{"target.yaml", "run.sh"}, "used by both"},
	} {
		bad := t.TempDir()
		writeScenario(t, bad, "A02-second", good, "target.yaml", "run.sh")
		writeScenario(t, bad, "Axx", tc.yaml, tc.files...)
		if _, err := LoadAll(bad); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want an error containing %q", name, err, tc.want)
		}
	}
}

func TestReport(t *testing.T) {
	r := &Report{Date: "2026-11-12", Sensor: "tephra/tephrad:dev", Kernel: "6.8.0"}
	r.Merge([]*Result{
		{ID: "A02", Title: "Memfd", Rules: []RuleResult{{Rule: "R003", Verdict: Missed}}},
		{ID: "A01", Title: "Reverse shell", Rules: []RuleResult{{Rule: "R001", Verdict: Detected, LatencyMS: 1200}, {Rule: "R002", Verdict: Partial, Why: "alert has no container"}}, AlsoFired: []string{"R004"}, VisibleMS: 2500, Drops: 3},
	})
	// A later run of one scenario replaces only that scenario.
	r.Merge([]*Result{{ID: "A02", Title: "Memfd", Rules: []RuleResult{{Rule: "R003", Verdict: Detected, LatencyMS: 400}}, VisibleMS: 1500}})
	r.FalsePositives = &FPResult{Minutes: 30, Alerts: []FPAlert{
		{Rule: "R004", Level: "low", Namespace: "tephra-fp", Count: 12, Example: "/usr/bin/curl [curl x | y]"},
		{Rule: "R015", Level: "high", Namespace: "tephra-fp", Count: 2},
	}}

	md := r.Markdown()
	for _, want := range []string{
		"**2 scenarios: 1 detected, 1 partial, 0 missed.** Ring buffer drops during the runs: 3.",
		"| A01 | Reverse shell | R001, R002 (partial) | **partial** | 1.2 s | 2.5 s | R004 |",
		"| A02 | Memfd | R003 | **detected** | 0.4 s | 1.5 s | — |",
		"- A01, R002: alert has no container.",
		"**High or critical alerts: 2.**",
		"| R004 | low | tephra-fp | 12 | `/usr/bin/curl [curl x \\| y]` |",
		"R019",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("report lacks %q\n%s", want, md)
		}
	}

	dir := t.TempDir()
	if err := r.Write(dir); err != nil {
		t.Fatal(err)
	}
	back, err := LoadReport(filepath.Join(dir, "coverage.json"))
	if err != nil || len(back.Results) != 2 || back.FalsePositives.Serious() != 2 || back.Markdown() != md {
		t.Errorf("report did not survive a round trip: %v", err)
	}
	if empty, err := LoadReport(filepath.Join(dir, "none.json")); err != nil || len(empty.Results) != 0 {
		t.Errorf("missing report: %v", err)
	}
}

func TestBuildVersion(t *testing.T) {
	metrics := "# HELP x\ntephra_build_info{version=\"3e540da-dirty\"} 1\ntephra_rules_loaded 21\n"
	if got := buildVersion(metrics); got != "3e540da-dirty" {
		t.Errorf("version %q", got)
	}
	if got := buildVersion("tephra_rules_loaded 21\n"); got != "" {
		t.Errorf("version %q from metrics without one", got)
	}
}

func refusal(rule string, denied bool, at time.Time) *Alert {
	a := alert(rule, "victim", "victim", "/bin/sh", at)
	a.Enforce = &struct {
		Action string `json:"action"`
		Denied bool   `json:"denied"`
	}{"mount", denied}
	return a
}

// Under enforcement only the alert of a refusal of the right kind counts:
// the ordinary alert of the rule does not, nor a would-be refusal when
// enforcement is on.
func TestJudgeEnforce(t *testing.T) {
	start := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	s := &Scenario{ID: "A10", AlertPod: "victim", Enforce: &EnforceSpec{DryRun: []string{"R017", "R011"}, On: []string{"R017"}}}
	ordinary := alert("R017", "victim", "victim", "/bin/mount", start.Add(time.Millisecond))

	rules, _ := judgeEnforce(s, EnforceOn, []*Alert{ordinary, refusal("R017", false, start)}, start)
	if len(rules) != 1 || rules[0].Verdict != Missed {
		t.Errorf("on, no refusal: %+v", rules)
	}
	rules, _ = judgeEnforce(s, EnforceOn, []*Alert{refusal("R017", true, start)}, start)
	if len(rules) != 1 || rules[0].Verdict != Detected {
		t.Errorf("on, refused: %+v", rules)
	}
	rules, _ = judgeEnforce(s, EnforceDryRun, []*Alert{refusal("R017", false, start), refusal("R011", false, start)}, start)
	if len(rules) != 2 || rules[0].Verdict != Detected || rules[1].Verdict != Detected {
		t.Errorf("dry-run: %+v", rules)
	}
}

func TestEnforceVerdict(t *testing.T) {
	yes, no := true, false
	ok := []RuleResult{{Rule: "R017", Verdict: Detected}}
	for _, tc := range []struct {
		mode string
		took *bool
		want string
	}{
		{EnforceOn, &no, Detected},
		{EnforceOn, &yes, "not-refused"},
		{EnforceDryRun, &yes, Detected},
		{EnforceDryRun, &no, "refused-in-dry-run"},
	} {
		r := &Result{Enforce: tc.mode, TookEffect: tc.took, Rules: ok}
		if got := r.Verdict(); got != tc.want {
			t.Errorf("%s took effect %v: %s, want %s", tc.mode, *tc.took, got, tc.want)
		}
	}
}

func TestSumSamples(t *testing.T) {
	page := `# HELP x
tephra_kernel_events_total{type="exec",outcome="dropped"} 3
tephra_kernel_events_total{type="exec",outcome="sent"} 100
tephra_kernel_events_total{type="open",outcome="dropped"} 4
tephra_enforce_mode 2
tephra_enforce_mode_other 7
`
	if n := sumSamples(page, "tephra_kernel_events_total", `outcome="dropped"`); n != 7 {
		t.Errorf("drops %d, want 7", n)
	}
	if n := sumSamples(page, "tephra_enforce_mode"); n != 2 {
		t.Errorf("mode %d, want 2", n)
	}
}

func TestShippedEnforceScenarios(t *testing.T) {
	all, err := LoadAll(filepath.Join("..", "..", "attacks"))
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, s := range all {
		if s.Enforce != nil {
			ids = append(ids, s.ID)
		}
	}
	if got := strings.Join(ids, " "); got != "A02 A06 A10 A13 A14 A15" {
		t.Errorf("blockable scenarios %s", got)
	}
	set, err := rules.Load(filepath.Join("..", "..", "rules"))
	if err != nil {
		t.Fatal(err)
	}
	block := map[string]bool{}
	for _, r := range set.Rules {
		block[r.ID] = r.Action == "block"
	}
	for _, s := range all {
		if s.Enforce == nil {
			continue
		}
		for _, id := range append(append([]string{}, s.Enforce.DryRun...), s.Enforce.On...) {
			if !block[id] {
				t.Errorf("%s: enforce names %s, which is not a block rule", s.ID, id)
			}
		}
	}
}

func TestEvasionVerdicts(t *testing.T) {
	missed := []RuleResult{{Rule: "R005", Verdict: Missed}}
	hit := []RuleResult{{Rule: "R005", Verdict: Detected}}
	for _, tc := range []struct {
		r        Result
		measured string
		held     bool
	}{
		{Result{Predicted: Missed, Rules: missed}, Missed, true},
		{Result{Predicted: Missed, Rules: hit}, Detected, false},
		{Result{Predicted: Detected, Rules: missed, DropsVisible: true}, DropsReported, true},
		{Result{Predicted: Detected, Rules: missed}, Missed, false},
		{Result{Predicted: Partial, Rules: hit}, Detected, false},
	} {
		if m := tc.r.Measured(); m != tc.measured || tc.r.PredictionHeld() != tc.held {
			t.Errorf("%+v: measured %s held %v, want %s %v", tc.r, m, tc.r.PredictionHeld(), tc.measured, tc.held)
		}
	}
	md := (&EvasionReport{Date: "2026-11-13", Results: []*Result{{ID: "E01", Title: "x", Predicted: Missed, Rules: hit}}}).Markdown()
	if !strings.Contains(md, "| E01 | x | R005 detected | missed | detected | corrected |") {
		t.Errorf("markdown row missing:\n%s", md)
	}
}

func TestShippedEvasions(t *testing.T) {
	all, err := LoadAll(filepath.Join("..", "..", "evasions"))
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 8 {
		t.Fatalf("%d evasion scenarios, want 8", len(all))
	}
	for _, s := range all {
		if !strings.HasPrefix(s.ID, "E") || s.Predicted == "" {
			t.Errorf("%s: predicted %q", s.ID, s.Predicted)
		}
	}
}
