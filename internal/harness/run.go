// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Verdicts for one expected rule.
const (
	Detected = "detected"
	// Partial: the alert fired but does not name the right pod, or has no
	// container or process.
	Partial = "partial"
	Missed  = "missed"
)

// RuleResult is the outcome for one expected rule.
type RuleResult struct {
	Rule    string `json:"rule"`
	Verdict string `json:"verdict"`
	// LatencyMS is the time from the start of the technique to the event
	// that raised the alert, by the event's own kernel timestamp.
	LatencyMS int64 `json:"latency_ms,omitempty"`
	// Why explains a partial verdict.
	Why string `json:"why,omitempty"`
	// Event is the alert as stored, kept so the detection can be read
	// back and reused as a rule test.
	Event string `json:"event,omitempty"`
}

// Result is the outcome of one scenario.
type Result struct {
	ID    string       `json:"id"`
	Title string       `json:"title"`
	Tags  []string     `json:"tags,omitempty"`
	Rules []RuleResult `json:"rules"`
	// AlsoFired lists rules that fired in the scenario's namespace without
	// being expected.
	AlsoFired []string `json:"also_fired,omitempty"`
	// VisibleMS is how long after the start of the technique every
	// expected alert could be queried.
	VisibleMS int64  `json:"visible_ms,omitempty"`
	Drops     uint64 `json:"ring_buffer_drops"`
	Note      string `json:"note,omitempty"`
	// Error is set when the scenario itself could not be run.
	Error string `json:"error,omitempty"`
	// Predicted is the expected verdict of an evasion scenario.
	Predicted string `json:"predicted,omitempty"`
	// DropsVisible: the scenario expects drops and the sensor reported
	// some.
	DropsVisible bool `json:"drops_visible,omitempty"`
	// AgentRestarts is how many times agent containers restarted while
	// the scenario ran.
	AgentRestarts int `json:"agent_restarts,omitempty"`
	// Enforce is the enforcement mode of the run, dry-run or on; empty for
	// a detection run.
	Enforce string `json:"enforce,omitempty"`
	// TookEffect says whether the technique went through, in an
	// enforcement run.
	TookEffect *bool `json:"took_effect,omitempty"`
}

// Enforcement modes of a run.
const (
	EnforceDryRun = "dry-run"
	EnforceOn     = "on"
)

// Verdict is the scenario's overall verdict: the worst of its rules.
func (r *Result) Verdict() string {
	if r.Error != "" {
		return "error"
	}
	if r.TookEffect != nil {
		switch {
		case r.Enforce == EnforceOn && *r.TookEffect:
			return "not-refused"
		case r.Enforce == EnforceDryRun && !*r.TookEffect:
			return "refused-in-dry-run"
		}
	}
	worst := Detected
	for _, rr := range r.Rules {
		switch rr.Verdict {
		case Missed:
			return Missed
		case Partial:
			worst = Partial
		}
	}
	return worst
}

func sortAlerts(as []*Alert) {
	sort.SliceStable(as, func(i, j int) bool { return as[i].TS < as[j].TS })
}

// judge turns the alerts of a scenario's namespace into verdicts.
func judge(s *Scenario, alerts []*Alert, start time.Time) (rules []RuleResult, also []string) {
	return judgeRules(s, s.Expect, alerts, start)
}

// judgeEnforce is judge for an enforcement run: the rules are the ones that
// must refuse, and only the alerts of refusals (or would-be refusals, in
// dry-run) count for them.
func judgeEnforce(s *Scenario, mode string, alerts []*Alert, start time.Time) (rules []RuleResult, also []string) {
	want := s.Enforce.On
	if mode == EnforceDryRun {
		want = s.Enforce.DryRun
	}
	var refusals []*Alert
	for _, a := range alerts {
		if a.Enforce != nil && a.Enforce.Denied == (mode == EnforceOn) {
			refusals = append(refusals, a)
		}
	}
	rules, _ = judgeRules(s, want, refusals, start)
	_, also = judgeRules(s, want, alerts, start)
	return rules, also
}

func judgeRules(s *Scenario, want []string, alerts []*Alert, start time.Time) (rules []RuleResult, also []string) {
	expected := map[string]bool{}
	for _, id := range want {
		expected[id] = true
		rr := RuleResult{Rule: id, Verdict: Missed}
		for _, a := range alerts {
			if a.Rule.ID != id {
				continue
			}
			why := ""
			switch {
			case a.K8s.Pod != s.AlertPod:
				why = fmt.Sprintf("alert names pod %q, expected %q", a.K8s.Pod, s.AlertPod)
			case a.Container == nil || a.Container.Name == "":
				why = "alert has no container"
			case a.Process.Image == "":
				why = "alert has no process image"
			}
			if why == "" {
				rr = RuleResult{Rule: id, Verdict: Detected, LatencyMS: a.Time().Sub(start).Milliseconds(), Event: a.Line}
				break
			}
			if rr.Verdict == Missed {
				rr = RuleResult{Rule: id, Verdict: Partial, Why: why, Event: a.Line}
			}
		}
		rules = append(rules, rr)
	}
	seen := map[string]bool{}
	for _, a := range alerts {
		if !expected[a.Rule.ID] && !seen[a.Rule.ID] {
			seen[a.Rule.ID] = true
			also = append(also, a.Rule.ID)
		}
	}
	sort.Strings(also)
	return rules, also
}

func complete(rules []RuleResult) bool {
	for _, r := range rules {
		if r.Verdict != Detected {
			return false
		}
	}
	return true
}

// notCarriedOut is the exit status by which run.sh says it could not carry
// out the technique, so the scenario has no result.
const notCarriedOut = 99

// scriptTimeout bounds run.sh.
const scriptTimeout = 5 * time.Minute

// Runner runs scenarios against a cluster.
type Runner struct {
	Cluster *Cluster
	Log     io.Writer
	// Keep leaves the scenario namespaces in place, for debugging.
	Keep bool
	// Enforce is empty for a detection run, or EnforceDryRun or
	// EnforceOn: the scenario's pods then carry the enforcement label and
	// what is judged is the refusal.
	Enforce string
}

// EnforceLabel opts a pod in to enforcement, as in the chart's default.
const EnforceLabel = "tephra.dev/enforce"

func (r *Runner) logf(format string, args ...any) {
	if r.Log != nil {
		_, _ = fmt.Fprintf(r.Log, format+"\n", args...)
	}
}

func suffix() string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Run executes one scenario: a fresh namespace, the target workload, the
// technique, the wait for alerts, clean-up.
func (r *Runner) Run(ctx context.Context, s *Scenario) *Result {
	res := &Result{ID: s.ID, Title: s.Title, Tags: s.Tags, Note: s.Note, Enforce: r.Enforce, Predicted: s.Predicted}
	c := r.Cluster
	ns := "tephra-" + strings.ToLower(s.ID) + "-" + suffix()
	want := s.Expect
	judgeFn := judge
	if r.Enforce != "" {
		if s.Enforce == nil {
			res.Error = "the scenario has no enforce section"
			return res
		}
		want = s.Enforce.On
		if r.Enforce == EnforceDryRun {
			want = s.Enforce.DryRun
		}
		judgeFn = func(s *Scenario, alerts []*Alert, start time.Time) ([]RuleResult, []string) {
			return judgeEnforce(s, r.Enforce, alerts, start)
		}
	}
	fail := func(step string, err error) *Result {
		res.Error = step + ": " + err.Error()
		for _, id := range want {
			res.Rules = append(res.Rules, RuleResult{Rule: id, Verdict: Missed, Why: "scenario did not run"})
		}
		return res
	}

	if _, err := c.kubectl(ctx, nil, "create", "namespace", ns); err != nil {
		return fail("create namespace", err)
	}
	defer func() {
		if r.Keep {
			r.logf("  namespace %s kept", ns)
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if _, err := os.Stat(filepath.Join(s.Dir, "cleanup.sh")); err == nil {
			_, _ = c.execScript(cleanup, ns, s.Run, filepath.Join(s.Dir, "cleanup.sh"))
		}
		_, _ = c.kubectl(cleanup, nil, "delete", "namespace", ns, "--wait=false")
	}()
	_, _ = c.kubectl(ctx, nil, "label", "namespace", ns, "tephra.dev/harness=true")

	if _, err := c.kubectl(ctx, nil, "-n", ns, "apply", "-f", filepath.Join(s.Dir, "target.yaml")); err != nil {
		return fail("apply target", err)
	}
	if _, err := c.kubectl(ctx, nil, "-n", ns, "wait", "--for=condition=Ready", "pod", "--all", "--timeout=180s"); err != nil {
		return fail("wait for target", err)
	}
	if r.Enforce != "" {
		if _, err := c.kubectl(ctx, nil, "-n", ns, "label", "pod", "--all", EnforceLabel+"=true"); err != nil {
			return fail("label for enforcement", err)
		}
	}
	// Let the agent learn of the new pod before anything happens in it.
	time.Sleep(2 * time.Second)

	dropsBefore, err := c.Drops(ctx)
	if err != nil {
		return fail("read drop counters", err)
	}
	restartsBefore, err := c.AgentRestarts(ctx)
	if err != nil {
		return fail("read agent restarts", err)
	}
	start := time.Now()
	// A technique that hangs must not hold up the run.
	scriptCtx, cancel := context.WithTimeout(ctx, scriptTimeout)
	out, runErr := c.execScript(scriptCtx, ns, s.Run, filepath.Join(s.Dir, "run.sh"))
	cancel()
	if runErr != nil {
		// Many techniques end with a non-zero status; what counts is
		// whether the alert fires. Status 99 is run.sh saying that it
		// could not carry the technique out at all.
		var ee *exec.ExitError
		if errors.As(runErr, &ee) && ee.ExitCode() == notCarriedOut {
			return fail("run.sh", fmt.Errorf("technique not carried out: %s", strings.TrimSpace(string(out))))
		}
		r.logf("  run.sh: %v %s", runErr, strings.TrimSpace(string(out)))
	}
	if r.Enforce != "" {
		took := runErr == nil
		if s.Enforce.Effect != "" {
			_, err := c.execCommand(ctx, ns, s.Run, s.Enforce.Effect)
			took = err == nil
		}
		res.TookEffect = &took
	}

	selector := fmt.Sprintf(`{stream="alert", namespace=%q}`, ns)
	deadline := time.Now().Add(s.Timeout)
	for {
		alerts, err := c.Alerts(ctx, selector, start.Add(-2*time.Second))
		if err != nil {
			return fail("query alerts", err)
		}
		res.Rules, res.AlsoFired = judgeFn(s, alerts, start)
		if complete(res.Rules) {
			res.VisibleMS = time.Since(start).Milliseconds()
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Second)
	}
	if n, err := c.AgentRestarts(ctx); err == nil && n > restartsBefore {
		res.AgentRestarts = n - restartsBefore
	}
	if dropsAfter, err := c.Drops(ctx); err == nil && dropsAfter > dropsBefore {
		res.Drops = dropsAfter - dropsBefore
	}
	res.DropsVisible = s.ExpectDrops && res.Drops > 0
	return res
}
