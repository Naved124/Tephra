// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// FPNamespace is where the ordinary workloads of a false-positive run live.
const FPNamespace = "tephra-fp"

// FalsePositives runs ordinary workloads for the given time and returns
// every alert that fired anywhere in the cluster meanwhile.
func (r *Runner) FalsePositives(ctx context.Context, manifest string, d time.Duration) (*FPResult, error) {
	c := r.Cluster
	_, _ = c.kubectl(ctx, nil, "delete", "namespace", FPNamespace, "--ignore-not-found", "--wait=true")
	if _, err := c.kubectl(ctx, nil, "create", "namespace", FPNamespace); err != nil {
		return nil, err
	}
	if !r.Keep {
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			_, _ = c.kubectl(cleanup, nil, "delete", "namespace", FPNamespace, "--wait=false")
		}()
	}
	if _, err := c.kubectl(ctx, nil, "-n", FPNamespace, "apply", "-f", manifest); err != nil {
		return nil, err
	}
	if r.Enforce != "" {
		// Every pod the workloads start, now and on every rollout, opts
		// in.
		if err := r.labelTemplates(ctx); err != nil {
			return nil, err
		}
	}
	r.logf("waiting for the workloads")
	for _, w := range []string{"deployment/web", "statefulset/db"} {
		if _, err := c.kubectl(ctx, nil, "-n", FPNamespace, "rollout", "status", w, "--timeout=600s"); err != nil {
			return nil, err
		}
	}

	// The clock starts once the workloads are up: their start-up is part
	// of ordinary life too, but pulling images is not what is measured.
	start := time.Now()
	dropsBefore, err := c.Drops(ctx)
	if err != nil {
		return nil, err
	}
	r.logf("workloads running; measuring for %s", d)
	rollout := time.NewTicker(5 * time.Minute)
	defer rollout.Stop()
	end := time.After(d)
loop:
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-end:
			break loop
		case <-rollout.C:
			r.logf("  rolling update of deployment/web (%s in)", time.Since(start).Round(time.Second))
			_, _ = c.kubectl(ctx, nil, "-n", FPNamespace, "rollout", "restart", "deployment/web")
		}
	}
	// Let the last records arrive.
	time.Sleep(5 * time.Second)

	alerts, err := c.Alerts(ctx, `{stream="alert"}`, start)
	if err != nil {
		return nil, err
	}
	type key struct{ rule, level, ns string }
	rows := map[key]*FPAlert{}
	for _, a := range alerts {
		k := key{a.Rule.ID, a.Rule.Level, a.K8s.Namespace}
		row := rows[k]
		if row == nil {
			row = &FPAlert{Rule: k.rule, Level: k.level, Namespace: k.ns, Example: a.Process.Image + " [" + a.Process.CommandLine + "]"}
			if len(row.Example) > 160 {
				row.Example = row.Example[:160] + "…"
			}
			rows[k] = row
		}
		row.Count++
	}
	res := &FPResult{Minutes: int(d.Minutes()), Enforce: r.Enforce}
	// Refusals are counted from the stored alerts, not from the agents'
	// counters, which start again from zero when an agent restarts.
	for _, a := range alerts {
		if a.Enforce != nil && a.Enforce.Denied {
			res.Denied++
		}
	}
	for _, row := range rows {
		res.Alerts = append(res.Alerts, *row)
	}
	sort.Slice(res.Alerts, func(i, j int) bool {
		a, b := res.Alerts[i], res.Alerts[j]
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		return a.Namespace < b.Namespace
	})
	if dropsAfter, err := c.Drops(ctx); err == nil && dropsAfter > dropsBefore {
		res.Drops = dropsAfter - dropsBefore
	}
	if len(alerts) == 5000 {
		return res, fmt.Errorf("the alert query hit its limit of 5000; the counts are incomplete")
	}
	return res, nil
}

// labelTemplates adds the enforcement label to the pod template of every
// workload in the false-positive namespace.
func (r *Runner) labelTemplates(ctx context.Context) error {
	c := r.Cluster
	names, err := c.kubectl(ctx, nil, "-n", FPNamespace, "get", "deployment,statefulset,daemonset,cronjob", "-o", "name")
	if err != nil {
		return err
	}
	label := fmt.Sprintf(`{"metadata":{"labels":{%q:"true"}}}`, EnforceLabel)
	for _, name := range strings.Fields(string(names)) {
		patch := `{"spec":{"template":` + label + `}}`
		if strings.HasPrefix(name, "cronjob") {
			patch = `{"spec":{"jobTemplate":{"spec":{"template":` + label + `}}}}`
		}
		if _, err := c.kubectl(ctx, nil, "-n", FPNamespace, "patch", name, "--type=merge", "-p", patch); err != nil {
			return err
		}
	}
	return nil
}
