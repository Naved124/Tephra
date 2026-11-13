// SPDX-License-Identifier: Apache-2.0

// harness runs the attack scenarios under attacks/ against the lab cluster
// and writes the coverage report. Lab use only: it refuses to run unless
// every node of the cluster is labelled tephra.dev/lab=true.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Naved124/tephra/internal/harness"
)

const usage = `usage:
  harness list
  harness run [flags] --all | <id>...
  harness fp  [flags]
  harness run --evasions [flags] --all | <id>...

With --enforce dry-run|on, "run" takes the scenarios that enforcement
refuses, runs them in pods carrying the enforcement label and judges the
refusal; "fp" runs the ordinary workloads that way and counts refusals.
The agents must already run enforcement in that mode.

Runs real attack techniques. Use it only on the lab VM or a throwaway
cluster you own; it refuses a cluster whose nodes are not labelled
tephra.dev/lab=true.

`

func main() { os.Exit(run()) }

func run() int {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	var (
		attacks   = fs.String("attacks", "attacks", "directory of scenarios")
		out       = fs.String("out", "docs", "directory for coverage.md and coverage.json")
		kctx      = fs.String("context", "", "kubectl context; empty uses the current one")
		namespace = fs.String("namespace", "tephra", "namespace Tephra is installed in")
		release   = fs.String("release", "tephra", "Helm release name")
		all       = fs.Bool("all", false, "run every scenario")
		keep      = fs.Bool("keep", false, "leave the scenario namespaces in place")
		record    = fs.String("record", "", "directory to save the event behind each detection in, as <rule>.live.jsonl (rules/testdata)")
		duration  = fs.Duration("duration", 30*time.Minute, "length of the false-positive run")
		enforce   = fs.String("enforce", "", "run under enforcement: dry-run or on")
		evasions  = fs.Bool("evasions", false, "run the evasion scenarios under evasions/ and write evasion.md and evasion.json")
	)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage); fs.PrintDefaults() }
	_ = fs.Parse(os.Args[2:])

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if *evasions {
		if *enforce != "" {
			return fail(fmt.Errorf("--evasions and --enforce cannot be combined"))
		}
		if *attacks == "attacks" {
			*attacks = "evasions"
		}
	}
	scenarios, err := harness.LoadAll(*attacks)
	if err != nil {
		return fail(err)
	}
	cluster := &harness.Cluster{Context: *kctx, Namespace: *namespace, Release: *release}
	runner := &harness.Runner{Cluster: cluster, Log: os.Stderr, Keep: *keep, Enforce: *enforce}
	var enforceMode uint64
	switch *enforce {
	case "":
	case harness.EnforceDryRun:
		enforceMode = 1
	case harness.EnforceOn:
		enforceMode = 2
	default:
		return fail(fmt.Errorf("--enforce %q is not dry-run or on", *enforce))
	}

	switch os.Args[1] {
	case "list":
		for _, s := range scenarios {
			fmt.Printf("%s  %-70s %s\n", s.ID, s.Title, strings.Join(s.Expect, ", "))
		}
		return 0
	case "run":
		if !*all {
			if fs.NArg() == 0 {
				fs.Usage()
				return 2
			}
			if scenarios, err = harness.Select(scenarios, fs.Args()); err != nil {
				return fail(err)
			}
		}
		if *enforce != "" {
			var blockable []*harness.Scenario
			for _, s := range scenarios {
				switch {
				case s.Enforce != nil:
					blockable = append(blockable, s)
				case !*all:
					return fail(fmt.Errorf("scenario %s has no enforce section", s.ID))
				}
			}
			scenarios = blockable
		}
	case "fp":
	default:
		fmt.Fprint(os.Stderr, usage)
		return 2
	}

	// Nothing below runs against a cluster that is not a lab.
	kernel, err := cluster.RequireLab(ctx)
	if err != nil {
		return fail(err)
	}
	if err := cluster.Connect(ctx); err != nil {
		return fail(err)
	}
	defer cluster.Close()
	if enforceMode != 0 {
		if err := cluster.EnforceMode(ctx, enforceMode); err != nil {
			return fail(err)
		}
	}
	report, err := harness.LoadReport(filepath.Join(*out, "coverage.json"))
	if err != nil {
		return fail(err)
	}
	sensor := cluster.SensorVersion(ctx)
	today := time.Now().UTC().Format("2006-01-02")

	if os.Args[1] == "fp" {
		res, err := runner.FalsePositives(ctx, filepath.Join(*attacks, "fp", "workloads.yaml"), *duration)
		if res == nil {
			return fail(err)
		}
		res.Date, res.Sensor, res.Kernel = today, sensor, kernel
		if *enforce == "" {
			report.FalsePositives = res
			if werr := report.Write(*out); werr != nil {
				return fail(werr)
			}
		} else if werr := writeJSON(filepath.Join(*out, "fp-enforce-"+*enforce+".json"), res); werr != nil {
			return fail(werr)
		}
		for _, a := range res.Alerts {
			fmt.Printf("%-5s %-8s %-22s %5d  %s\n", a.Rule, a.Level, a.Namespace, a.Count, a.Example)
		}
		fmt.Printf("false-positive run: %d minutes, %d high or critical alerts, %d drops\n", res.Minutes, res.Serious(), res.Drops)
		if *enforce != "" {
			fmt.Printf("enforcement %s: %d actions refused\n", *enforce, res.Denied)
		}
		if err != nil || res.Serious() > 0 || res.Denied > 0 {
			if err != nil {
				fmt.Fprintln(os.Stderr, "harness:", err)
			}
			return 1
		}
		return 0
	}

	var results []*harness.Result
	failed := 0
	for _, s := range scenarios {
		fmt.Fprintf(os.Stderr, "%s %s\n", s.ID, s.Title)
		res := runner.Run(ctx, s)
		results = append(results, res)
		line := fmt.Sprintf("%s  %-9s", res.ID, res.Verdict())
		for _, rr := range res.Rules {
			line += fmt.Sprintf(" %s=%s", rr.Rule, rr.Verdict)
			if rr.Why != "" {
				line += " (" + rr.Why + ")"
			}
		}
		if len(res.AlsoFired) > 0 {
			line += "  also: " + strings.Join(res.AlsoFired, ",")
		}
		if res.TookEffect != nil {
			if *res.TookEffect {
				line += "  took effect"
			} else {
				line += "  refused"
			}
		}
		if res.Error != "" {
			line += "  error: " + res.Error
		}
		if res.Predicted != "" {
			line += fmt.Sprintf("  predicted %s, measured %s", res.Predicted, res.Measured())
		}
		if res.Drops > 0 || res.AgentRestarts > 0 {
			line += fmt.Sprintf("  drops %d, agent restarts %d", res.Drops, res.AgentRestarts)
		}
		fmt.Println(line)
		if res.Verdict() != harness.Detected {
			failed++
		}
		if *record != "" {
			if err := saveEvents(*record, res); err != nil {
				return fail(err)
			}
		}
		if ctx.Err() != nil {
			break
		}
	}
	if *evasions {
		er := &harness.EvasionReport{Date: today, Sensor: sensor, Kernel: kernel, Results: results}
		if err := er.Write(*out); err != nil {
			return fail(err)
		}
		corrected := 0
		for _, r := range results {
			if !r.PredictionHeld() {
				corrected++
			}
		}
		fmt.Printf("%d evasion scenarios, %d predictions corrected; report in %s/evasion.md\n", len(results), corrected, *out)
		// Evasions find limits; a miss is a result, not a failure.
		return 0
	}
	if *enforce != "" {
		path := filepath.Join(*out, "enforcement-"+*enforce+".json")
		if err := writeJSON(path, map[string]any{"date": today, "sensor": sensor, "kernel": kernel, "mode": *enforce, "results": results}); err != nil {
			return fail(err)
		}
		fmt.Printf("%d scenarios under enforcement %s, %d not as expected; results in %s\n", len(results), *enforce, failed, path)
		if failed > 0 {
			return 1
		}
		return 0
	}
	report.Date, report.Sensor, report.Kernel = today, sensor, kernel
	report.Merge(results)
	if err := report.Write(*out); err != nil {
		return fail(err)
	}
	fmt.Printf("%d scenarios, %d not detected; report in %s/coverage.md\n", len(results), failed, *out)
	if failed > 0 {
		return 1
	}
	return 0
}

// saveEvents writes the event behind each detection as the rule's live
// test event: the alert without its rule, with the fields that differ from
// run to run left as they are.
func saveEvents(dir string, res *harness.Result) error {
	for _, rr := range res.Rules {
		if rr.Verdict != harness.Detected || rr.Event == "" {
			continue
		}
		var rec map[string]json.RawMessage
		if err := json.Unmarshal([]byte(rr.Event), &rec); err != nil {
			return err
		}
		delete(rec, "rule")
		line, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		path := filepath.Join(dir, rr.Rule+".live.jsonl")
		if err := os.WriteFile(path, append(line, '\n'), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "harness:", err)
	return 1
}
