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
	)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage); fs.PrintDefaults() }
	_ = fs.Parse(os.Args[2:])

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	scenarios, err := harness.LoadAll(*attacks)
	if err != nil {
		return fail(err)
	}
	cluster := &harness.Cluster{Context: *kctx, Namespace: *namespace, Release: *release}
	runner := &harness.Runner{Cluster: cluster, Log: os.Stderr, Keep: *keep}

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
		report.FalsePositives = res
		if werr := report.Write(*out); werr != nil {
			return fail(werr)
		}
		for _, a := range res.Alerts {
			fmt.Printf("%-5s %-8s %-22s %5d  %s\n", a.Rule, a.Level, a.Namespace, a.Count, a.Example)
		}
		fmt.Printf("false-positive run: %d minutes, %d high or critical alerts, %d drops\n", res.Minutes, res.Serious(), res.Drops)
		if err != nil || res.Serious() > 0 {
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
		if res.Error != "" {
			line += "  error: " + res.Error
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

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "harness:", err)
	return 1
}
