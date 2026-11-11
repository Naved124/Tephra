// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/Naved124/tephra/internal/export"
	"github.com/Naved124/tephra/internal/rules"
)

const rulesUsage = `usage:
  tephrad rules validate <rule file or directory>...
  tephrad rules test <rule file or directory> <events.jsonl>

validate loads the rules and reports the first problem with its file and
line. test runs the rules over recorded events, one JSON event per line
("-" for stdin), and prints each alert as the agent would.
`

// rulesCmd runs "tephrad rules ..." and returns the exit code.
func rulesCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) < 2 {
		_, _ = fmt.Fprint(stderr, rulesUsage)
		return 2
	}
	switch args[0] {
	case "validate":
		for _, path := range args[1:] {
			set, err := rules.LoadPath(path)
			if err != nil {
				_, _ = fmt.Fprintln(stderr, err)
				return 1
			}
			_, _ = fmt.Fprintf(stdout, "%s: %d rules valid\n", path, len(set.Rules))
		}
		return 0
	case "test":
		if len(args) != 3 {
			_, _ = fmt.Fprint(stderr, rulesUsage)
			return 2
		}
		return rulesTest(args[1], args[2], stdout, stderr)
	}
	_, _ = fmt.Fprint(stderr, rulesUsage)
	return 2
}

func rulesTest(rulePath, eventsPath string, stdout, stderr io.Writer) int {
	set, err := rules.LoadPath(rulePath)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	in := io.Reader(os.Stdin)
	if eventsPath != "-" {
		f, err := os.Open(eventsPath)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 1
		}
		defer func() { _ = f.Close() }()
		in = f
	}

	out := export.NewJSONLines(stdout)
	sc := bufio.NewScanner(in)
	sc.Buffer(nil, 1<<20)
	var line, nEvents, nAlerts int
	for sc.Scan() {
		line++
		var rec export.Record
		// Lines that are not events (the agent's own log shares the
		// stream in kubectl logs) are skipped.
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil || rec.Type == "" {
			continue
		}
		// An alert in the input is the event that caused it; test the
		// event.
		rec.Rule = nil
		nEvents++
		for _, r := range set.Match(&rec) {
			nAlerts++
			if err := out.Write(r.Alert(&rec)); err != nil {
				_, _ = fmt.Fprintln(stderr, err)
				return 1
			}
		}
	}
	if err := sc.Err(); err != nil {
		_, _ = fmt.Fprintf(stderr, "%s:%d: %v\n", eventsPath, line+1, err)
		return 1
	}
	if err := out.Flush(); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	_, _ = fmt.Fprintf(stderr, "%d rules, %d events, %d alerts\n", len(set.Rules), nEvents, nAlerts)
	return 0
}
