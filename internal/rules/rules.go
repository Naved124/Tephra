// SPDX-License-Identifier: Apache-2.0

// Package rules loads detection rules from YAML, validates them, and
// compiles them into two things: the filters the kernel programs apply, and
// a matcher that runs on enriched events.
package rules

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/Naved124/tephra/internal/events"
	"github.com/Naved124/tephra/internal/export"
	"github.com/Naved124/tephra/internal/filter"
)

// Error is a problem in a rule file, with its position.
type Error struct {
	File string
	Line int
	Msg  string
}

func (e *Error) Error() string { return fmt.Sprintf("%s:%d: %s", e.File, e.Line, e.Msg) }

// Rule is one loaded detection rule.
type Rule struct {
	ID             string
	Title          string
	Level          string
	Tags           []string
	Event          string
	Action         string
	Description    string
	FalsePositives []string
	// File and Line say where the rule was read from.
	File string
	Line int

	blocks  []block
	cond    expr
	watches []filter.Watch
}

type block struct {
	name  string
	line  int
	tests []test
}

// test is one "field|modifier: value" line of a block.
type test struct {
	field    string
	modifier string
	// strs holds the values when they are strings, for the compiler.
	strs []string
	// wantTrue is set on a boolean test for true.
	wantTrue bool
	match    func(*export.Record) bool
}

var (
	levels = map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}
	// The event types a rule can subscribe to. A Unix socket connect is a
	// connect with network.family "unix".
	ruleEvents = map[string][]events.Type{
		"exec":        {events.TypeExec},
		"fork":        {events.TypeFork},
		"exit":        {events.TypeExit},
		"connect":     {events.TypeConnect, events.TypeUnixConnect},
		"accept":      {events.TypeAccept},
		"file_open":   {events.TypeFileOpen},
		"file_change": {events.TypeFileChange},
		"file_denied": {events.TypeFileDenied},
		"ptrace":      {events.TypePtrace},
		"memfd":       {events.TypeMemfd},
		"module_load": {events.TypeModuleLoad},
		"bpf_load":    {events.TypeBPFLoad},
		"cred_change": {events.TypeCredChange},
		"mount":       {events.TypeMount},
		"setns":       {events.TypeSetns},
	}
	idRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*$`)
	// attack.<tactic>, or attack.t1234 with an optional .001 sub-technique.
	tagRE     = regexp.MustCompile(`^attack\.(t\d{4}(\.\d{3})?|[a-z][a-z_]*)$`)
	modifiers = map[string]bool{
		"equals": true, "startswith": true, "endswith": true, "contains": true,
		"in": true, "cidr": true, "re": true, "gt": true, "lt": true,
	}
)

// Parse reads the rules in one YAML file. Several rules may be separated by
// "---".
func Parse(file string, data []byte) ([]*Rule, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var out []*Rule
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, yamlError(file, err)
		}
		if len(doc.Content) == 0 {
			continue
		}
		r, err := parseRule(file, doc.Content[0])
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil, &Error{file, 1, "no rule in file"}
	}
	return out, nil
}

var yamlLineRE = regexp.MustCompile(`line (\d+)`)

// yamlError keeps the line number the YAML parser reports.
func yamlError(file string, err error) error {
	line := 1
	if m := yamlLineRE.FindStringSubmatch(err.Error()); m != nil {
		_, _ = fmt.Sscan(m[1], &line)
	}
	return &Error{file, line, "invalid YAML: " + strings.TrimPrefix(err.Error(), "yaml: ")}
}

func parseRule(file string, n *yaml.Node) (*Rule, error) {
	fail := func(at *yaml.Node, format string, args ...any) error {
		return &Error{file, at.Line, fmt.Sprintf(format, args...)}
	}
	if n.Kind != yaml.MappingNode {
		return nil, fail(n, "a rule must be a mapping")
	}
	r := &Rule{File: file, Line: n.Line, Action: "alert"}
	var detection *yaml.Node
	seen := map[string]bool{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if seen[k.Value] {
			return nil, fail(k, "duplicate key %q", k.Value)
		}
		seen[k.Value] = true
		var err error
		switch k.Value {
		case "id":
			r.ID, err = scalarString(v)
		case "title":
			r.Title, err = scalarString(v)
		case "level":
			r.Level, err = scalarString(v)
		case "event":
			r.Event, err = scalarString(v)
		case "action":
			r.Action, err = scalarString(v)
		case "description":
			r.Description, err = scalarString(v)
		case "tags":
			r.Tags, err = stringList(v)
		case "falsepositives":
			r.FalsePositives, err = stringList(v)
		case "references":
			_, err = stringList(v)
		case "detection":
			detection = v
		default:
			return nil, fail(k, "unknown key %q", k.Value)
		}
		if err != nil {
			return nil, fail(v, "%s: %v", k.Value, err)
		}
	}

	switch {
	case !idRE.MatchString(r.ID):
		return nil, fail(n, "id is missing or not a plain identifier: %q", r.ID)
	case r.Title == "":
		return nil, fail(n, "rule %s: title is missing", r.ID)
	case !levels[r.Level]:
		return nil, fail(n, "rule %s: level %q is not one of info, low, medium, high, critical", r.ID, r.Level)
	case ruleEvents[r.Event] == nil:
		return nil, fail(n, "rule %s: event %q is not a known event type (exec, fork, exit, connect, accept, file_open, file_change, file_denied, ptrace, memfd, module_load, bpf_load, cred_change, mount, setns)", r.ID, r.Event)
	case r.Action == "block":
		return nil, fail(n, "rule %s: action block needs the enforcement programs, which are not part of this version", r.ID)
	case r.Action != "alert":
		return nil, fail(n, "rule %s: action %q is not alert", r.ID, r.Action)
	case detection == nil:
		return nil, fail(n, "rule %s: detection is missing", r.ID)
	}
	for _, tag := range r.Tags {
		if !tagRE.MatchString(tag) {
			return nil, fail(n, "rule %s: tag %q is not attack.<tactic> or attack.t<4 digits>[.<3 digits>]", r.ID, tag)
		}
	}

	if err := r.parseDetection(file, detection); err != nil {
		return nil, err
	}
	if err := r.compileWatches(); err != nil {
		return nil, fail(detection, "rule %s: %v", r.ID, err)
	}
	return r, nil
}

func scalarString(n *yaml.Node) (string, error) {
	if n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
		return "", fmt.Errorf("want a string")
	}
	return n.Value, nil
}

func stringList(n *yaml.Node) ([]string, error) {
	if n.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("want a list of strings")
	}
	out := make([]string, 0, len(n.Content))
	for _, c := range n.Content {
		s, err := scalarString(c)
		if err != nil {
			return nil, fmt.Errorf("want a list of strings")
		}
		out = append(out, s)
	}
	return out, nil
}

func (r *Rule) parseDetection(file string, n *yaml.Node) error {
	fail := func(at *yaml.Node, format string, args ...any) error {
		return &Error{file, at.Line, fmt.Sprintf("rule %s: ", r.ID) + fmt.Sprintf(format, args...)}
	}
	if n.Kind != yaml.MappingNode {
		return fail(n, "detection must be a mapping of block names")
	}
	var cond *yaml.Node
	names := map[string]bool{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Value == "condition" {
			cond = v
			continue
		}
		switch k.Value {
		case "and", "or", "not":
			return fail(k, "%q cannot be a block name", k.Value)
		}
		if names[k.Value] {
			return fail(k, "duplicate block %q", k.Value)
		}
		names[k.Value] = true
		if v.Kind != yaml.MappingNode || len(v.Content) == 0 {
			return fail(v, "block %q must be a non-empty mapping of fields", k.Value)
		}
		b := block{name: k.Value, line: k.Line}
		for j := 0; j+1 < len(v.Content); j += 2 {
			t, err := r.parseTest(v.Content[j].Value, v.Content[j+1])
			if err != nil {
				return fail(v.Content[j], "%v", err)
			}
			b.tests = append(b.tests, t)
		}
		r.blocks = append(r.blocks, b)
	}
	if cond == nil {
		return fail(n, "detection has no condition")
	}
	text, err := scalarString(cond)
	if err != nil {
		return fail(cond, "condition: %v", err)
	}
	if r.cond, err = parseCondition(text); err != nil {
		return fail(cond, "%v", err)
	}
	used := map[string]bool{}
	refs(r.cond, used)
	for name := range used {
		if !names[name] {
			return fail(cond, "condition names block %q, which is not defined", name)
		}
	}
	// An unused block is nearly always a typo in the condition.
	for _, b := range r.blocks {
		if !used[b.name] {
			return &Error{file, b.line, fmt.Sprintf("rule %s: block %q is not used by the condition", r.ID, b.name)}
		}
	}
	return nil
}

// parseTest compiles one "field|modifier: value" entry.
func (r *Rule) parseTest(key string, v *yaml.Node) (test, error) {
	name, mod, hasMod := strings.Cut(key, "|")
	if !hasMod {
		mod = "equals"
	}
	f, ok := lookupField(name)
	if !ok {
		return test{}, fmt.Errorf("unknown field %q", name)
	}
	if !f.on(r.Event) {
		return test{}, fmt.Errorf("field %q does not exist on %s events", name, r.Event)
	}
	if !modifiers[mod] {
		return test{}, fmt.Errorf("unknown modifier %q on %s", mod, name)
	}

	var nodes []*yaml.Node
	switch v.Kind {
	case yaml.ScalarNode:
		nodes = []*yaml.Node{v}
	case yaml.SequenceNode:
		nodes = v.Content
		if len(nodes) == 0 {
			return test{}, fmt.Errorf("%s: the list of values is empty", key)
		}
	default:
		return test{}, fmt.Errorf("%s: want a value or a list of values", key)
	}
	if mod == "in" && v.Kind != yaml.SequenceNode {
		return test{}, fmt.Errorf("%s: modifier in takes a list", key)
	}
	wrong := func() (test, error) {
		return test{}, fmt.Errorf("modifier %q does not apply to %s, which is a %s", mod, name, f.kind)
	}
	typed := func(tag string) error {
		for _, n := range nodes {
			if n.Kind != yaml.ScalarNode || n.Tag != tag {
				return fmt.Errorf("%s: value %q is not a %s", key, n.Value, f.kind)
			}
		}
		return nil
	}

	t := test{field: name, modifier: mod}
	get := f.get
	switch f.kind {
	case kBool:
		if mod != "equals" {
			return wrong()
		}
		if len(nodes) != 1 {
			return test{}, fmt.Errorf("%s: a boolean field takes one value", key)
		}
		if err := typed("!!bool"); err != nil {
			return test{}, err
		}
		var want bool
		_ = nodes[0].Decode(&want)
		t.wantTrue = want
		t.match = func(rec *export.Record) bool {
			v := get(rec)
			return v.ok && v.b == want
		}

	case kInt:
		if err := typed("!!int"); err != nil {
			return test{}, err
		}
		wants := make([]int64, len(nodes))
		for i, n := range nodes {
			if err := n.Decode(&wants[i]); err != nil {
				return test{}, fmt.Errorf("%s: %q is not an integer", key, n.Value)
			}
		}
		var cmp func(have, want int64) bool
		switch mod {
		case "equals", "in":
			cmp = func(have, want int64) bool { return have == want }
		case "gt":
			cmp = func(have, want int64) bool { return have > want }
		case "lt":
			cmp = func(have, want int64) bool { return have < want }
		default:
			return wrong()
		}
		if (mod == "gt" || mod == "lt") && len(wants) != 1 {
			return test{}, fmt.Errorf("%s: modifier %s takes one value", key, mod)
		}
		t.match = func(rec *export.Record) bool {
			v := get(rec)
			if !v.ok {
				return false
			}
			for _, w := range wants {
				if cmp(v.n, w) {
					return true
				}
			}
			return false
		}

	case kIP:
		if err := typed("!!str"); err != nil {
			return test{}, err
		}
		var prefixes []netip.Prefix
		for _, n := range nodes {
			switch mod {
			case "equals", "in":
				a, err := netip.ParseAddr(n.Value)
				if err != nil {
					return test{}, fmt.Errorf("%s: %q is not an IP address", key, n.Value)
				}
				prefixes = append(prefixes, netip.PrefixFrom(a, a.BitLen()))
			case "cidr":
				p, err := netip.ParsePrefix(n.Value)
				if err != nil {
					return test{}, fmt.Errorf("%s: %q is not a CIDR", key, n.Value)
				}
				prefixes = append(prefixes, p.Masked())
			default:
				return wrong()
			}
		}
		t.match = func(rec *export.Record) bool {
			v := get(rec)
			if !v.ok {
				return false
			}
			a, err := netip.ParseAddr(v.s)
			if err != nil {
				return false
			}
			for _, p := range prefixes {
				if p.Contains(a) {
					return true
				}
			}
			return false
		}

	case kString, kStrings:
		if err := typed("!!str"); err != nil {
			return test{}, err
		}
		for _, n := range nodes {
			t.strs = append(t.strs, n.Value)
		}
		var one func(have string) bool
		wants := t.strs
		anyOf := func(op func(have, want string) bool) func(string) bool {
			return func(have string) bool {
				for _, w := range wants {
					if op(have, w) {
						return true
					}
				}
				return false
			}
		}
		switch mod {
		case "equals", "in":
			one = anyOf(func(have, want string) bool { return have == want })
		case "startswith":
			one = anyOf(strings.HasPrefix)
		case "endswith":
			one = anyOf(strings.HasSuffix)
		case "contains":
			one = anyOf(strings.Contains)
		case "re":
			res := make([]*regexp.Regexp, len(wants))
			for i, w := range wants {
				re, err := regexp.Compile(w)
				if err != nil {
					return test{}, fmt.Errorf("%s: %w", key, err)
				}
				res[i] = re
			}
			one = func(have string) bool {
				for _, re := range res {
					if re.MatchString(have) {
						return true
					}
				}
				return false
			}
		default:
			return wrong()
		}
		if f.kind == kString {
			t.match = func(rec *export.Record) bool {
				v := get(rec)
				return v.ok && one(v.s)
			}
		} else {
			// On a list the test holds if any element passes it.
			t.match = func(rec *export.Record) bool {
				v := get(rec)
				for _, s := range v.ss {
					if one(s) {
						return true
					}
				}
				return false
			}
		}
	}
	return t, nil
}

// Matches reports whether the rule fires on a record of its event type.
func (r *Rule) Matches(rec *export.Record) bool {
	results := make(map[string]bool, len(r.blocks))
	for _, b := range r.blocks {
		ok := true
		for _, t := range b.tests {
			if !t.match(rec) {
				ok = false
				break
			}
		}
		results[b.name] = ok
	}
	return r.cond.eval(results)
}

// Alert wraps the event that matched.
func (r *Rule) Alert(rec *export.Record) *export.Record {
	a := *rec
	a.Rule = &export.Rule{ID: r.ID, Title: r.Title, Level: r.Level, Tags: r.Tags}
	return &a
}

// Set is a compiled rule set.
type Set struct {
	Rules   []*Rule
	byEvent map[string][]*Rule
}

// NewSet indexes rules by event type. Rule IDs must be unique.
func NewSet(rules []*Rule) (*Set, error) {
	s := &Set{byEvent: map[string][]*Rule{}}
	ids := map[string]*Rule{}
	for _, r := range rules {
		if prev, dup := ids[r.ID]; dup {
			return nil, &Error{r.File, r.Line, fmt.Sprintf("rule id %s is already used at %s:%d", r.ID, prev.File, prev.Line)}
		}
		ids[r.ID] = r
		s.Rules = append(s.Rules, r)
		s.byEvent[r.Event] = append(s.byEvent[r.Event], r)
	}
	return s, nil
}

// Load reads every .yaml and .yml file in a directory, in name order.
// Subdirectories are not read.
func Load(dir string) (*Set, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("rules directory: %w", err)
	}
	var all []*Rule
	for _, e := range entries {
		name := e.Name()
		// A ConfigMap mount holds "..data" and friends next to the files.
		if strings.HasPrefix(name, ".") {
			continue
		}
		if ext := filepath.Ext(name); ext != ".yaml" && ext != ".yml" {
			continue
		}
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if info.IsDir() {
			continue
		}
		rs, err := LoadFile(path)
		if err != nil {
			return nil, err
		}
		all = append(all, rs...)
	}
	return NewSet(all)
}

// LoadPath reads a directory of rules, or a single rule file.
func LoadPath(path string) (*Set, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return Load(path)
	}
	rs, err := LoadFile(path)
	if err != nil {
		return nil, err
	}
	return NewSet(rs)
}

// LoadFile reads the rules in one file.
func LoadFile(path string) ([]*Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(path, data)
}

// Match returns the rules that fire on a record.
func (s *Set) Match(rec *export.Record) []*Rule {
	var out []*Rule
	for _, r := range s.byEvent[rec.Type] {
		if r.Matches(rec) {
			out = append(out, r)
		}
	}
	return out
}

// EventTypes lists the kernel event types the rules need, sorted.
func (s *Set) EventTypes() []events.Type {
	seen := map[events.Type]bool{}
	out := []events.Type{}
	for event := range s.byEvent {
		for _, t := range ruleEvents[event] {
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Watches lists the file watches the rules need.
func (s *Set) Watches() []filter.Watch {
	var out []filter.Watch
	for _, r := range s.Rules {
		out = append(out, r.watches...)
	}
	return out
}
