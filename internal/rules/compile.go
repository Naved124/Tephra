// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"strings"

	"github.com/Naved124/tephra/internal/filter"
)

// compileWatches derives the kernel file watches of a rule on file_open,
// file_change or file_denied.
//
// A file event is emitted only when a watch matches, so a rule that could be
// satisfied by an event no watch covers would silently never fire.
// Such a rule is rejected. A block is covered when it constrains file.path
// in a way the kernel can filter on:
//
//	file.path: /etc/shadow                    exact path, and by inode
//	file.path|startswith: /etc/cron.d/        path prefix
//	file.path|endswith: /authorized_keys      file name, in any directory
//
// The whole condition is covered when every way of satisfying it goes
// through a covered block.
func (r *Rule) compileWatches() error {
	if r.Event != "file_open" && r.Event != "file_change" && r.Event != "file_denied" {
		return nil
	}
	byName := map[string]*block{}
	for i := range r.blocks {
		byName[r.blocks[i].name] = &r.blocks[i]
	}
	ws, ok, err := cover(r.cond, byName)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("the condition can be met by a file event that no kernel watch covers; " +
			"every alternative needs file.path with equals, startswith, or endswith \"/<file name>\"")
	}
	// If nothing but writes can satisfy the rule, reads are dropped in
	// the kernel.
	bits := filter.Read | filter.Write
	switch {
	case r.Event == "file_change":
		// Every such operation changes the name.
		bits = filter.Write
	case r.Event == "file_denied":
		// Successful opens of the file are of no use to this rule.
		bits = filter.Denied
	case needsWrite(r.cond, byName):
		bits = filter.Write
	}
	for i := range ws {
		ws[i].Bits = bits
	}
	r.watches = ws
	return nil
}

// cover returns the watches that catch every record the expression can
// match, or false if there is no such finite set.
func cover(e expr, blocks map[string]*block) ([]filter.Watch, bool, error) {
	switch e := e.(type) {
	case blockRef:
		return blockWatches(blocks[string(e)])
	case notExpr:
		return nil, false, nil
	case andExpr:
		// All parts must hold, so the watches of any one covered part
		// are enough.
		for _, x := range e.xs {
			ws, ok, err := cover(x, blocks)
			if err != nil {
				return nil, false, err
			}
			if ok {
				return ws, true, nil
			}
		}
		return nil, false, nil
	case orExpr:
		var all []filter.Watch
		for _, x := range e.xs {
			ws, ok, err := cover(x, blocks)
			if err != nil || !ok {
				return nil, false, err
			}
			all = append(all, ws...)
		}
		return all, true, nil
	}
	return nil, false, nil
}

func blockWatches(b *block) ([]filter.Watch, bool, error) {
	for _, t := range b.tests {
		if t.field != "file.path" {
			continue
		}
		var ws []filter.Watch
		for _, v := range t.strs {
			w, ok, err := pathWatch(t.modifier, v)
			if err != nil {
				return nil, false, err
			}
			if !ok {
				ws = nil
				break
			}
			ws = append(ws, w)
		}
		if ws != nil {
			return ws, true, nil
		}
	}
	return nil, false, nil
}

func pathWatch(modifier, v string) (filter.Watch, bool, error) {
	switch modifier {
	case "equals", "in":
		if !strings.HasPrefix(v, "/") {
			return filter.Watch{}, false, fmt.Errorf("file.path %q is not an absolute path", v)
		}
		return filter.Watch{Kind: filter.Exact, Path: v}, true, nil
	case "startswith":
		if !strings.HasPrefix(v, "/") {
			return filter.Watch{}, false, fmt.Errorf("file.path|startswith %q is not an absolute path", v)
		}
		if v == "/" {
			return filter.Watch{}, false, fmt.Errorf("file.path|startswith \"/\" would report every file open on the node")
		}
		return filter.Watch{Kind: filter.Prefix, Path: v}, true, nil
	case "endswith":
		// Only a whole last component can be matched by name.
		name, ok := strings.CutPrefix(v, "/")
		if !ok || name == "" || strings.Contains(name, "/") || len(name) > filter.MaxNameLen {
			return filter.Watch{}, false, nil
		}
		return filter.Watch{Kind: filter.Name, Path: name}, true, nil
	}
	return filter.Watch{}, false, nil
}

// needsWrite reports whether only an open for writing can satisfy the
// expression.
func needsWrite(e expr, blocks map[string]*block) bool {
	switch e := e.(type) {
	case blockRef:
		for _, t := range blocks[string(e)].tests {
			// A test "file.write: true" or "file.truncate: true";
			// a truncating open counts as a write.
			if (t.field == "file.write" || t.field == "file.truncate") && t.modifier == "equals" && t.wantTrue {
				return true
			}
		}
		return false
	case andExpr:
		for _, x := range e.xs {
			if needsWrite(x, blocks) {
				return true
			}
		}
		return false
	case orExpr:
		for _, x := range e.xs {
			if !needsWrite(x, blocks) {
				return false
			}
		}
		return true
	}
	return false
}
