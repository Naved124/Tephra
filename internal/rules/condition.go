// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"strings"
)

// expr is a parsed condition: block names combined with and, or, not.
type expr interface {
	eval(blocks map[string]bool) bool
}

type (
	blockRef string
	notExpr  struct{ x expr }
	andExpr  struct{ xs []expr }
	orExpr   struct{ xs []expr }
)

func (b blockRef) eval(m map[string]bool) bool { return m[string(b)] }
func (n notExpr) eval(m map[string]bool) bool  { return !n.x.eval(m) }

func (a andExpr) eval(m map[string]bool) bool {
	for _, x := range a.xs {
		if !x.eval(m) {
			return false
		}
	}
	return true
}

func (o orExpr) eval(m map[string]bool) bool {
	for _, x := range o.xs {
		if x.eval(m) {
			return true
		}
	}
	return false
}

type condParser struct {
	toks []string
	pos  int
}

// parseCondition parses "selection and not (filter or other)". Precedence,
// tightest first: not, and, or.
func parseCondition(s string) (expr, error) {
	p := &condParser{toks: tokenize(s)}
	if len(p.toks) == 0 {
		return nil, fmt.Errorf("condition is empty")
	}
	e, err := p.or()
	if err != nil {
		return nil, err
	}
	if p.pos < len(p.toks) {
		return nil, fmt.Errorf("condition: unexpected %q", p.toks[p.pos])
	}
	return e, nil
}

func tokenize(s string) []string {
	s = strings.NewReplacer("(", " ( ", ")", " ) ").Replace(s)
	return strings.Fields(s)
}

func (p *condParser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *condParser) or() (expr, error) {
	x, err := p.and()
	if err != nil {
		return nil, err
	}
	xs := []expr{x}
	for p.peek() == "or" {
		p.pos++
		if x, err = p.and(); err != nil {
			return nil, err
		}
		xs = append(xs, x)
	}
	if len(xs) == 1 {
		return xs[0], nil
	}
	return orExpr{xs}, nil
}

func (p *condParser) and() (expr, error) {
	x, err := p.not()
	if err != nil {
		return nil, err
	}
	xs := []expr{x}
	for p.peek() == "and" {
		p.pos++
		if x, err = p.not(); err != nil {
			return nil, err
		}
		xs = append(xs, x)
	}
	if len(xs) == 1 {
		return xs[0], nil
	}
	return andExpr{xs}, nil
}

func (p *condParser) not() (expr, error) {
	switch tok := p.peek(); tok {
	case "":
		return nil, fmt.Errorf("condition ends where a block name is expected")
	case "not":
		p.pos++
		x, err := p.not()
		if err != nil {
			return nil, err
		}
		return notExpr{x}, nil
	case "(":
		p.pos++
		x, err := p.or()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, fmt.Errorf("condition: missing )")
		}
		p.pos++
		return x, nil
	case ")", "and", "or":
		return nil, fmt.Errorf("condition: unexpected %q", tok)
	default:
		p.pos++
		return blockRef(tok), nil
	}
}

// refs lists the block names an expression uses.
func refs(e expr, into map[string]bool) {
	switch e := e.(type) {
	case blockRef:
		into[string(e)] = true
	case notExpr:
		refs(e.x, into)
	case andExpr:
		for _, x := range e.xs {
			refs(x, into)
		}
	case orExpr:
		for _, x := range e.xs {
			refs(x, into)
		}
	}
}
