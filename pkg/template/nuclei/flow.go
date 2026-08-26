package nuclei

import (
	"fmt"
	"strconv"
	"strings"
)

// flowExpr is a parsed flow: script — this project's minimal subset of real
// Nuclei's small JS control-flow layer, covering only boolean composition of
// http(N) calls (&&, ||, parens). See parseFlow's doc comment for the exact
// grammar and docs/10-implementation-plan-ph1b.md's flow: note for the real
// corpus measurement (36 of 38 sampled flow: templates match this grammar;
// the other 2 use javascript() and stay rejected).
type flowExpr interface {
	// eval walks the expression, calling call(n) for every http(n) node it
	// reaches, short-circuiting && and || exactly like Go/JS boolean
	// operators — a call not reached (because an earlier && was false or an
	// earlier || was true) never fires its request. call's own error return
	// is for ctx cancellation only (see nuclei.Executor.runFlow); a request
	// that merely fails to match is reported through call's bool, not an
	// error.
	eval(call func(n int) (bool, error)) (bool, error)
}

type flowCall struct{ n int }

func (f flowCall) eval(call func(n int) (bool, error)) (bool, error) {
	return call(f.n)
}

type flowAnd struct{ left, right flowExpr }

func (f flowAnd) eval(call func(n int) (bool, error)) (bool, error) {
	l, err := f.left.eval(call)
	if err != nil || !l {
		return false, err
	}
	return f.right.eval(call)
}

type flowOr struct{ left, right flowExpr }

func (f flowOr) eval(call func(n int) (bool, error)) (bool, error) {
	l, err := f.left.eval(call)
	if err != nil || l {
		return l, err
	}
	return f.right.eval(call)
}

// parseFlow parses a flow: script against the grammar:
//
//	expr    := orTerm ( "||" orTerm )*
//	orTerm  := andTerm ( "&&" andTerm )*
//	andTerm := "http" "(" NUMBER ")" | "(" expr ")"
//
// standard precedence (&& binds tighter than ||), matching every real
// sampled template even though the corpus only needed explicit parens for
// its one mixed case. Anything outside this grammar (javascript(), loops,
// variable assignment, unbalanced parens, trailing garbage) is a parse
// error — flow: templates using those stay rejected at load time, same
// "fail loudly" pattern as code:/headless: and multi-key payloads:.
//
// maxN is the highest N seen across every http(N) call, so loader.go can
// reject a template referencing an http: index it doesn't actually have.
func parseFlow(expr string) (root flowExpr, maxN int, err error) {
	toks, err := tokenizeFlow(expr)
	if err != nil {
		return nil, 0, err
	}
	p := &flowParser{toks: toks}
	root, err = p.parseExpr()
	if err != nil {
		return nil, 0, err
	}
	if p.pos != len(p.toks) {
		return nil, 0, fmt.Errorf("unexpected trailing input at %q", p.toks[p.pos])
	}
	return root, p.maxN, nil
}

type flowParser struct {
	toks []string
	pos  int
	maxN int
}

func (p *flowParser) peek() string {
	if p.pos >= len(p.toks) {
		return ""
	}
	return p.toks[p.pos]
}

func (p *flowParser) next() string {
	t := p.peek()
	p.pos++
	return t
}

func (p *flowParser) parseExpr() (flowExpr, error) {
	left, err := p.parseAndTerm()
	if err != nil {
		return nil, err
	}
	for p.peek() == "||" {
		p.next()
		right, err := p.parseAndTerm()
		if err != nil {
			return nil, err
		}
		left = flowOr{left: left, right: right}
	}
	return left, nil
}

func (p *flowParser) parseAndTerm() (flowExpr, error) {
	left, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	for p.peek() == "&&" {
		p.next()
		right, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		left = flowAnd{left: left, right: right}
	}
	return left, nil
}

func (p *flowParser) parsePrimary() (flowExpr, error) {
	switch t := p.peek(); t {
	case "(":
		p.next()
		inner, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, fmt.Errorf("expected ')', got %q", p.peek())
		}
		p.next()
		return inner, nil
	case "http":
		p.next()
		if p.peek() != "(" {
			return nil, fmt.Errorf("expected '(' after 'http', got %q", p.peek())
		}
		p.next()
		numTok := p.next()
		n, err := strconv.Atoi(numTok)
		if err != nil || n < 1 {
			return nil, fmt.Errorf("expected a positive request index in http(N), got %q", numTok)
		}
		if p.peek() != ")" {
			return nil, fmt.Errorf("expected ')', got %q", p.peek())
		}
		p.next()
		if n > p.maxN {
			p.maxN = n
		}
		return flowCall{n: n}, nil
	default:
		return nil, fmt.Errorf("expected 'http(' or '(', got %q", t)
	}
}

// tokenizeFlow splits a flow: script into "http", "(", ")", "&&", "||", and
// digit-run tokens, skipping whitespace. Any other character (letters other
// than "http", "=", ";", etc.) is a lex error — that's what rejects
// javascript()/loop/assignment scripts at the tokenizer stage rather than
// letting them silently parse as garbage.
func tokenizeFlow(expr string) ([]string, error) {
	var toks []string
	i := 0
	for i < len(expr) {
		c := expr[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(' || c == ')':
			toks = append(toks, string(c))
			i++
		case strings.HasPrefix(expr[i:], "&&"):
			toks = append(toks, "&&")
			i += 2
		case strings.HasPrefix(expr[i:], "||"):
			toks = append(toks, "||")
			i += 2
		case c >= '0' && c <= '9':
			j := i
			for j < len(expr) && expr[j] >= '0' && expr[j] <= '9' {
				j++
			}
			toks = append(toks, expr[i:j])
			i = j
		case c >= 'a' && c <= 'z':
			j := i
			for j < len(expr) && expr[j] >= 'a' && expr[j] <= 'z' {
				j++
			}
			word := expr[i:j]
			if word != "http" {
				return nil, fmt.Errorf("unsupported flow: construct %q — only http(N) calls composed with && / || / () are supported, see docs/10-implementation-plan-ph1b.md", word)
			}
			toks = append(toks, word)
			i = j
		default:
			return nil, fmt.Errorf("unexpected character %q in flow: script", c)
		}
	}
	return toks, nil
}
