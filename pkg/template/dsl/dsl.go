// Package dsl implements a hand-rolled evaluator for the small subset of
// Nuclei's DSL expression language this project supports: comparisons
// (==, !=, <, >) against status_code/len(body), contains()/regex() function
// calls, the status_code/body/header built-in variables, combined with
// &&/||, unary "!" negation, and parenthesized grouping. Anything outside
// this grammar is a parse/eval error, not a silent false/empty result — see
// docs/10-implementation-plan-ph1b.md Step 2's "DSL matcher/extractor scope"
// note for why this stays deliberately small rather than growing toward a
// general expression language.
package dsl

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Context supplies the values a DSL expression can reference.
type Context struct {
	StatusCode int
	Body       string
	Header     string // raw "Name: value\n"-per-line dump, matching Nuclei's own "header" DSL variable — see matcher.Part("header", r)
}

// Eval parses and evaluates expr against ctx. A bare comparison or an
// &&/||-combined expression always yields a bool; a bare function call or
// literal (e.g. "len(body)" alone, used by an extractor) yields whatever
// that call/literal produces (int or string).
func Eval(expr string, ctx Context) (any, error) {
	toks, err := tokenize(expr)
	if err != nil {
		return nil, fmt.Errorf("dsl: %w", err)
	}
	p := &parser{tokens: toks, ctx: ctx}
	val, err := p.parseOr()
	if err != nil {
		return nil, fmt.Errorf("dsl: %w", err)
	}
	if !p.atEnd() {
		return nil, fmt.Errorf("dsl: unexpected token %q after expression", p.peek().text)
	}
	return val, nil
}

// --- tokenizer ---

type tokenKind int

const (
	tokIdent tokenKind = iota
	tokNumber
	tokString
	tokAnd
	tokOr
	tokEq
	tokNeq
	tokLt
	tokGt
	tokBang
	tokLParen
	tokRParen
	tokComma
	tokEOF
)

type token struct {
	kind tokenKind
	text string
}

func tokenize(expr string) ([]token, error) {
	var toks []token
	r := []rune(expr)
	i := 0
	for i < len(r) {
		c := r[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(':
			toks = append(toks, token{tokLParen, "("})
			i++
		case c == ')':
			toks = append(toks, token{tokRParen, ")"})
			i++
		case c == ',':
			toks = append(toks, token{tokComma, ","})
			i++
		case c == '&' && i+1 < len(r) && r[i+1] == '&':
			toks = append(toks, token{tokAnd, "&&"})
			i += 2
		case c == '|' && i+1 < len(r) && r[i+1] == '|':
			toks = append(toks, token{tokOr, "||"})
			i += 2
		case c == '=' && i+1 < len(r) && r[i+1] == '=':
			toks = append(toks, token{tokEq, "=="})
			i += 2
		case c == '!' && i+1 < len(r) && r[i+1] == '=':
			toks = append(toks, token{tokNeq, "!="})
			i += 2
		case c == '!':
			toks = append(toks, token{tokBang, "!"})
			i++
		case c == '<':
			toks = append(toks, token{tokLt, "<"})
			i++
		case c == '>':
			toks = append(toks, token{tokGt, ">"})
			i++
		case c == '"' || c == '\'':
			quote := c
			j := i + 1
			for j < len(r) && r[j] != quote {
				j++
			}
			if j >= len(r) {
				return nil, fmt.Errorf("unterminated string literal starting at %d", i)
			}
			toks = append(toks, token{tokString, string(r[i+1 : j])})
			i = j + 1
		case c >= '0' && c <= '9':
			j := i
			for j < len(r) && r[j] >= '0' && r[j] <= '9' {
				j++
			}
			toks = append(toks, token{tokNumber, string(r[i:j])})
			i = j
		case isIdentStart(c):
			j := i
			for j < len(r) && isIdentPart(r[j]) {
				j++
			}
			toks = append(toks, token{tokIdent, string(r[i:j])})
			i = j
		default:
			return nil, fmt.Errorf("unexpected character %q at %d", c, i)
		}
	}
	toks = append(toks, token{tokEOF, ""})
	return toks, nil
}

func isIdentStart(c rune) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentPart(c rune) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}

// --- parser / evaluator ---

type parser struct {
	tokens []token
	pos    int
	ctx    Context
}

func (p *parser) peek() token   { return p.tokens[p.pos] }
func (p *parser) atEnd() bool   { return p.peek().kind == tokEOF }
func (p *parser) next() token   { t := p.tokens[p.pos]; p.pos++; return t }

func (p *parser) expect(k tokenKind) (token, error) {
	if p.peek().kind != k {
		return token{}, fmt.Errorf("unexpected token %q", p.peek().text)
	}
	return p.next(), nil
}

// parseOr handles a || b || c ..., left-associative. If there's no '||' at
// all, it just returns the single parseAnd result unchanged (not coerced to
// bool) — this is what lets a bare "len(body)" evaluate to an int.
func (p *parser) parseOr() (any, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.peek().kind == tokOr {
		p.next()
		lb, err := toBool(left)
		if err != nil {
			return nil, err
		}
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		rb, err := toBool(right)
		if err != nil {
			return nil, err
		}
		left = lb || rb
	}
	return left, nil
}

func (p *parser) parseAnd() (any, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.peek().kind == tokAnd {
		p.next()
		lb, err := toBool(left)
		if err != nil {
			return nil, err
		}
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		rb, err := toBool(right)
		if err != nil {
			return nil, err
		}
		left = lb && rb
	}
	return left, nil
}

// parseUnary handles a leading "!" (logical NOT), e.g. "!regex(...)" or
// "!(a && b)" — binds tighter than &&/||, same as most C-family languages,
// so "!a && b" is "(!a) && b", not "!(a && b)". A confirmed real-world need:
// upstream's own http-missing-security-headers.yaml (one of the most-used
// templates in nuclei-templates) uses exactly this shape.
func (p *parser) parseUnary() (any, error) {
	if p.peek().kind == tokBang {
		p.next()
		val, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		b, err := toBool(val)
		if err != nil {
			return nil, err
		}
		return !b, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (any, error) {
	if p.peek().kind == tokLParen {
		p.next()
		val, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(tokRParen); err != nil {
			return nil, err
		}
		return val, nil
	}
	return p.parseComparison()
}

// parseComparison handles a bare operand, or operand OP operand.
func (p *parser) parseComparison() (any, error) {
	left, err := p.parseOperand()
	if err != nil {
		return nil, err
	}
	switch p.peek().kind {
	case tokEq, tokNeq, tokLt, tokGt:
		opTok := p.next()
		right, err := p.parseOperand()
		if err != nil {
			return nil, err
		}
		return compare(opTok, left, right)
	default:
		return left, nil
	}
}

func (p *parser) parseOperand() (any, error) {
	t := p.peek()
	switch t.kind {
	case tokNumber:
		p.next()
		n, err := strconv.Atoi(t.text)
		if err != nil {
			return nil, fmt.Errorf("invalid number %q", t.text)
		}
		return n, nil
	case tokString:
		p.next()
		return t.text, nil
	case tokIdent:
		p.next()
		if p.peek().kind == tokLParen {
			return p.parseCall(t.text)
		}
		return p.resolveIdent(t.text)
	default:
		return nil, fmt.Errorf("unexpected token %q", t.text)
	}
}

func (p *parser) parseCall(name string) (any, error) {
	if _, err := p.expect(tokLParen); err != nil {
		return nil, err
	}
	var args []any
	if p.peek().kind != tokRParen {
		for {
			arg, err := p.parseOperand()
			if err != nil {
				return nil, err
			}
			args = append(args, arg)
			if p.peek().kind != tokComma {
				break
			}
			p.next()
		}
	}
	if _, err := p.expect(tokRParen); err != nil {
		return nil, err
	}
	return callFunc(name, args)
}

func (p *parser) resolveIdent(name string) (any, error) {
	switch name {
	case "status_code":
		return p.ctx.StatusCode, nil
	case "body":
		return p.ctx.Body, nil
	case "header":
		return p.ctx.Header, nil
	default:
		return nil, fmt.Errorf("unknown identifier %q", name)
	}
}

func callFunc(name string, args []any) (any, error) {
	switch name {
	case "len":
		if len(args) != 1 {
			return nil, fmt.Errorf("len() takes exactly 1 argument, got %d", len(args))
		}
		s, ok := args[0].(string)
		if !ok {
			return nil, fmt.Errorf("len() argument must be a string")
		}
		return len(s), nil
	case "contains":
		if len(args) != 2 {
			return nil, fmt.Errorf("contains() takes exactly 2 arguments, got %d", len(args))
		}
		haystack, ok1 := args[0].(string)
		needle, ok2 := args[1].(string)
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("contains() arguments must be strings")
		}
		return strings.Contains(haystack, needle), nil
	case "regex":
		if len(args) != 2 {
			return nil, fmt.Errorf("regex() takes exactly 2 arguments, got %d", len(args))
		}
		pattern, ok1 := args[0].(string)
		subject, ok2 := args[1].(string)
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("regex() arguments must be strings")
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("regex() invalid pattern %q: %w", pattern, err)
		}
		return re.MatchString(subject), nil
	default:
		return nil, fmt.Errorf("unsupported function %q", name)
	}
}

func compare(op token, a, b any) (bool, error) {
	ai, aIsInt := a.(int)
	bi, bIsInt := b.(int)
	if aIsInt && bIsInt {
		switch op.kind {
		case tokEq:
			return ai == bi, nil
		case tokNeq:
			return ai != bi, nil
		case tokLt:
			return ai < bi, nil
		case tokGt:
			return ai > bi, nil
		}
	}
	as, aIsStr := a.(string)
	bs, bIsStr := b.(string)
	if aIsStr && bIsStr {
		switch op.kind {
		case tokEq:
			return as == bs, nil
		case tokNeq:
			return as != bs, nil
		default:
			return false, fmt.Errorf("operator %q not supported between strings", op.text)
		}
	}
	return false, fmt.Errorf("type mismatch: cannot compare %T and %T", a, b)
}

func toBool(v any) (bool, error) {
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("expected a boolean expression, got %T", v)
	}
	return b, nil
}
