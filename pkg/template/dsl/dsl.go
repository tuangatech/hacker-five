// Package dsl implements a hand-rolled evaluator for the small subset of
// Nuclei's DSL expression language this project supports: comparisons
// (==, !=, <, >) against status_code/len(body), function calls
// (contains/contains_any/contains_all/regex/to_lower/tolower/trim/md5/sha1/
// base64_py/mmh3/compare_versions/base64_decode/concat), the status_code/body/header/content_type/response
// built-in variables, combined with &&/||, unary "!" negation, and
// parenthesized grouping. Anything
// outside this grammar is a parse/eval error, not a silent false/empty
// result — see docs/10-implementation-plan-ph1b.md Step 2's "DSL
// matcher/extractor scope" note for why this stays deliberately small
// rather than growing toward a general expression language; the function
// set above is grown deliberately too, one real observed template need at a
// time (see "Post-v0.1.0 DSL/part expansion" in doc10), not speculatively.
package dsl

import (
	"crypto/md5"  //nolint:gosec // fingerprint matching against known template hashes, not a security use of MD5
	"crypto/sha1" //nolint:gosec // same as above
	"encoding/base64"
	"fmt"
	"math/bits"
	"regexp"
	"strconv"
	"strings"
)

// Context supplies the values a DSL expression can reference.
type Context struct {
	StatusCode  int
	Body        string
	Header      string            // raw "Name: value\n"-per-line dump, matching Nuclei's own "header" DSL variable — see matcher.Part("header", r)
	ContentType string            // the response's Content-Type header value alone, matching Nuclei's own "content_type" DSL identifier — see matcher.Part("content_type", r); distinct from part: content_type, real upstream templates use both forms (e.g. redoc-api-docs.yaml uses the identifier form: contains(content_type, "text/html"))
	Vars        map[string]string // bound template variables (native format's condition: field, e.g. "auth_token != \"\"") — checked after the built-ins below, so a bound var can't shadow status_code/body/header/content_type
	IntVars     map[string]int    // same idea as Vars, but int-typed — needed for e.g. a raw:-multi-request template's status_code_2 (see matcher.Response.ExtraInts), since compare() only compares matching types and a real template does "status_code_1 != 404", not a string comparison
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
	tokLe
	tokGt
	tokGe
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
		case c == '<' && i+1 < len(r) && r[i+1] == '=':
			toks = append(toks, token{tokLe, "<="})
			i += 2
		case c == '>' && i+1 < len(r) && r[i+1] == '=':
			toks = append(toks, token{tokGe, ">="})
			i += 2
		case c == '<':
			toks = append(toks, token{tokLt, "<"})
			i++
		case c == '>':
			toks = append(toks, token{tokGt, ">"})
			i++
		case c == '"' || c == '\'':
			quote := c
			var sb strings.Builder
			j := i + 1
			closed := false
			for j < len(r) {
				if r[j] == '\\' && j+1 < len(r) && (r[j+1] == quote || r[j+1] == '\\') {
					sb.WriteRune(r[j+1])
					j += 2
					continue
				}
				if r[j] == quote {
					closed = true
					break
				}
				sb.WriteRune(r[j])
				j++
			}
			if !closed {
				return nil, fmt.Errorf("unterminated string literal starting at %d", i)
			}
			toks = append(toks, token{tokString, sb.String()})
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
	case tokEq, tokNeq, tokLt, tokLe, tokGt, tokGe:
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
	case "content_type":
		return p.ctx.ContentType, nil
	case "response":
		// Same header+body alias as matcher.Part's "response" case, and the
		// same reasoning: real usage (e.g. upstream's
		// jetty-directory-listing.yaml: contains_all(response, "Jetty",
		// "jetty-dir.css")) only word-matches header/body content, never the
		// literal HTTP status line.
		return p.ctx.Header + p.ctx.Body, nil
	default:
		if v, ok := p.ctx.Vars[name]; ok {
			return v, nil
		}
		if v, ok := p.ctx.IntVars[name]; ok {
			return v, nil
		}
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
	case "contains_any":
		return containsMulti(name, args, false)
	case "contains_all":
		return containsMulti(name, args, true)
	case "to_lower", "tolower":
		s, err := oneStringArg(name, args)
		if err != nil {
			return nil, err
		}
		return strings.ToLower(s), nil
	case "trim":
		if len(args) != 2 {
			return nil, fmt.Errorf("trim() takes exactly 2 arguments, got %d", len(args))
		}
		s, ok1 := args[0].(string)
		cutset, ok2 := args[1].(string)
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("trim() arguments must be strings")
		}
		return strings.Trim(s, cutset), nil
	case "md5":
		s, err := oneStringArg(name, args)
		if err != nil {
			return nil, err
		}
		sum := md5.Sum([]byte(s)) //nolint:gosec // fingerprint matching, not a security use of MD5
		return fmt.Sprintf("%x", sum), nil
	case "sha1":
		s, err := oneStringArg(name, args)
		if err != nil {
			return nil, err
		}
		sum := sha1.Sum([]byte(s)) //nolint:gosec // fingerprint matching, not a security use of SHA1
		return fmt.Sprintf("%x", sum), nil
	case "base64_py":
		s, err := oneStringArg(name, args)
		if err != nil {
			return nil, err
		}
		return base64Py(s), nil
	case "mmh3":
		s, err := oneStringArg(name, args)
		if err != nil {
			return nil, err
		}
		return strconv.FormatInt(int64(int32(mmh3Sum32(s))), 10), nil
	case "compare_versions":
		return compareVersions(args)
	case "concat":
		if len(args) == 0 {
			return nil, fmt.Errorf("concat() takes at least 1 argument, got 0")
		}
		var sb strings.Builder
		for _, a := range args {
			switch v := a.(type) {
			case string:
				sb.WriteString(v)
			case int:
				sb.WriteString(strconv.Itoa(v))
			default:
				return nil, fmt.Errorf("concat() argument must be a string or int, got %T", a)
			}
		}
		return sb.String(), nil
	case "base64_decode":
		s, err := oneStringArg(name, args)
		if err != nil {
			return nil, err
		}
		decoded, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("base64_decode(): %w", err)
		}
		return string(decoded), nil
	default:
		return nil, fmt.Errorf("unsupported function %q", name)
	}
}

// oneStringArg validates that fn was called with exactly one string argument
// — the shape shared by to_lower/tolower, md5, sha1, base64_py, and mmh3.
func oneStringArg(fn string, args []any) (string, error) {
	if len(args) != 1 {
		return "", fmt.Errorf("%s() takes exactly 1 argument, got %d", fn, len(args))
	}
	s, ok := args[0].(string)
	if !ok {
		return "", fmt.Errorf("%s() argument must be a string", fn)
	}
	return s, nil
}

// containsMulti implements contains_any (all==false: true if any needle
// matches) and contains_all (all==true: true only if every needle matches).
func containsMulti(fn string, args []any, all bool) (bool, error) {
	if len(args) < 2 {
		return false, fmt.Errorf("%s() takes at least 2 arguments, got %d", fn, len(args))
	}
	haystack, ok := args[0].(string)
	if !ok {
		return false, fmt.Errorf("%s() arguments must be strings", fn)
	}
	for _, a := range args[1:] {
		needle, ok := a.(string)
		if !ok {
			return false, fmt.Errorf("%s() arguments must be strings", fn)
		}
		matched := strings.Contains(haystack, needle)
		if matched && !all {
			return true, nil
		}
		if !matched && all {
			return false, nil
		}
	}
	return all, nil
}

// base64Py reproduces Python's base64.encodebytes (the function real
// Nuclei's base64_py DSL function matches): standard base64, but with a
// newline inserted every 76 encoded characters and a trailing newline —
// unlike Go's base64.StdEncoding, which emits one unbroken line. Templates
// pair this with mmh3() for Shodan/ZoomEye-style favicon-hash fingerprinting
// (e.g. real upstream's appwrite-panel.yaml), so the exact line-wrapping
// matters: it changes the hashed bytes, not just cosmetic formatting.
// Cross-checked against a real Python 3.12 base64.encodebytes+mmh3.hash run
// (empty string, a short string, and a >76-char string forcing multiple
// wrapped lines) — all three matched this implementation's output exactly,
// not just verified against documentation.
func base64Py(s string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(s))
	var sb strings.Builder
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		sb.WriteString(encoded[i:end])
		sb.WriteByte('\n')
	}
	return sb.String()
}

// mmh3 constants and mmh3Sum32 are a direct, hand-ported implementation of
// MurmurHash3's 32-bit x86 variant (seed 0) — verified against the
// canonical reference vectors published in spaolacci/murmur3's own test
// suite (e.g. Sum32WithSeed([]byte("hello"), 0) == 0x248bfa47), not
// reimplemented from memory. Ported rather than added as a go.mod
// dependency: this project avoids new third-party dependencies for a
// self-contained security tool where every dependency is extra supply-chain
// surface, and the algorithm itself is small, fixed, and easily verified.
const (
	mmh3C1 uint32 = 0xcc9e2d51
	mmh3C2 uint32 = 0x1b873593
)

func mmh3Sum32(s string) uint32 {
	data := []byte(s)
	var h1 uint32
	nblocks := len(data) / 4
	for i := 0; i < nblocks; i++ {
		k1 := uint32(data[i*4]) | uint32(data[i*4+1])<<8 | uint32(data[i*4+2])<<16 | uint32(data[i*4+3])<<24
		k1 *= mmh3C1
		k1 = bits.RotateLeft32(k1, 15)
		k1 *= mmh3C2
		h1 ^= k1
		h1 = bits.RotateLeft32(h1, 13)
		h1 = h1*4 + h1 + 0xe6546b64
	}

	tail := data[nblocks*4:]
	var k1 uint32
	switch len(tail) & 3 {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= mmh3C1
		k1 = bits.RotateLeft32(k1, 15)
		k1 *= mmh3C2
		h1 ^= k1
	}

	h1 ^= uint32(len(data))
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16
	return h1
}

// compareVersions implements Nuclei's compare_versions(version, constraint,
// ...) — real corpus usage (grep across .nuclei-templates-cache/http) is
// always a dot-separated numeric version against one or more constraints
// like "<=2.2.34" or ">= 12.0.0", ANDed together when there's more than
// one (e.g. upstream's ">= 12.0.0", "< 14.0.0" range check). No dependency
// added for this — a hand-rolled numeric-segment comparator, same
// precedent as the existing hand-ported MurmurHash3, since every sampled
// real constraint is plain dot-separated integers (no semver pre-release
// suffixes observed).
func compareVersions(args []any) (bool, error) {
	if len(args) < 2 {
		return false, fmt.Errorf("compare_versions() takes at least 2 arguments, got %d", len(args))
	}
	version, ok := args[0].(string)
	if !ok {
		return false, fmt.Errorf("compare_versions() arguments must be strings")
	}
	for _, a := range args[1:] {
		constraint, ok := a.(string)
		if !ok {
			return false, fmt.Errorf("compare_versions() arguments must be strings")
		}
		ok, err := satisfiesConstraint(version, constraint)
		if err != nil {
			return false, fmt.Errorf("compare_versions(): %w", err)
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

// versionConstraintOps is checked longest-prefix-first so "<=" doesn't get
// mistaken for a "<" followed by a stray "=".
var versionConstraintOps = []string{"<=", ">=", "==", "!=", "<", ">", "="}

func satisfiesConstraint(version, constraint string) (bool, error) {
	constraint = strings.TrimSpace(constraint)
	op := "=="
	for _, candidate := range versionConstraintOps {
		if strings.HasPrefix(constraint, candidate) {
			op = candidate
			constraint = constraint[len(candidate):]
			break
		}
	}
	constraint = strings.TrimSpace(constraint)
	if op == "=" {
		op = "=="
	}

	cmp, err := compareVersionSegments(version, constraint)
	if err != nil {
		return false, err
	}
	switch op {
	case "<":
		return cmp < 0, nil
	case "<=":
		return cmp <= 0, nil
	case ">":
		return cmp > 0, nil
	case ">=":
		return cmp >= 0, nil
	case "==":
		return cmp == 0, nil
	case "!=":
		return cmp != 0, nil
	default:
		return false, fmt.Errorf("unsupported constraint operator %q", op)
	}
}

// compareVersionSegments compares two dot-separated numeric version strings
// segment by segment, treating a missing trailing segment as 0 (so "2.2"
// vs "2.2.34" compares as "2.2.0" vs "2.2.34"). Returns -1/0/1 like
// strings.Compare.
func compareVersionSegments(a, b string) (int, error) {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		var av, bv int
		var err error
		if i < len(as) {
			if av, err = strconv.Atoi(strings.TrimSpace(as[i])); err != nil {
				return 0, fmt.Errorf("invalid version segment %q in %q", as[i], a)
			}
		}
		if i < len(bs) {
			if bv, err = strconv.Atoi(strings.TrimSpace(bs[i])); err != nil {
				return 0, fmt.Errorf("invalid version segment %q in %q", bs[i], b)
			}
		}
		if av != bv {
			if av < bv {
				return -1, nil
			}
			return 1, nil
		}
	}
	return 0, nil
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
		case tokLe:
			return ai <= bi, nil
		case tokGt:
			return ai > bi, nil
		case tokGe:
			return ai >= bi, nil
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
