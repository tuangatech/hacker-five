// Package matcher evaluates Nuclei-style matchers against an HTTP response.
// Shared by both template formats (the Nuclei-compatible parser and
// HackerFive's native format, see docs/10-implementation-plan-ph1b.md Steps
// 2-3) so match evaluation is implemented once.
package matcher

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/template/dsl"
)

// Response is the minimal view a Matcher needs — decoupled from net/http so
// both template formats, and any future non-HTTP protocol (see
// docs/follow-up.md §4), can supply it.
type Response struct {
	StatusCode int
	Headers    http.Header
	Body       []byte

	// ExtraVars/ExtraInts supply additional named values a dsl: matcher or
	// extractor can reference beyond the status_code/body/header/
	// content_type/response built-ins — used by a raw:-request block with
	// more than one Raw entry to bind body_N/header_N (string) and
	// status_code_N (int) for N = 1..len(Raw), so a real template's shared
	// correlating matcher (e.g. upstream's open-proxy-internal.yaml:
	// contains(body_1, ...) || contains(body_2, ...) ...) can actually
	// reference each fired probe's own result — see nuclei.Executor's
	// tryRaw. Nil for every non-raw Response (the existing path:-based
	// flow), so this is a zero-behavior-change addition there.
	ExtraVars map[string]string
	ExtraInts map[string]int
}

// Matcher checks one condition against a Response. Type selects which
// fields are relevant: "status" (Status), "word"/"regex" (Words/Regex, plus
// Part), "size" (Size), or "dsl" (DSL, evaluated via pkg/template/dsl). No
// "binary": not used by any template sampled across the curated
// exposed-panels/misconfiguration/technologies categories — add later if
// that changes, same "add when needed" discipline as this project's
// regexp2/json-iterator carve-outs.
type Matcher struct {
	Type      string   `yaml:"type"`
	Name      string   `yaml:"name,omitempty"` // optional label for this specific check, e.g. "strict-transport-security" — surfaced in Finding evidence via MatchingNames so a matchers-condition: or template's Finding says which sub-check actually fired, not just "something matched"
	Status    []int    `yaml:"status,omitempty"`
	Words     []string `yaml:"words,omitempty"`
	Regex     []string `yaml:"regex,omitempty"`
	Size      []int    `yaml:"size,omitempty"`
	DSL       []string `yaml:"dsl,omitempty"`
	Part      string   `yaml:"part,omitempty"`      // "body" | "header" | "all" | "content_type" | "response"; default "body"
	Condition string   `yaml:"condition,omitempty"` // "and" | "or", within this matcher's own Words/Regex/DSL list; default "or"
	Negative  bool     `yaml:"negative,omitempty"`

	// Internal marks a matcher as flow-control-only: in real Nuclei, an
	// internal matcher gates whether a later request in a multi-request
	// `flow:` template runs at all, and never produces standalone output on
	// its own. This project's executor doesn't implement `flow:`'s
	// conditional request sequencing (see Template.Flow), so a template
	// using Internal is rejected at load time — evaluating it as an
	// ordinary matcher is actively wrong, not just incomplete: found live
	// against upstream's apache-server-status-localhost.yaml, whose
	// internal matcher checks for a 403 (i.e. "correctly blocked") as its
	// flow gate, which our engine reported as a false "disclosure" finding
	// when DVWA's real 403 respose "matched" it in isolation.
	Internal bool `yaml:"internal,omitempty"`
}

// MatchersCondition combines multiple Matchers within one request: "and"
// requires every matcher to match, "or" requires at least one.
type MatchersCondition string

const (
	And MatchersCondition = "and"
	Or  MatchersCondition = "or"
)

// Part returns the slice of r that a matcher/extractor's Part field selects.
// Shared between Matcher.Evaluate and pkg/template/extractor, which has the
// same "body"/"header"/"all" selection to make.
func Part(part string, r Response) string {
	switch part {
	case "header":
		var b strings.Builder
		for k, vs := range r.Headers {
			for _, v := range vs {
				b.WriteString(k)
				b.WriteString(": ")
				b.WriteString(v)
				b.WriteString("\n")
			}
		}
		return b.String()
	case "content_type":
		return r.Headers.Get("Content-Type")
	case "all", "response":
		// "response" is real Nuclei's full raw HTTP response (status line +
		// headers + body). Every real "response"-part matcher sampled across
		// the synced corpus (all 32, checked at implementation time) only
		// word/regex-matches against header/body content, never the literal
		// status line — so aliasing it to the existing "all" behavior is
		// safe and avoids synthesizing a fake status line this project has
		// no real use for yet.
		return Part("header", r) + string(r.Body)
	default:
		return string(r.Body)
	}
}

// Evaluate reports whether m matches r, honoring m.Negative. A malformed
// Regex/DSL entry is treated as non-matching rather than propagating an
// error — real templates are expected to have already passed Validate at
// load time, so this is a defensive fallback, not the primary error path.
func (m Matcher) Evaluate(r Response) bool {
	result := m.evaluate(r)
	if m.Negative {
		return !result
	}
	return result
}

func (m Matcher) evaluate(r Response) bool {
	switch m.Type {
	case "status":
		for _, s := range m.Status {
			if s == r.StatusCode {
				return true
			}
		}
		return false
	case "word":
		return m.evaluateList(m.Words, func(w string) bool {
			return strings.Contains(Part(m.Part, r), w)
		})
	case "regex":
		return m.evaluateList(m.Regex, func(pattern string) bool {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return false
			}
			return re.MatchString(Part(m.Part, r))
		})
	case "size":
		size := len(r.Body)
		for _, s := range m.Size {
			if s == size {
				return true
			}
		}
		return false
	case "dsl":
		return m.evaluateList(m.DSL, func(expr string) bool {
			val, err := dsl.Eval(expr, dsl.Context{StatusCode: r.StatusCode, Body: string(r.Body), Header: Part("header", r), ContentType: r.Headers.Get("Content-Type"), Vars: r.ExtraVars, IntVars: r.ExtraInts})
			if err != nil {
				return false
			}
			b, ok := val.(bool)
			return ok && b
		})
	default:
		return false
	}
}

// evaluateList applies check to every entry, combining via m.Condition
// ("or" by default, matching Nuclei's own default).
func (m Matcher) evaluateList(entries []string, check func(string) bool) bool {
	and := strings.EqualFold(m.Condition, "and")
	matchedAny := false
	for _, entry := range entries {
		if check(entry) {
			matchedAny = true
			if !and {
				return true
			}
		} else if and {
			return false
		}
	}
	if and {
		return len(entries) > 0
	}
	return matchedAny
}

// EvaluateAll combines every matcher in matchers via cond ("and" requires
// all, "or" requires at least one). An empty matchers slice is NOT a match
// — this used to trivially return true ("nothing disqualifies it"), which
// turned out to be a real false-positive generator: many real upstream
// templates (fingerprinting/discovery ones especially — herokuapp-detect.yaml,
// vmware-horizon-version.yaml) carry only Extractors, no Matchers, meaning
// "I looked for this pattern, and here's what I found if anything" rather
// than "this target is X." Confirmed against real Nuclei's own behavior
// (pkg/protocols/protocols.go: an extractor-only result has Matched=false
// and is skipped from output unless a real matcher fires) — so extractor
// presence must never substitute for an actual match.
func EvaluateAll(matchers []Matcher, cond MatchersCondition, r Response) bool {
	if len(matchers) == 0 {
		return false
	}
	and := cond == And
	for _, m := range matchers {
		ok := m.Evaluate(r)
		if ok && !and {
			return true
		}
		if !ok && and {
			return false
		}
	}
	return and
}

// MatchingNames returns the Name of every matcher in matchers that
// individually evaluates true against r, regardless of the overall
// matchers-condition. A matchers-condition: or template (e.g. upstream's
// http-missing-security-headers.yaml, which ORs together 11 separately
// named checks) only needs one matcher true to produce a Finding at all —
// without this, that Finding can only say "something matched," not which
// specific check did. Matchers with no Name are skipped, not reported as "".
func MatchingNames(matchers []Matcher, r Response) []string {
	var names []string
	for _, m := range matchers {
		if m.Name != "" && m.Evaluate(r) {
			names = append(names, m.Name)
		}
	}
	return names
}

// ValidPart reports whether part is one of the response slices this project
// actually implements ("", "body", "header", "all", "content_type",
// "response" — "" defaults to "body"). Real templates also use
// protocol-specific parts this project
// doesn't have the underlying protocol support for, most notably the OAST/
// out-of-band values ("interactsh_protocol", "interactsh_request",
// "interactsh_response") used by blind-SSRF-style checks like upstream's
// linkerd-ssrf-detect.yaml — this project has no interactsh/OOB callback
// infrastructure. Found the hard way: an unrecognized Part used to silently
// fall through to matching against the body in Part(), so a template
// checking "does the interactsh callback log contain 'http'" was actually
// checking "does the page body contain the substring 'http'" — true for
// nearly any HTML page, a live false positive against a real target.
func ValidPart(part string) bool {
	switch part {
	case "", "body", "header", "all", "content_type", "response":
		return true
	default:
		return false
	}
}

// Validate reports whether m is well-formed — its Type is recognized, its
// Part is one this project implements, every Regex pattern compiles, and
// every DSL expression parses — without evaluating it against a real
// response. Used by the nuclei loader to reject a malformed or
// unsupported-protocol template at load time rather than mis-evaluating it
// mid-scan.
func Validate(m Matcher) error {
	return ValidateWithContext(m, dsl.Context{})
}

// ValidateWithContext is Validate, but checks a dsl: matcher's expressions
// against a caller-supplied dsl.Context instead of an empty one — needed
// for a raw:-request block with more than one Raw entry, whose matchers
// legitimately reference indexed identifiers (body_1, status_code_2, ...)
// that only exist once execution actually binds them (see nuclei.Executor's
// tryRaw); validating against an empty Context would reject those as
// "unknown identifier" even though they're valid. The nuclei loader builds
// a dummy Context (zero-valued entries for every N = 1..len(Raw)) purely so
// these identifiers resolve during validation — the values themselves are
// never used for anything but confirming the expression parses/type-checks.
func ValidateWithContext(m Matcher, ctx dsl.Context) error {
	if !ValidPart(m.Part) {
		return fmt.Errorf("matcher: unsupported part %q (likely an out-of-band/OAST check — not supported)", m.Part)
	}
	switch m.Type {
	case "status", "word", "size":
		return nil
	case "regex":
		for _, p := range m.Regex {
			if _, err := regexp.Compile(p); err != nil {
				return fmt.Errorf("matcher: invalid regex %q: %w", p, err)
			}
		}
		return nil
	case "dsl":
		for _, expr := range m.DSL {
			if _, err := dsl.Eval(expr, ctx); err != nil {
				return fmt.Errorf("matcher: invalid dsl expression %q: %w", expr, err)
			}
		}
		return nil
	default:
		return fmt.Errorf("matcher: unsupported type %q", m.Type)
	}
}
