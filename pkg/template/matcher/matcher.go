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
	// content_type/response built-ins. A raw:-request block with more than
	// one Raw entry binds body_N/header_N/content_type_N (string) and
	// status_code_N/duration_N (int) for N = 1..len(Raw), so a real
	// template's shared correlating matcher (e.g. upstream's
	// open-proxy-internal.yaml: contains(body_1, ...) || contains(body_2,
	// ...) ...) can actually reference each fired probe's own result — see
	// nuclei.Executor's tryRaw. Every Response (raw: or plain path:-based)
	// also carries a bare ExtraInts["duration"] — elapsed seconds of the
	// request actually evaluated (the last raw entry, or the single path:
	// request) — since "duration" has no dedicated Context field the way
	// status_code/body/header/content_type do; see nuclei.Executor's tryPath
	// and pkg/template/nuclei/loader.go's rawIndexedDSLContext doc comment.
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
	// its own, even when it evaluates true. Allowed only inside a template
	// that has `flow:` set (see nuclei/loader.go's validate) — outside one,
	// still rejected at load time, since there's nothing for it to gate.
	// Found live against upstream's apache-server-status-localhost.yaml,
	// whose internal matcher checks for a 403 (i.e. "correctly blocked") as
	// its flow gate: before flow: support existed, this project ran it as
	// an ordinary matcher and reported a false "disclosure" finding on its
	// own true evaluation — see nuclei.Executor.hasReportableMatcher, which
	// exists specifically so an all-internal block can never do that again.
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
	case "interactsh_protocol", "interactsh_request", "interactsh_response":
		// Deliberately never falls through to the body, unlike the default
		// case below — these three are always resolved from r.ExtraVars
		// even when the key is entirely absent (a bare/hand-built Response
		// that never went through nuclei.Executor's awaitOOB, e.g.), zero
		// value "" and all. See ValidPart's doc comment for the exact
		// live false-positive class this guards: "does the interactsh
		// callback log contain 'http'" must never become "does the page
		// body contain 'http'" just because no callback was ever recorded.
		return r.ExtraVars[part]
	default:
		// An indexed body_N/header_N/content_type_N name (IsIndexedPart)
		// resolves straight out of r.ExtraVars -- a request block that fires
		// more than one probe (raw:'s multiple Raw entries, or a
		// path:-multi-request block flagged for correlation, see
		// nuclei.Executor's tryRawIteration/tryPathCorrelatedIteration) binds
		// exactly these keys there, string-formatted the same way the bare
		// "header"/"content_type" cases above are. Any other unrecognized
		// part (already rejected at load time by ValidPartWithContext, so
		// this is a defensive fallback only) falls through to the body, same
		// as before this case existed.
		if v, ok := r.ExtraVars[part]; ok {
			return v
		}
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
// "response" — "" defaults to "body" — plus the three OAST/out-of-band
// values "interactsh_protocol", "interactsh_request", "interactsh_response"
// used by blind-SSRF-style checks like upstream's linkerd-ssrf-detect.yaml,
// now backed by real Interactsh-protocol infrastructure — see
// nuclei.Executor's prepareOOB/awaitOOB). Found the hard way, before that
// infrastructure existed: an unrecognized Part used to silently fall
// through to matching against the body in Part(), so a template checking
// "does the interactsh callback log contain 'http'" was actually checking
// "does the page body contain the substring 'http'" — true for nearly any
// HTML page, a live false positive against a real target. The three
// interactsh_ names are safe to always accept here (unlike an indexed
// body_N — see ValidPartWithContext) because nuclei.Executor's awaitOOB
// unconditionally populates all three in r.ExtraVars for every request,
// real callback or not (real values, or "" on no callback/no probe/OOB not
// configured) — Part()'s ExtraVars lookup below never falls through to the
// body for them.
func ValidPart(part string) bool {
	switch part {
	case "", "body", "header", "all", "content_type", "response",
		"interactsh_protocol", "interactsh_request", "interactsh_response":
		return true
	default:
		return false
	}
}

// indexedPartPattern matches a body_N/header_N/content_type_N part: value —
// the per-probe indexed form real templates use to name one specific fired
// request's own result within a request block that fires more than one
// (real examples: CVE-2014-4592.yaml's `part: body_2` word matcher,
// zimbra-lfi.yaml's `part: header_1`). Deliberately excludes status_code_N/
// duration_N — those are int-typed (dsl.Context.IntVars, see
// nuclei/loader.go's indexedDSLContext), never a "part" a word/regex matcher
// selects text out of.
var indexedPartPattern = regexp.MustCompile(`^(?:body|header|content_type)_[0-9]+$`)

// IsIndexedPart reports whether part is a body_N/header_N/content_type_N
// name (see indexedPartPattern). Exported so pkg/template/nuclei's loader
// can use the exact same definition to decide whether a path:-multi-request
// template's matchers/extractors need the raw:-style "fire every entry,
// then bind, then match once" correlation model instead of this project's
// default independent per-path try-until-match loop — see
// nuclei.Executor.runPathRequest.
func IsIndexedPart(part string) bool {
	return indexedPartPattern.MatchString(part)
}

// ValidPartWithContext is ValidPart, but also accepts an indexed
// body_N/header_N/content_type_N name (IsIndexedPart) when ctx.Vars actually
// carries that exact key — i.e. N is within range of however many probes
// THIS request fires (raw:'s Raw entries, or a path:-multi-request block's
// Path entries once flagged for correlation). Reuses the same dummy-Vars
// population nuclei/loader.go's indexedDSLContext already builds for DSL
// identifier validation, so a word/regex matcher's `part: body_2` and a
// `dsl: contains(body_2, ...)` matcher on the same request are validated by
// the exact same "does N exist for this request" check — one request
// referencing body_5 with only 2 probes is rejected either way.
func ValidPartWithContext(part string, ctx dsl.Context) bool {
	if ValidPart(part) {
		return true
	}
	if !IsIndexedPart(part) || ctx.Vars == nil {
		return false
	}
	_, ok := ctx.Vars[part]
	return ok
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
	if !ValidPartWithContext(m.Part, ctx) {
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
