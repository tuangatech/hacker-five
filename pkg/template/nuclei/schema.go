// Package nuclei parses and executes a defined subset of the upstream
// Nuclei template schema — see docs/10-implementation-plan-ph1b.md Step 2
// for the exact scope, what's deliberately rejected, and why.
package nuclei

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/tuangatech/hacker-five/pkg/template/extractor"
	"github.com/tuangatech/hacker-five/pkg/template/matcher"
)

// Template is the top-level parsed shape of one Nuclei-compatible template
// file, restricted to the http: protocol.
type Template struct {
	ID   string        `yaml:"id"`
	Info Info          `yaml:"info"`
	HTTP []HTTPRequest `yaml:"http"`

	// Flow holds the raw flow: script text. Real Nuclei's flow: is small JS
	// controlling conditional/looped execution across a template's multiple
	// HTTP requests (e.g. "only run request 2 if request 1's matcher
	// fired"); this project supports only a minimal subset — boolean
	// composition of http(N) calls via &&/||/() — parsed into flowAST by
	// loader.go's validate. See matcher.Matcher.Internal's doc comment for
	// the real example (apache-server-status-localhost.yaml) that showed
	// why running a flow template's requests unconditionally/independently
	// is actively wrong, not just incomplete, and
	// docs/10-implementation-plan-ph1b.md's flow: note for the real corpus
	// measurement behind the supported grammar.
	Flow string `yaml:"flow,omitempty"`

	// flowAST is Flow parsed by loader.go's validate — nil for a non-flow
	// template. Unexported: only nuclei.Executor.runFlow reads it, and it
	// has no YAML shape of its own (populated after decode, not by it).
	flowAST flowExpr
}

// Info carries the fields that affect a Finding (Name, Severity), plus the
// informational-only fields real upstream templates commonly carry
// (Reference, Classification, Metadata, Tags) — confirmed present in every
// sampled template (angular-detect.yaml, adminer-panel.yaml, etc.). These
// are accepted so a real template's info: block doesn't fail to load just
// for having them, even though the executor doesn't act on them.
type Info struct {
	Name           string         `yaml:"name"`
	Author         string         `yaml:"author,omitempty"`
	Severity       string         `yaml:"severity,omitempty"`
	Description    string         `yaml:"description,omitempty"`
	Tags           string         `yaml:"tags,omitempty"` // comma-separated, e.g. "tech,angular,discovery"
	Reference      []string       `yaml:"reference,omitempty"`
	Classification map[string]any `yaml:"classification,omitempty"`
	Metadata       map[string]any `yaml:"metadata,omitempty"`
}

// HTTPRequest is one request block within a template's http: list.
type HTTPRequest struct {
	Method  string            `yaml:"method"`
	Path    []string          `yaml:"path"` // every entry is tried, in order — see loader.go/executor.go; NOT Path[0]-only,
	Headers map[string]string `yaml:"headers,omitempty"`
	Body    string            `yaml:"body,omitempty"`
	// StopAtFirstMatch stops trying further Path entries once one matches.
	StopAtFirstMatch  bool                      `yaml:"stop-at-first-match,omitempty"`
	MatchersCondition matcher.MatchersCondition `yaml:"matchers-condition,omitempty"`
	Matchers          []matcher.Matcher         `yaml:"matchers,omitempty"`
	Extractors        []extractor.Extractor     `yaml:"extractors,omitempty"`

	// Raw is a list of literal HTTP/1.1 request texts (method/path/headers/
	// body, {{}}-templated same as Path/Headers/Body), fired instead of the
	// Method/Path/Headers/Body fields above when non-empty. Every entry
	// fires, every time (see executor.go's tryRaw) — not a Path-style "try
	// each until one matches" list, because a request block with more than
	// one Raw entry commonly correlates results across all of them in a
	// single shared matcher (real example: upstream's open-proxy-*.yaml,
	// which fires ~24 probes and checks body_1..body_24 in one DSL
	// expression) — see docs/10-implementation-plan-ph1b.md's "raw:/
	// payloads: support" note for the real corpus measurement behind this.
	Raw []string `yaml:"raw,omitempty"`

	// Payloads maps a placeholder name (referenced as {{name}} in Raw) to
	// its list of substitution values. Real Nuclei allows either an inline
	// YAML list (supported here) or a bare string naming an external
	// wordlist file (rejected at load time — see loader.go's validate,
	// "file-based payload not supported"); kept as yaml.Node rather than
	// []string so validate() can distinguish the two shapes and reject the
	// unsupported one with a clear error instead of a decode failure.
	// Multiple keys (Nuclei's sniper/pitchfork/clusterbomb "attack modes")
	// are also rejected at load time — see Attack's doc comment.
	Payloads map[string]yaml.Node `yaml:"payloads,omitempty"`

	// Attack names Nuclei's payload "attack mode" (sniper/pitchfork/
	// clusterbomb/batteringram, default batteringram) — only meaningful
	// with more than one Payloads key, which this project doesn't support
	// (see Payloads' doc comment); kept only so a rejected multi-key
	// template's error message can name the mode it was trying to use.
	Attack string `yaml:"attack,omitempty"`
}

// resolvePayload validates and decodes req.Payloads into the single
// key/values pair this project supports (see Payloads' doc comment), or
// ("", nil, nil) when there are none. Shared by loader.go's validate (so a
// bad payload is a load-time error, not a scan-time surprise) and
// executor.go's tryRaw (so execution uses the exact values validation
// already confirmed).
func (req HTTPRequest) resolvePayload() (key string, values []string, err error) {
	if len(req.Payloads) == 0 {
		return "", nil, nil
	}
	if len(req.Payloads) > 1 {
		return "", nil, fmt.Errorf("uses %d payload keys — multi-key payloads (attack: %s and friends) unsupported in this version, see docs/10-implementation-plan-ph1b.md", len(req.Payloads), attackOrDefault(req.Attack))
	}
	for k, node := range req.Payloads {
		switch node.Kind {
		case yaml.SequenceNode:
			var vals []string
			if err := node.Decode(&vals); err != nil {
				return "", nil, fmt.Errorf("payloads.%s: %w", k, err)
			}
			return k, vals, nil
		case yaml.ScalarNode:
			return "", nil, fmt.Errorf("payloads.%s: file-based payload (%q) unsupported in this version, see docs/10-implementation-plan-ph1b.md", k, node.Value)
		default:
			return "", nil, fmt.Errorf("payloads.%s: unsupported payload shape", k)
		}
	}
	panic("unreachable") // len == 1, loop above always returns
}

func attackOrDefault(attack string) string {
	if attack == "" {
		return "batteringram (default)"
	}
	return attack
}

// hasAbsoluteRequestLine reports whether raw's first line's request target
// is an absolute URI (e.g. "GET http://192.168.0.1/ HTTP/1.1") rather than
// a path relative to whatever host the connection actually goes to. Real
// templates use this to test open-proxy/SSRF-via-proxy behavior — the
// scanned target is expected to relay the request to the named URI. This
// project has no execution path that can honor that safely: net/http's
// standard client dials whatever URL it's given, so naively sending this
// would connect the scanner directly to the (template-controlled,
// downloaded) URI's own host, never touching the actual authorized target —
// a real out-of-scope-host risk, not just an unsupported feature. Checked
// on the raw, pre-render template text (real templates author the absolute
// URI literally, not via a payload variable), so this is a load-time
// rejection like the other raw:/payloads: exclusions above.
func hasAbsoluteRequestLine(raw string) bool {
	line := raw
	if idx := strings.IndexAny(raw, "\r\n"); idx != -1 {
		line = raw[:idx]
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return false
	}
	target := fields[1]
	return strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://")
}
