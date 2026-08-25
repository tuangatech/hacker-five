// Package native parses and executes HackerFive's own YAML template format —
// see docs/10-implementation-plan-ph1b.md Step 3 for scope and the design
// decisions this package resolves against doc02's older worked example.
package native

import (
	"github.com/tuangatech/hacker-five/pkg/template/extractor"
	"github.com/tuangatech/hacker-five/pkg/template/matcher"
)

// Template is the top-level parsed shape of one native template file.
type Template struct {
	ID        string            `yaml:"id"`
	Info      Info              `yaml:"info"`
	Tags      []string          `yaml:"tags"`
	Variables map[string]string `yaml:"variables,omitempty"` // global scope — visible to every request, per doc02
	Requests  []Request         `yaml:"requests"`
}

// Info carries the fields that affect a Finding, plus author/description for
// human readability — same shape as nuclei.Info's behavior-affecting subset.
type Info struct {
	Name        string `yaml:"name"`
	Author      string `yaml:"author,omitempty"`
	Severity    string `yaml:"severity,omitempty"`
	Description string `yaml:"description,omitempty"`
}

// Request is one request within a template's requests: list.
type Request struct {
	Method     string                `yaml:"method"`
	Path       string                `yaml:"path"`
	Headers    map[string]string     `yaml:"headers,omitempty"`
	Body       string                `yaml:"body,omitempty"`
	Extractors []extractor.Extractor `yaml:"extractors,omitempty"`
	Matchers   []matcher.Matcher     `yaml:"matchers,omitempty"`

	// MatchersCondition combines this request's own Matchers list. Unlike
	// the Nuclei-compatible format (Step 2), an empty value here defaults to
	// "and", not "or" — see loader.go/executor.go and
	// docs/10-implementation-plan-ph1b.md Step 3's Context #3 for why: doc02's
	// own worked example relies on AND semantics with no field to say so.
	MatchersCondition matcher.MatchersCondition `yaml:"matchers-condition,omitempty"`

	// Condition is a pkg/template/dsl expression evaluated against
	// already-bound variables (global Variables + prior requests' chain-scoped
	// extractor output) before this request fires — e.g. `auth_token != ""`.
	// Empty means always fire. A false Condition skips this request entirely,
	// same as a network error: not scan-fatal.
	Condition string `yaml:"condition,omitempty"`
}
