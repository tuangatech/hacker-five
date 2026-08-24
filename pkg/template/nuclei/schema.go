// Package nuclei parses and executes a defined subset of the upstream
// Nuclei template schema — see docs/10-implementation-plan-ph1b.md Step 2
// for the exact scope, what's deliberately rejected, and why.
package nuclei

import (
	"github.com/tuangatech/hacker-five/pkg/template/extractor"
	"github.com/tuangatech/hacker-five/pkg/template/matcher"
)

// Template is the top-level parsed shape of one Nuclei-compatible template
// file, restricted to the http: protocol.
type Template struct {
	ID   string        `yaml:"id"`
	Info Info          `yaml:"info"`
	HTTP []HTTPRequest `yaml:"http"`

	// Flow is a presence-only sentinel, not implemented: real Nuclei's
	// `flow:` field is small JS controlling conditional/looped execution
	// across a template's multiple HTTP requests (e.g. "only run request 2
	// if request 1's matcher fired"). This project's executor runs every
	// HTTP entry unconditionally and independently, which is actively wrong
	// for a flow template, not just incomplete — see loader.go's rejection
	// and matcher.Matcher.Internal's doc comment for the real example that
	// found this (a false "disclosure" finding from a flow-control gate
	// matcher evaluated as if it were a standalone check).
	Flow string `yaml:"flow,omitempty"`
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

	// Raw/Payloads are presence-only sentinels, not implemented: a template
	// using either is rejected at load time (see loader.go's validate) —
	// see docs/10-implementation-plan-ph1b.md Step 2's "Unsupported request
	// styles" note for why (a small fuzzing engine, not a matcher-subset
	// extension).
	Raw      []string       `yaml:"raw,omitempty"`
	Payloads map[string]any `yaml:"payloads,omitempty"`
}
