// Package vars provides plain string-substitution request templating,
// independent of the (stubbed) pkg/template YAML engine — the IDOR detector
// uses it directly to turn an endpoint template plus a generated ID into a
// request URL, so IDOR doesn't have to wait on Phase 1b's template parser.
// The native YAML engine will reuse the same Render function once it exists.
package vars

import (
	"fmt"
	"regexp"
)

// Context carries the values available to Render when expanding a template string.
type Context struct {
	BaseURL  string
	Hostname string // host[:port], no scheme — matches Nuclei's own {{Hostname}}, used by raw: requests' Host: header (see nuclei.Executor's tryRaw)
	Vars     map[string]string
}

// placeholderPattern accepts a hyphen alongside \w — real Nuclei's own
// {{interactsh-url}} is the one common built-in variable name that isn't a
// plain word-character identifier; \w+ alone silently failed to match it at
// all (found via the interactsh_ OOB work, docs/follow-up.md), so instead
// of being substituted it passed straight through Render as the literal
// text "{{interactsh-url}}" in the outgoing request — no error, just a
// request that could never actually work.
var placeholderPattern = regexp.MustCompile(`\{\{([\w-]+)\}\}`)

// Render expands {{BaseURL}}/{{RootURL}}, {{Hostname}}/{{Host}}, and every
// {{name}} present in ctx.Vars within input. An unresolved placeholder is
// an error rather than being left verbatim — a request built from a
// silently-unexpanded template would be a broken URL, not a working one.
func Render(input string, ctx Context) (string, error) {
	var firstErr error
	result := placeholderPattern.ReplaceAllStringFunc(input, func(match string) string {
		name := placeholderPattern.FindStringSubmatch(match)[1]
		switch name {
		case "BaseURL", "RootURL":
			// RootURL is treated as an alias of BaseURL. Real Nuclei's
			// RootURL is scheme://host with no path, distinct from BaseURL
			// when the target itself carries a path — this project's
			// targets are conventionally bare origins (--target), so the
			// two coincide in the common case; a target submitted with its
			// own path is the one case this simplification doesn't
			// capture, not worth a URL-parsing pass just for that.
			return ctx.BaseURL
		case "Hostname", "Host":
			return ctx.Hostname
		}
		if v, ok := ctx.Vars[name]; ok {
			return v
		}
		if firstErr == nil {
			firstErr = fmt.Errorf("rendering template: undefined variable %q", name)
		}
		return match
	})
	if firstErr != nil {
		return "", firstErr
	}
	return result, nil
}
