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

var placeholderPattern = regexp.MustCompile(`\{\{(\w+)\}\}`)

// Render expands {{BaseURL}} and every {{name}} present in ctx.Vars within
// input. An unresolved placeholder is an error rather than being left
// verbatim — a request built from a silently-unexpanded template would be a
// broken URL, not a working one.
func Render(input string, ctx Context) (string, error) {
	var firstErr error
	result := placeholderPattern.ReplaceAllStringFunc(input, func(match string) string {
		name := placeholderPattern.FindStringSubmatch(match)[1]
		if name == "BaseURL" {
			return ctx.BaseURL
		}
		if name == "Hostname" {
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
