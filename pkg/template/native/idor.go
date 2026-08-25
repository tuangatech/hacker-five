package native

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/scanner/vars"
)

// idorRangePattern matches the {{RangeInt(min|max)}} marker doc02/Step 3 use
// to mark an idor-tagged template's enumerated-ID placeholder — distinct from
// vars.Render's plain {{name}} syntax, which can't parse function-call-shaped
// placeholders (parens/"|" aren't word characters, so vars.Render silently
// leaves this marker untouched rather than erroring on it).
var idorRangePattern = regexp.MustCompile(`\{\{RangeInt\((\d+)\|(\d+)\)\}\}`)

// idorSentinel stands in for the RangeInt marker while vars.Render resolves
// every other {{name}} in the path — vars.Render treats any unresolved
// {{name}} as a hard error, and it has no "id" binding at this point (id is
// per-candidate, filled in later by idor.Detector itself). NUL bytes can't
// appear in a YAML-sourced path string, so this can never collide with real
// template content.
const idorSentinel = "\x00HACKERFIVE_ID\x00"

// isIDORTagged reports whether tmpl.Tags contains exactly "idor".
func isIDORTagged(tmpl *Template) bool {
	for _, t := range tmpl.Tags {
		if t == "idor" {
			return true
		}
	}
	return false
}

// parseIDORRequest extracts req.Path's {{RangeInt(min|max)}} marker and
// resolves every other {{name}} in the path against tmpl.Variables and target
// (as {{BaseURL}}) — producing the exact "{{id}}"-templated endpoint string
// idor.Detector.Run already expects (see pkg/detectors/idor/detector.go's
// renderEndpoint). Requires exactly one marker; see
// docs/10-implementation-plan-ph1b.md Step 3's Context #2 for why an
// idor-tagged template is constrained to this single, well-defined shape
// rather than supporting arbitrary chaining/matchers.
func parseIDORRequest(target string, tmpl *Template, req Request) (min, max int, endpointTemplate string, err error) {
	matches := idorRangePattern.FindAllStringSubmatch(req.Path, -1)
	if len(matches) == 0 {
		return 0, 0, "", fmt.Errorf("no {{RangeInt(min|max)}} marker found in path %q", req.Path)
	}
	if len(matches) > 1 {
		return 0, 0, "", fmt.Errorf("path %q has %d {{RangeInt(...)}} markers, expected exactly 1", req.Path, len(matches))
	}

	min, errMin := strconv.Atoi(matches[0][1])
	max, errMax := strconv.Atoi(matches[0][2])
	if errMin != nil || errMax != nil {
		return 0, 0, "", fmt.Errorf("invalid RangeInt bounds in path %q", req.Path)
	}
	if max < min {
		return 0, 0, "", fmt.Errorf("RangeInt(%d|%d) in path %q: max must be >= min", min, max, req.Path)
	}

	withSentinel := idorRangePattern.ReplaceAllLiteralString(req.Path, idorSentinel)
	rendered, err := vars.Render(withSentinel, vars.Context{BaseURL: target, Vars: tmpl.Variables})
	if err != nil {
		return 0, 0, "", fmt.Errorf("rendering path %q: %w", req.Path, err)
	}
	endpointTemplate = strings.ReplaceAll(rendered, idorSentinel, "{{id}}")
	return min, max, endpointTemplate, nil
}
