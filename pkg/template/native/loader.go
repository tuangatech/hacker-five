package native

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/tuangatech/hacker-five/pkg/template/dsl"
	"github.com/tuangatech/hacker-five/pkg/template/extractor"
	"github.com/tuangatech/hacker-five/pkg/template/matcher"
)

// LoadDir parses every .yaml/.yml file under dir, recursively. One bad file
// doesn't stop the rest from loading — same per-file error isolation as
// nuclei.LoadDir (see pkg/template/nuclei/loader.go).
func LoadDir(dir string) (templates []*Template, errs []error) {
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			errs = append(errs, fmt.Errorf("walking %s: %w", path, err))
			return nil
		}
		if d.IsDir() {
			return nil
		}
		ext := filepath.Ext(path)
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		tmpl, err := loadFile(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, err))
			return nil
		}
		templates = append(templates, tmpl)
		return nil
	})
	return templates, errs
}

func loadFile(path string) (*Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	var tmpl Template
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&tmpl); err != nil {
		return nil, fmt.Errorf("parsing yaml: %w", err)
	}

	if err := validate(&tmpl); err != nil {
		return nil, err
	}
	return &tmpl, nil
}

// validate rejects a parsed template that's malformed, or that an
// idor-tagged template uses in a shape the idor.Detector-routing path can't
// honor — rather than silently running it incompletely. See
// docs/10-implementation-plan-ph1b.md Step 3's Context #2.
func validate(tmpl *Template) error {
	if tmpl.ID == "" {
		return fmt.Errorf("template has no id")
	}
	if len(tmpl.Requests) == 0 {
		return fmt.Errorf("template has no requests: entries")
	}

	if isIDORTagged(tmpl) {
		return validateIDORTemplate(tmpl)
	}
	return validateGenericTemplate(tmpl)
}

// validateIDORTemplate enforces the single-request, no-matchers/extractors
// shape an idor-tagged template must have — every other field would be
// silently ignored by idor.Detector, which fires its own hardcoded
// baseline-comparison request rather than executing this template's Request
// as written.
func validateIDORTemplate(tmpl *Template) error {
	if len(tmpl.Requests) != 1 {
		return fmt.Errorf("idor-tagged template has %d requests, expected exactly 1 (idor.Detector fires its own request, not a chain — see docs/10-implementation-plan-ph1b.md Step 3)", len(tmpl.Requests))
	}
	req := tmpl.Requests[0]
	if req.Method != "" && req.Method != "GET" {
		return fmt.Errorf("idor-tagged template's request must be GET (or omitted), got %q — idor.Detector always uses GET", req.Method)
	}
	if len(req.Headers) > 0 {
		return fmt.Errorf("idor-tagged template's request declares headers:, which idor.Detector ignores (it only ever sets Authorization) — remove them")
	}
	if req.Body != "" {
		return fmt.Errorf("idor-tagged template's request declares body:, which idor.Detector ignores (GET-only) — remove it")
	}
	if len(req.Matchers) > 0 {
		return fmt.Errorf("idor-tagged template's request declares matchers:, which idor.Detector ignores (it has its own baseline-comparison logic) — remove them")
	}
	if len(req.Extractors) > 0 {
		return fmt.Errorf("idor-tagged template's request declares extractors:, which idor.Detector ignores (single request, no chaining) — remove them")
	}
	if req.Condition != "" {
		return fmt.Errorf("idor-tagged template's request declares condition:, which idor.Detector ignores (always fires) — remove it")
	}
	if _, _, _, err := parseIDORRequest("", tmpl, req); err != nil {
		return fmt.Errorf("idor-tagged template: %w", err)
	}
	return nil
}

// validateGenericTemplate validates every request's matchers/extractors the
// same way the nuclei loader does, plus this format's own condition:
// expressions — checked against every name that could plausibly be bound at
// runtime (global variables: plus every request's extractor names), so a
// genuine typo in a condition still fails at load time without rejecting
// every legitimate reference to a not-yet-bound chain variable.
func validateGenericTemplate(tmpl *Template) error {
	knownVars := map[string]string{}
	for k := range tmpl.Variables {
		knownVars[k] = ""
	}
	for _, req := range tmpl.Requests {
		for _, e := range req.Extractors {
			if e.Name != "" {
				knownVars[e.Name] = ""
			}
		}
	}

	for i, req := range tmpl.Requests {
		if req.Path == "" {
			return fmt.Errorf("requests[%d]: no path", i)
		}
		for j, m := range req.Matchers {
			if err := matcher.Validate(m); err != nil {
				return fmt.Errorf("requests[%d].matchers[%d]: %w", i, j, err)
			}
		}
		for j, e := range req.Extractors {
			if err := extractor.Validate(e); err != nil {
				return fmt.Errorf("requests[%d].extractors[%d]: %w", i, j, err)
			}
		}
		if req.Condition != "" {
			if _, err := dsl.Eval(req.Condition, dsl.Context{Vars: knownVars}); err != nil {
				return fmt.Errorf("requests[%d]: invalid condition expression %q: %w", i, req.Condition, err)
			}
		}
	}
	return nil
}
