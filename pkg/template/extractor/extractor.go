// Package extractor pulls dynamic values out of an HTTP response for
// request chaining. Shared by both template formats, same as
// pkg/template/matcher (see docs/10-implementation-plan-ph1b.md Steps 2-3).
package extractor

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/template/dsl"
	"github.com/tuangatech/hacker-five/pkg/template/matcher"
)

// Extractor pulls one named value out of a response, to be bound as
// {{Name}} for later requests in the same template's chain.
type Extractor struct {
	Type  string   `yaml:"type"` // "regex" | "kval" | "json" | "dsl"
	Name  string   `yaml:"name,omitempty"`
	Part  string   `yaml:"part,omitempty"`
	Regex []string `yaml:"regex,omitempty"`
	Group int      `yaml:"group,omitempty"` // regex capture group to extract; 0 = whole match
	JSON  []string `yaml:"json,omitempty"`  // dot-path, e.g. "token" or "data.user.id" — no array wildcards in v0.1.0
	Kval  []string `yaml:"kval,omitempty"`  // response header key name (cookie-specific parsing not implemented — no sampled template needed it)
	DSL   []string `yaml:"dsl,omitempty"`
}

// Extract runs every extractor against r and returns the bound name/value
// pairs. An extractor with no Name is skipped — only named extractors
// participate in chaining, matching Nuclei's own behavior.
func Extract(extractors []Extractor, r matcher.Response) map[string]string {
	out := make(map[string]string)
	for _, e := range extractors {
		if e.Name == "" {
			continue
		}
		if val, ok := extractOne(e, r); ok {
			out[e.Name] = val
		}
	}
	return out
}

func extractOne(e Extractor, r matcher.Response) (string, bool) {
	switch e.Type {
	case "regex":
		return extractRegex(e, r)
	case "json":
		return extractJSON(e, r)
	case "kval":
		return extractKval(e, r)
	case "dsl":
		return extractDSL(e, r)
	default:
		return "", false
	}
}

func extractRegex(e Extractor, r matcher.Response) (string, bool) {
	text := matcher.Part(e.Part, r)
	for _, pattern := range e.Regex {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		m := re.FindStringSubmatch(text)
		if m == nil {
			continue
		}
		if e.Group > 0 && e.Group < len(m) {
			return m[e.Group], true
		}
		return m[0], true
	}
	return "", false
}

func extractJSON(e Extractor, r matcher.Response) (string, bool) {
	var data any
	if err := json.Unmarshal(r.Body, &data); err != nil {
		return "", false
	}
	for _, path := range e.JSON {
		if val, ok := jsonPath(data, path); ok {
			return fmt.Sprintf("%v", val), true
		}
	}
	return "", false
}

func jsonPath(data any, path string) (any, bool) {
	cur := data
	for _, key := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[key]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func extractKval(e Extractor, r matcher.Response) (string, bool) {
	for _, key := range e.Kval {
		if v := r.Headers.Get(key); v != "" {
			return v, true
		}
	}
	return "", false
}

func extractDSL(e Extractor, r matcher.Response) (string, bool) {
	for _, expr := range e.DSL {
		val, err := dsl.Eval(expr, dsl.Context{StatusCode: r.StatusCode, Body: string(r.Body), Header: matcher.Part("header", r), ContentType: r.Headers.Get("Content-Type"), Headers: r.Headers, Request: r.Request, Vars: r.ExtraVars, IntVars: r.ExtraInts})
		if err != nil {
			continue
		}
		return fmt.Sprintf("%v", val), true
	}
	return "", false
}

// Validate reports whether e is well-formed — its Type is recognized, every
// Regex pattern compiles, and every DSL expression parses — without
// extracting from a real response. Used by the nuclei loader to reject a
// malformed template at load time.
func Validate(e Extractor) error {
	return ValidateWithContext(e, dsl.Context{})
}

// ValidateWithContext is Validate, but checks a dsl: extractor's expressions
// against a caller-supplied dsl.Context instead of an empty one — same
// reason as matcher.ValidateWithContext (a raw:-request block with more
// than one Raw entry legitimately references indexed identifiers that only
// exist once execution binds them).
func ValidateWithContext(e Extractor, ctx dsl.Context) error {
	if !matcher.ValidPartWithContext(e.Part, ctx) {
		// See matcher.ValidateWithContext's matching comment (LT-15,
		// docs/follow-up.md) — this used to always guess "likely OAST",
		// which mislabeled the real prestashop-cartabandonmentpro-file-
		// upload.yaml rejection (`part: request`, unrelated to OAST).
		return fmt.Errorf("extractor: unsupported part %q (not implemented — see matcher.ValidPart for the supported list)", e.Part)
	}
	switch e.Type {
	case "json", "kval":
		return nil
	case "regex":
		for _, p := range e.Regex {
			if _, err := regexp.Compile(p); err != nil {
				return fmt.Errorf("extractor: invalid regex %q: %w", p, err)
			}
		}
		return nil
	case "dsl":
		for _, expr := range e.DSL {
			if _, err := dsl.Eval(expr, ctx); err != nil {
				return fmt.Errorf("extractor: invalid dsl expression %q: %w", expr, err)
			}
		}
		return nil
	default:
		return fmt.Errorf("extractor: unsupported type %q", e.Type)
	}
}
