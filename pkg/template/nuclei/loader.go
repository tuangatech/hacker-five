package nuclei

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/tuangatech/hacker-five/pkg/template/dsl"
	"github.com/tuangatech/hacker-five/pkg/template/extractor"
	"github.com/tuangatech/hacker-five/pkg/template/matcher"
)

// disallowedBlocks are top-level YAML keys that trigger a load-time error
// rather than a parsed-but-silently-incomplete template — RCE/LFI-capable
// protocol blocks nobody on this project has reviewed. Same list as
// documented in doc 02/03.
var disallowedBlocks = []string{"code", "javascript", "headless", "file", "dns", "tcp", "ssl", "network", "websocket", "whois"}

// LoadError pairs a rejected file's path with why it failed — the
// structured shape LoadDirDetailed returns so a caller that also runs the
// other template format's loader against the same dir (pkg/templatesync.List,
// pkg/scanner.Engine.loadTemplates) can tell "this file is simply the other
// format" (rejected here, accepted there) apart from a genuine parse
// failure (rejected by both), instead of double-counting the former as a
// real problem.
type LoadError struct {
	Path string
	Err  error
}

func (e *LoadError) Error() string { return fmt.Sprintf("%s: %v", e.Path, e.Err) }

// LoadDir parses every .yaml/.yml file under dir, recursively — upstream
// nuclei-templates categories nest vendor-named subdirectories (e.g.
// http/exposed-panels/adobe/), so a single-level scan would miss most of
// them. One bad file doesn't stop the rest from loading: errs collects one
// error per rejected file; callers should log/count them, not treat a
// non-empty errs as fatal to the whole load. A thin wrapper over
// LoadDirDetailed, kept at this exact signature since ~40 existing call
// sites (tests/unit, tests/integration) already depend on it.
func LoadDir(dir string) (templates []*Template, errs []error) {
	templates, detailed := LoadDirDetailed(dir)
	for i := range detailed {
		errs = append(errs, &detailed[i])
	}
	return templates, errs
}

// LoadDirDetailed is LoadDir with structured, per-path errors — same walk,
// same parsing, same accept/reject decisions, only the error shape differs.
func LoadDirDetailed(dir string) (templates []*Template, errs []LoadError) {
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			errs = append(errs, LoadError{Path: path, Err: fmt.Errorf("walking: %w", err)})
			return nil
		}
		if d.IsDir() {
			return nil
		}
		ext := filepath.Ext(path)
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		tmpl, err := loadFile(path, dir)
		if err != nil {
			errs = append(errs, LoadError{Path: path, Err: err})
			return nil
		}
		templates = append(templates, tmpl)
		return nil
	})
	return templates, errs
}

func loadFile(path, sourceDir string) (*Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	if err := checkDisallowedBlocks(data); err != nil {
		return nil, err
	}

	var tmpl Template
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&tmpl); err != nil {
		return nil, fmt.Errorf("parsing yaml: %w", err)
	}
	tmpl.sourceDir = sourceDir

	if err := validate(&tmpl); err != nil {
		return nil, err
	}
	return &tmpl, nil
}

// checkDisallowedBlocks rejects a template containing any top-level key in
// disallowedBlocks. This has to happen on the raw YAML, before decoding
// into Template — a key with no matching struct field would otherwise just
// be silently dropped by yaml.v3's default lenient unmarshal, and these
// specific keys (code:/javascript:/etc.) are exactly the ones that must
// never be silently ignored.
func checkDisallowedBlocks(data []byte) error {
	var raw map[string]yaml.Node
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parsing yaml: %w", err)
	}
	for _, block := range disallowedBlocks {
		if _, ok := raw[block]; ok {
			return fmt.Errorf("template uses disallowed block %q — protocol not reviewed for this project, see CLAUDE.md", block)
		}
	}
	return nil
}

// validate rejects a parsed template that uses request styles or malformed
// matcher/extractor entries this project doesn't support, rather than
// letting it silently run incompletely or panic mid-scan.
func validate(tmpl *Template) error {
	if strings.TrimSpace(tmpl.ID) == "" {
		return fmt.Errorf("template has no id")
	}
	if len(tmpl.HTTP) == 0 {
		return fmt.Errorf("template has no http: requests")
	}
	if tmpl.Flow != "" {
		ast, maxN, err := parseFlow(tmpl.Flow)
		if err != nil {
			return fmt.Errorf("flow: %w", err)
		}
		if maxN > len(tmpl.HTTP) {
			return fmt.Errorf("flow: references http(%d) but template only has %d http: requests", maxN, len(tmpl.HTTP))
		}
		tmpl.flowAST = ast
	}
	// knownExtractorNames accumulates every extractor Name seen so far, plus
	// (despite the name) every payloads: key of the CURRENT request only —
	// both bind a DSL-visible string variable the same way, so they share
	// one dummy-Vars mechanism. Extractor names: seeded with the current
	// request's own names before that request's matchers/extractors are
	// checked (so a same-request reference like apache-httpd-eol.yaml's
	// compare_versions(version, ...) resolves), then carried forward
	// unmodified into later requests (so a cross-request reference like
	// google-iap-detect.yaml's request 2 dsl: ["email"], extracted by
	// request 1, resolves too). Payload keys: NOT carried forward past the
	// request that declares them (each request's payloads: is its own
	// substitution scope, unlike an extractor's binding) — added fresh each
	// iteration below, real example: upstream's wp-crontrol.yaml's
	// compare_versions(internal_detected_version, concat("< ",
	// last_version)), where last_version is a file-based payloads: key
	// referenced directly in the same request's own dsl: matcher. See
	// nuclei.Executor's tryPath/tryRawIteration for the matching runtime
	// behavior — this is purely the load-time "does this expression
	// type-check" counterpart, real values are never known this early.
	knownExtractorNames := map[string]string{}

	for i, req := range tmpl.HTTP {
		// payloads: is also legitimately used with a plain path:-based
		// request, not just raw: (real example: upstream's
		// phpmyadmin-panel.yaml — path: ["{{BaseURL}}{{paths}}"] +
		// payloads: {paths: [...]}, arguably the more common shape in the
		// synced corpus — see docs/10-implementation-plan-ph1b.md's raw:/
		// payloads: note). No rejection needed here for that combination;
		// nuclei.Executor's Run handles both.
		for j, entry := range req.Raw {
			if hasAbsoluteRequestLine(entry) {
				return fmt.Errorf("http[%d].raw[%d]: absolute-URI request line — proxy-relay-style raw requests unsupported in this version, see docs/10-implementation-plan-ph1b.md", i, j)
			}
		}
		if _, err := req.resolvePayloads(tmpl.sourceDir); err != nil {
			return fmt.Errorf("http[%d]: %w", i, err)
		}
		if len(req.Raw) == 0 && len(req.Path) == 0 {
			return fmt.Errorf("http[%d]: no path", i)
		}
		for _, e := range req.Extractors {
			if e.Name != "" {
				knownExtractorNames[e.Name] = ""
			}
		}
		reqScopeNames := knownExtractorNames
		if len(req.Payloads) > 0 {
			reqScopeNames = make(map[string]string, len(knownExtractorNames)+len(req.Payloads))
			for k, v := range knownExtractorNames {
				reqScopeNames[k] = v
			}
			for k := range req.Payloads {
				reqScopeNames[k] = ""
			}
		}
		dslCtx := requestDSLContext(req.Raw, reqScopeNames)
		for j, m := range req.Matchers {
			if m.Internal && tmpl.Flow == "" {
				return fmt.Errorf("http[%d].matchers[%d]: uses internal: true outside a flow: template — flow-control-only matcher has nothing to gate without flow:, see docs/10-implementation-plan-ph1b.md", i, j)
			}
			if err := matcher.ValidateWithContext(m, dslCtx); err != nil {
				return fmt.Errorf("http[%d].matchers[%d]: %w", i, j, err)
			}
		}
		for j, e := range req.Extractors {
			if err := extractor.ValidateWithContext(e, dslCtx); err != nil {
				return fmt.Errorf("http[%d].extractors[%d]: %w", i, j, err)
			}
		}
	}
	return nil
}

// requestDSLContext builds the dsl.Context used to validate one request's
// matchers/extractors: rawIndexedDSLContext's body_N/header_N/status_code_N/
// content_type_N/duration_N/duration entries (same-block raw: correlation,
// plus the always-present bare "duration"), plus a dummy entry for every name
// in knownExtractorNames (same-request-or-earlier extractor binding — see
// validate's knownExtractorNames comment). Both mechanisms are independent
// and additive; either can be empty without affecting the other.
//
// The dummy value is "0", not "" — an extractor's real value is an
// arbitrary string, but a real template might immediately feed it into
// compare_versions(), which needs to actually parse its dummy input as
// dot-separated numeric segments to confirm the expression type-checks
// (found live: apache-httpd-eol.yaml's compare_versions(version, ...)
// errored against an empty-string dummy — "0" parses cleanly as a version
// while still being a harmless placeholder for any string-only function).
func requestDSLContext(raw []string, knownExtractorNames map[string]string) dsl.Context {
	ctx := rawIndexedDSLContext(raw)
	if len(knownExtractorNames) == 0 {
		return ctx
	}
	if ctx.Vars == nil {
		ctx.Vars = make(map[string]string, len(knownExtractorNames))
	}
	for name := range knownExtractorNames {
		ctx.Vars[name] = "0"
	}
	return ctx
}

// rawIndexedDSLContext builds a dsl.Context with a zero-valued body_N/
// header_N/status_code_N/content_type_N/duration_N entry for every N =
// 1..len(raw) — just enough for matcher.ValidateWithContext/
// extractor.ValidateWithContext to confirm a dsl: expression referencing
// those identifiers actually parses/type-checks at load time, without
// needing (or having) real per-entry results yet (those only exist once
// nuclei.Executor's tryRaw actually fires every entry).
//
// A bare "duration" entry is always present, even when raw is empty: unlike
// body/header/status_code/content_type (whose bare forms are built-in
// dsl.Context fields, populated straight from the response regardless of
// raw:), "duration" has no such field — it's threaded through IntVars like
// the indexed identifiers, so it needs an explicit dummy entry here too. A
// duration check is just as valid on a plain path:-based request as a raw:
// one (real example: upstream's CVE-2023-2130.yaml, a single-path
// blind-SQLi sleep check with no raw: at all) — nuclei.Executor's tryPath
// binds it the same way tryRawIteration binds the aliased bare
// status_code/body/header/content_type to the last raw entry. Non-duration,
// non-raw templates are otherwise unaffected: this used to return a fully
// zero-value Context when raw was empty, now it returns one with only
// IntVars["duration"] set.
func rawIndexedDSLContext(raw []string) dsl.Context {
	ints := map[string]int{"duration": 0}
	if len(raw) == 0 {
		return dsl.Context{IntVars: ints}
	}
	vars := make(map[string]string, len(raw)*3)
	for n := 1; n <= len(raw); n++ {
		vars[fmt.Sprintf("body_%d", n)] = ""
		vars[fmt.Sprintf("header_%d", n)] = ""
		vars[fmt.Sprintf("content_type_%d", n)] = ""
		ints[fmt.Sprintf("status_code_%d", n)] = 0
		ints[fmt.Sprintf("duration_%d", n)] = 0
	}
	return dsl.Context{Vars: vars, IntVars: ints}
}
