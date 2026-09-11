package nuclei

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/tuangatech/hacker-five/pkg/template/dsl"
	"github.com/tuangatech/hacker-five/pkg/template/extractor"
	"github.com/tuangatech/hacker-five/pkg/template/matcher"
)

// disallowedBlocks are top-level YAML keys that trigger a load-time error
// rather than a parsed-but-silently-incomplete template — RCE/LFI-capable
// protocol blocks nobody on this project has reviewed. Same list as
// documented in doc 02/03. "tcp" was lifted out (Phase 8 Step 1,
// docs/17-implementation-plan-ph8.md): a bounded connect/send/read-banner
// executor now exists (see TCPRequest, executor.go's runTCPRequest), same
// review status as every other supported protocol — "deferred, not
// rejected", per that same doc's framing, until each remaining entry gets
// its own reviewed executor.
var disallowedBlocks = []string{"code", "javascript", "headless", "file", "dns", "ssl", "network", "websocket", "whois"}

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

// LoadDirByIDs is LoadDirDetailed narrowed to templates whose id: is in
// want — F4 (docs/follow-up.md LT-71). It still walks the whole tree (a
// cheap readdir), but only fully parses + validates a file whose id:,
// cheaply peeked from the head of the file, is one of the requested IDs.
// For a plan dispatching a handful of named template leaves this turns a
// ~9,500-file parse into a ~10-file one, with a result identical to
// LoadDirDetailed followed by an exact-id filter: a caller that can't
// account for every requested ID in the result should fall back to the full
// load (a template whose id: sits outside the peeked head is far outside
// nuclei convention, but the fallback keeps the narrowing a pure
// optimisation). want == nil / empty returns nothing.
func LoadDirByIDs(dir string, want map[string]bool) (templates []*Template, errs []LoadError) {
	if len(want) == 0 {
		return nil, nil
	}
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if ext := filepath.Ext(path); ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			errs = append(errs, LoadError{Path: path, Err: fmt.Errorf("reading file: %w", rerr)})
			return nil
		}
		if id := peekTemplateID(data); id == "" || !want[id] {
			return nil
		}
		tmpl, lerr := loadFileData(data, dir)
		if lerr != nil {
			errs = append(errs, LoadError{Path: path, Err: lerr})
			return nil
		}
		templates = append(templates, tmpl)
		return nil
	})
	return templates, errs
}

// LoadFiles parses exactly the files named in relPaths (each resolved
// against dir), skipping the recursive directory walk LoadDirDetailed does.
// It is the fast-load counterpart to a caller that already knows which files
// it wants — pkg/scanner's parse cache (docs/follow-up.md LT-106): given a
// dir fingerprint that still matches, the cache holds the id/tags/path of
// every template, so a tag-scoped scan can parse only the ~1.6k matching
// files instead of the full ~9.6k corpus. sourceDir on each returned
// Template is dir, identical to LoadDirDetailed, so file-based payloads:
// resolve the same way. A relPath that doesn't exist or fails to parse is
// collected in errs, exactly as LoadDirDetailed collects a bad file — one
// missing entry doesn't abort the rest.
func LoadFiles(dir string, relPaths []string) (templates []*Template, errs []LoadError) {
	for _, rel := range relPaths {
		full := filepath.Join(dir, filepath.FromSlash(rel))
		tmpl, err := loadFile(full, dir)
		if err != nil {
			errs = append(errs, LoadError{Path: full, Err: err})
			continue
		}
		templates = append(templates, tmpl)
	}
	return templates, errs
}

// PeekDirIDs walks dir recursively and returns a map from each template's
// declared id: to its path relative to dir (forward-slash form), read via
// the same bounded head-of-file peek LoadDirByIDs uses — no YAML parse. It
// backs pkg/scanner's parse-cache rebuild: after a full LoadDirDetailed, the
// scanner needs each loaded template's on-disk path to record in the cache,
// and re-deriving it from a cheap peek pass is far cheaper than threading a
// path back through every loader signature. A file whose id: isn't in the
// peeked head is omitted (its entry then carries an empty path, which the
// cache treats as a reason to fall back to a full parse). The id: convention
// (column-0, near the top) is shared by both this format and the native
// one, so the same map covers a mixed directory. On a duplicate id the last
// file walked wins; the corpus is not expected to contain any.
func PeekDirIDs(dir string) (map[string]string, error) {
	ids := make(map[string]string)
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // a walk error on one entry must not abort the rest — same posture as LoadDirDetailed
		}
		if ext := filepath.Ext(path); ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		id := peekTemplateID(data)
		if id == "" {
			return nil
		}
		rel, rerr := filepath.Rel(dir, path)
		if rerr != nil {
			return nil
		}
		ids[id] = filepath.ToSlash(rel)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ids, nil
}

// templateIDPeekPattern pulls the id: value from the head of a nuclei
// template without a full YAML parse — id: is the conventional first
// top-level key of every nuclei template (upstream's template guidelines
// make it mandatory and first). Anchored to column 0 so an indented "id:"
// inside info: or a matcher can't match.
var templateIDPeekPattern = regexp.MustCompile(`(?m)^id:[ \t]*["']?([A-Za-z0-9_.\-]+)`)

// templateIDPeekBytes bounds how much of a file's head peekTemplateID
// scans — id: is line 1 in practice; 4 KiB is generous slack for a leading
// comment block.
const templateIDPeekBytes = 4096

// peekTemplateID returns the template's declared id: from a bounded head of
// the file, or "" if it isn't there (the caller then just skips the file in
// the fast path).
func peekTemplateID(data []byte) string {
	if len(data) > templateIDPeekBytes {
		data = data[:templateIDPeekBytes]
	}
	if m := templateIDPeekPattern.FindSubmatch(data); m != nil {
		return string(m[1])
	}
	return ""
}

func loadFile(path, sourceDir string) (*Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}
	return loadFileData(data, sourceDir)
}

// loadFileData is loadFile's parse/validate half, split out so LoadDirByIDs
// can reuse the bytes it already read for the id: peek.
func loadFileData(data []byte, sourceDir string) (*Template, error) {
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
	if len(tmpl.HTTP) == 0 && len(tmpl.TCP) == 0 {
		return fmt.Errorf("template has no http: or tcp: requests")
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

	// allExtractorNames is the template-wide (not forward-accumulated)
	// counterpart to knownExtractorNames above — every extractor Name used
	// anywhere in the template, regardless of request order. It's the
	// exclusion list requestDSLContext's AssumeUnknownIsHeader fallback
	// needs (LT-15, docs/follow-up.md): an as-yet-unaccumulated extractor
	// Name (a genuine forward-reference bug, see
	// TestNucleiLoadDir_ForwardExtractorReferenceRejected) must still be
	// rejected, not silently assumed to be a header just because it isn't
	// in knownExtractorNames YET.
	allExtractorNames := map[string]bool{}
	for _, req := range tmpl.HTTP {
		for _, e := range req.Extractors {
			if e.Name != "" {
				allExtractorNames[e.Name] = true
			}
		}
	}

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
		dslCtx := requestDSLContext(req.Raw, req.Path, reqScopeNames, allExtractorNames)
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

		// pathCorrelated opts this specific request into the raw:-style "fire
		// every entry, then bind body_N/header_N/..., then match once" model
		// instead of the default independent per-path try-until-match loop —
		// see nuclei.Executor.runPathRequest. Gated on genuinely needing it
		// (usesPathCorrelation: a matcher/extractor actually references an
		// indexed identifier or part) so the ~9,000+ other multi-path
		// templates that rely on today's independent-try-each-path behavior
		// are completely unaffected — only a request with no raw: (raw:
		// already always correlates, see HTTPRequest.Raw) and more than one
		// Path entry can even qualify. Real example: CVE-2012-3153.yaml fires
		// both its Path entries every time and checks body_1/body_2 together.
		if len(req.Raw) == 0 && len(req.Path) > 1 && usesPathCorrelation(req.Matchers, req.Extractors) {
			tmpl.HTTP[i].pathCorrelated = true
		}

		// usesInteractsh gates nuclei.Executor's OOB machinery (prepareOOB/
		// awaitOOB) — only a request that actually embeds {{interactsh-url}}
		// pays the cost of generating a probe and polling for a correlated
		// callback afterward. See HTTPRequest.usesInteractsh's doc comment.
		if usesInteractshURL(req) {
			tmpl.HTTP[i].usesInteractsh = true
		}

		// usesTiming gates D5's response cache (respcache.go): a request
		// whose matcher/extractor reads response timing must always hit the
		// network, since a cache hit's elapsed time is meaningless.
		if usesTimingRef(req.Matchers, req.Extractors) {
			tmpl.HTTP[i].usesTiming = true
		}
	}

	for i, req := range tmpl.TCP {
		if len(req.Inputs) == 0 {
			return fmt.Errorf("tcp[%d]: no inputs", i)
		}
		for j, m := range req.Matchers {
			// No flow: support for tcp: requests (see TCPRequest's doc
			// comment) — an internal: true matcher would have nothing to
			// gate, same rejection reasoning as the http: case above.
			if m.Internal {
				return fmt.Errorf("tcp[%d].matchers[%d]: uses internal: true — flow: is unsupported for tcp: requests", i, j)
			}
			// Validated against an empty dsl.Context: TCP v1 binds no
			// indexed body_N-style identifiers (no multi-input
			// correlation, see TCPRequest's doc comment) — a bare
			// "body"/"data" identifier and part: already resolve fine
			// against the zero Context, same as any single-request http:
			// template's matchers do.
			if err := matcher.Validate(m); err != nil {
				return fmt.Errorf("tcp[%d].matchers[%d]: %w", i, j, err)
			}
		}
	}
	return nil
}

// timingIdentifierPattern matches the bare "duration" DSL identifier or a
// duration_N alias — the blind time-based signal D5's response cache
// (respcache.go) must never serve from cache. Word-boundary-anchored, same
// discipline as indexedIdentifierPattern.
var timingIdentifierPattern = regexp.MustCompile(`\bduration(?:_[0-9]+)?\b`)

// usesTimingRef reports whether any matcher/extractor observes response
// timing — a dsl: expression referencing duration/duration_N, or a
// part: duration matcher/extractor.
func usesTimingRef(matchers []matcher.Matcher, extractors []extractor.Extractor) bool {
	for _, m := range matchers {
		if m.Part == "duration" {
			return true
		}
		for _, expr := range m.DSL {
			if timingIdentifierPattern.MatchString(expr) {
				return true
			}
		}
	}
	for _, e := range extractors {
		if e.Part == "duration" {
			return true
		}
		for _, expr := range e.DSL {
			if timingIdentifierPattern.MatchString(expr) {
				return true
			}
		}
	}
	return false
}

// interactshURLPlaceholder is real Nuclei's own out-of-band correlation
// variable — see nuclei.Executor's prepareOOB for what firing one actually
// does. Literal, not regex-matched: real templates always spell it exactly
// this way (docs/follow-up.md's OOB item measured the real synced corpus to
// confirm before relying on this).
const interactshURLPlaceholder = "{{interactsh-url}}"

// usesInteractshURL reports whether any of req's Raw/Path/Body/Headers
// content embeds interactshURLPlaceholder.
func usesInteractshURL(req HTTPRequest) bool {
	if strings.Contains(req.Body, interactshURLPlaceholder) {
		return true
	}
	for _, s := range req.Raw {
		if strings.Contains(s, interactshURLPlaceholder) {
			return true
		}
	}
	for _, s := range req.Path {
		if strings.Contains(s, interactshURLPlaceholder) {
			return true
		}
	}
	for _, v := range req.Headers {
		if strings.Contains(v, interactshURLPlaceholder) {
			return true
		}
	}
	return false
}

// indexedIdentifierPattern matches a body_N/header_N/status_code_N/
// content_type_N/duration_N DSL identifier reference (N a positive
// integer) — the same identifier family indexedDSLContext seeds dummy
// values for. Word-boundary-anchored so it only matches the identifier
// itself, not an unrelated longer name that happens to contain one of these
// as a substring.
var indexedIdentifierPattern = regexp.MustCompile(`\b(?:body|header|status_code|content_type|duration)_[0-9]+\b`)

// usesPathCorrelation reports whether matchers/extractors reference an
// indexed body_N/header_N/... identifier — either directly in a dsl:
// expression, or via a word/regex matcher/extractor's indexed part: value
// (matcher.IsIndexedPart). Real corpus examples of each form:
// CVE-2012-3153.yaml (dsl: 'contains(body_1, "Reports Servlet")'),
// CVE-2014-4592.yaml (a word matcher with `part: body_2`). Only meaningful
// for a plain path:-based request — req.Raw already gets unconditional
// fire-every-entry treatment regardless of whether anything references the
// indexed identifiers (see HTTPRequest.Raw); callers gate on
// len(req.Raw) == 0 && len(req.Path) > 1 separately.
func usesPathCorrelation(matchers []matcher.Matcher, extractors []extractor.Extractor) bool {
	for _, m := range matchers {
		if matcher.IsIndexedPart(m.Part) {
			return true
		}
		for _, expr := range m.DSL {
			if indexedIdentifierPattern.MatchString(expr) {
				return true
			}
		}
	}
	for _, e := range extractors {
		if matcher.IsIndexedPart(e.Part) {
			return true
		}
		for _, expr := range e.DSL {
			if indexedIdentifierPattern.MatchString(expr) {
				return true
			}
		}
	}
	return false
}

// requestDSLContext builds the dsl.Context used to validate one request's
// matchers/extractors: indexedDSLContext's body_N/header_N/status_code_N/
// content_type_N/duration_N/duration entries (same-block correlation, plus
// the always-present bare "duration"), plus a dummy entry for every name in
// knownExtractorNames (same-request-or-earlier extractor binding — see
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
func requestDSLContext(raw, path []string, knownExtractorNames map[string]string, allExtractorNames map[string]bool) dsl.Context {
	ctx := indexedDSLContext(raw, path, allExtractorNames)
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

// indexedDSLContext builds a dsl.Context with a zero-valued body_N/
// header_N/status_code_N/content_type_N/duration_N entry for every N =
// 1..count — just enough for matcher.ValidateWithContext/
// extractor.ValidateWithContext to confirm a dsl: expression (or an indexed
// part: value, via matcher.ValidPartWithContext) referencing those
// identifiers actually parses/type-checks at load time, without needing (or
// having) real per-entry results yet (those only exist once
// nuclei.Executor's tryRawIteration/tryPathCorrelatedIteration actually
// fires every entry).
//
// count is len(raw) when raw is non-empty (raw: always correlates
// unconditionally — see HTTPRequest.Raw), else len(path). This makes
// indexed identifiers/parts validate-able on a path:-based request too, not
// just raw: — including the "_1" form on a genuinely single-path request
// (real examples: CVE-2023-1362.yaml's `status_code_1 == 200`,
// yonyou-nc-baseapp-deserialization.yaml's `contains_all(body_1, ...)`,
// both single-path, single-request templates where Nuclei's own DSL treats
// "_1" as a always-valid alias for the bare identifier — nuclei.Executor's
// tryPath binds that alias directly, no correlation firing needed for it).
// Whether execution actually runs a >1-path request in full correlation
// mode (firing every entry, not just aliasing "_1") is a separate decision
// — see validate's pathCorrelated flag / usesPathCorrelation — this
// function only widens what type-checks at load time.
//
// A bare "duration" entry is always present, even when count is 0: unlike
// body/header/status_code/content_type (whose bare forms are built-in
// dsl.Context fields, populated straight from the response regardless of
// raw:), "duration" has no such field — it's threaded through IntVars like
// the indexed identifiers, so it needs an explicit dummy entry here too. A
// duration check is just as valid on a plain path:-based request as a raw:
// one (real example: upstream's CVE-2023-2130.yaml, a single-path
// blind-SQLi sleep check with no raw: at all) — nuclei.Executor's tryPath
// binds it the same way tryRawIteration binds the aliased bare
// status_code/body/header/content_type to the last raw entry.
func indexedDSLContext(raw, path []string, excludeFromHeaderAssumption map[string]bool) dsl.Context {
	n := len(raw)
	if n == 0 {
		n = len(path)
	}
	ints := map[string]int{"duration": 0}
	// interactsh_protocol/interactsh_request/interactsh_response are always
	// present, regardless of n or of whether this specific request actually
	// uses {{interactsh-url}} — cheap (3 fixed entries, not indexed/scaling)
	// and matches how nuclei.Executor's awaitOOB always populates all three
	// at runtime (see matcher.ValidPart's doc comment for why that
	// unconditional presence matters).
	vars := map[string]string{"interactsh_protocol": "", "interactsh_request": "", "interactsh_response": ""}
	if n == 0 {
		// AssumeUnknownIsHeader (LT-15, docs/follow-up.md): which response
		// headers a live target actually sends back is unknowable at load
		// time, so a bare-word identifier this dummy Context doesn't
		// otherwise recognize (real example: webp-server-lfi.yaml's
		// `contains(server, ...)`) is assumed to be a header name that will
		// resolve at runtime, rather than rejecting the template outright.
		return dsl.Context{Vars: vars, IntVars: ints, AssumeUnknownIsHeader: true, ExcludedFromHeaderAssumption: excludeFromHeaderAssumption}
	}
	for i := 1; i <= n; i++ {
		vars[fmt.Sprintf("body_%d", i)] = ""
		vars[fmt.Sprintf("header_%d", i)] = ""
		vars[fmt.Sprintf("content_type_%d", i)] = ""
		ints[fmt.Sprintf("status_code_%d", i)] = 0
		ints[fmt.Sprintf("duration_%d", i)] = 0
	}
	return dsl.Context{Vars: vars, IntVars: ints, AssumeUnknownIsHeader: true, ExcludedFromHeaderAssumption: excludeFromHeaderAssumption}
}
