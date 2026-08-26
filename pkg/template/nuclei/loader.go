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

// LoadDir parses every .yaml/.yml file under dir, recursively — upstream
// nuclei-templates categories nest vendor-named subdirectories (e.g.
// http/exposed-panels/adobe/), so a single-level scan would miss most of
// them. One bad file doesn't stop the rest from loading: errs collects one
// error per rejected file; callers should log/count them, not treat a
// non-empty errs as fatal to the whole load.
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

	if err := checkDisallowedBlocks(data); err != nil {
		return nil, err
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
		return fmt.Errorf("uses flow: — conditional multi-request control flow unsupported in this version, see docs/10-implementation-plan-ph1b.md Step 2")
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
		if _, _, err := req.resolvePayload(); err != nil {
			return fmt.Errorf("http[%d]: %w", i, err)
		}
		if len(req.Raw) == 0 && len(req.Path) == 0 {
			return fmt.Errorf("http[%d]: no path", i)
		}
		dslCtx := rawIndexedDSLContext(req.Raw)
		for j, m := range req.Matchers {
			if m.Internal {
				return fmt.Errorf("http[%d].matchers[%d]: uses internal: true — flow-control-only matcher, unsupported without flow: support, see docs/10-implementation-plan-ph1b.md Step 2", i, j)
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

// rawIndexedDSLContext builds a dsl.Context with a zero-valued body_N/
// header_N/status_code_N entry for every N = 1..len(raw) — just enough for
// matcher.ValidateWithContext/extractor.ValidateWithContext to confirm a
// dsl: expression referencing those identifiers actually parses/type-checks
// at load time, without needing (or having) real per-entry results yet
// (those only exist once nuclei.Executor's tryRaw actually fires every
// entry). Returns a zero-value Context (identical to the old
// dsl.Context{}-everywhere behavior) when raw is empty, so non-raw
// templates are completely unaffected.
func rawIndexedDSLContext(raw []string) dsl.Context {
	if len(raw) == 0 {
		return dsl.Context{}
	}
	vars := make(map[string]string, len(raw)*2)
	ints := make(map[string]int, len(raw))
	for n := 1; n <= len(raw); n++ {
		vars[fmt.Sprintf("body_%d", n)] = ""
		vars[fmt.Sprintf("header_%d", n)] = ""
		ints[fmt.Sprintf("status_code_%d", n)] = 0
	}
	return dsl.Context{Vars: vars, IntVars: ints}
}
