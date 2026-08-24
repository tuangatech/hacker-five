package nuclei

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

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
		if len(req.Raw) > 0 || len(req.Payloads) > 0 {
			return fmt.Errorf("http[%d]: uses raw:/payloads: — unsupported in this version, see docs/10-implementation-plan-ph1b.md Step 2", i)
		}
		if len(req.Path) == 0 {
			return fmt.Errorf("http[%d]: no path", i)
		}
		for j, m := range req.Matchers {
			if m.Internal {
				return fmt.Errorf("http[%d].matchers[%d]: uses internal: true — flow-control-only matcher, unsupported without flow: support, see docs/10-implementation-plan-ph1b.md Step 2", i, j)
			}
			if err := matcher.Validate(m); err != nil {
				return fmt.Errorf("http[%d].matchers[%d]: %w", i, j, err)
			}
		}
		for j, e := range req.Extractors {
			if err := extractor.Validate(e); err != nil {
				return fmt.Errorf("http[%d].extractors[%d]: %w", i, j, err)
			}
		}
	}
	return nil
}
