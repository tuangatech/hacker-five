// Package nuclei parses and executes a defined subset of the upstream
// Nuclei template schema — see docs/10-implementation-plan-ph1b.md Step 2
// for the exact scope, what's deliberately rejected, and why.
package nuclei

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/tuangatech/hacker-five/pkg/template/extractor"
	"github.com/tuangatech/hacker-five/pkg/template/matcher"
)

// Template is the top-level parsed shape of one Nuclei-compatible template
// file, restricted to the http: protocol.
type Template struct {
	ID   string        `yaml:"id"`
	Info Info          `yaml:"info"`
	HTTP []HTTPRequest `yaml:"http"`

	// Flow holds the raw flow: script text. Real Nuclei's flow: is small JS
	// controlling conditional/looped execution across a template's multiple
	// HTTP requests (e.g. "only run request 2 if request 1's matcher
	// fired"); this project supports only a minimal subset — boolean
	// composition of http(N) calls via &&/||/() — parsed into flowAST by
	// loader.go's validate. See matcher.Matcher.Internal's doc comment for
	// the real example (apache-server-status-localhost.yaml) that showed
	// why running a flow template's requests unconditionally/independently
	// is actively wrong, not just incomplete, and
	// docs/10-implementation-plan-ph1b.md's flow: note for the real corpus
	// measurement behind the supported grammar.
	Flow string `yaml:"flow,omitempty"`

	// flowAST is Flow parsed by loader.go's validate — nil for a non-flow
	// template. Unexported: only nuclei.Executor.runFlow reads it, and it
	// has no YAML shape of its own (populated after decode, not by it).
	flowAST flowExpr

	// sourceDir is the root directory this template was loaded from
	// (LoadDir/LoadDirDetailed's dir argument — the synced-corpus root,
	// e.g. ~/.config/hackerfive/nuclei-templates, not the individual
	// template file's own subdirectory). A request's file-based payloads:
	// entry (e.g. "helpers/wordpress/plugins/wp-crontrol.txt") resolves
	// relative to this, same as real Nuclei resolves it relative to the
	// corpus root rather than the template's own location — see
	// resolvePayloads. Populated by loader.go's loadFile after parsing;
	// empty for a Template built directly (e.g. in a test), in which case a
	// file-based payload reference fails clearly rather than resolving
	// against an unrelated working directory.
	sourceDir string
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
	// Path lists every path to try, in order — NOT Path[0]-only. Normally
	// each is tried independently (evaluate/report per entry, own
	// StopAtFirstMatch semantics — see loader.go/executor.go) unless
	// pathCorrelated is set, in which case every entry fires unconditionally
	// and Matchers evaluate once against the last — see pathCorrelated's doc
	// comment.
	Path    []string          `yaml:"path"`
	Headers map[string]string `yaml:"headers,omitempty"`
	Body    string            `yaml:"body,omitempty"`
	// StopAtFirstMatch stops trying further Path entries once one matches.
	StopAtFirstMatch  bool                      `yaml:"stop-at-first-match,omitempty"`
	MatchersCondition matcher.MatchersCondition `yaml:"matchers-condition,omitempty"`
	Matchers          []matcher.Matcher         `yaml:"matchers,omitempty"`
	Extractors        []extractor.Extractor     `yaml:"extractors,omitempty"`

	// Raw is a list of literal HTTP/1.1 request texts (method/path/headers/
	// body, {{}}-templated same as Path/Headers/Body), fired instead of the
	// Method/Path/Headers/Body fields above when non-empty. Every entry
	// fires, every time (see executor.go's tryRaw) — not a Path-style "try
	// each until one matches" list, because a request block with more than
	// one Raw entry commonly correlates results across all of them in a
	// single shared matcher (real example: upstream's open-proxy-*.yaml,
	// which fires ~24 probes and checks body_1..body_24 in one DSL
	// expression) — see docs/10-implementation-plan-ph1b.md's "raw:/
	// payloads: support" note for the real corpus measurement behind this.
	Raw []string `yaml:"raw,omitempty"`

	// Payloads maps a placeholder name (referenced as {{name}} in Raw) to
	// its list of substitution values. Real Nuclei allows either an inline
	// YAML list or a bare string naming an external wordlist file, resolved
	// relative to the synced-corpus root (see readPayloadFile) — both
	// supported; kept as yaml.Node rather than []string so validate() can
	// distinguish the two shapes and read the file-based one via
	// resolvePayloads instead of a decode failure. Two or
	// more keys are combined per Attack's mode — see resolvePayloads.
	Payloads map[string]yaml.Node `yaml:"payloads,omitempty"`

	// Attack names Nuclei's payload "attack mode" — pitchfork/clusterbomb/
	// batteringram, default batteringram — only meaningful with more than
	// one Payloads key (a single key iterates the same way under any mode).
	// "sniper" is valid Nuclei syntax but not expressible via nuclei's
	// map-shaped payloads: (each key names one fixed substitution position,
	// not a set of positions to try one at a time the way Burp's own Sniper
	// does) — 0 real corpus templates use it, consistent with that. See
	// resolvePayloads.
	Attack string `yaml:"attack,omitempty"`

	// pathCorrelated, when true, makes nuclei.Executor fire every Path entry
	// unconditionally (once per payload iteration) and evaluate Matchers
	// once against the last entry's response — the same "fire every entry,
	// then bind body_N/header_N/status_code_N/content_type_N/duration_N,
	// then match once" model Raw already always uses — instead of this
	// project's default behavior for Path: try each entry independently,
	// evaluating/reporting per-path (stopping early on StopAtFirstMatch).
	// Computed once at load time by loader.go's validate
	// (usesPathCorrelation), never set directly from YAML — a template
	// author has no field for this; it's inferred from whether the request
	// actually references an indexed identifier/part. Only ever true when
	// len(Raw) == 0 && len(Path) > 1 (Raw already correlates unconditionally
	// regardless of this flag; a single Path entry has no "N" to index).
	// Real example needing it: CVE-2012-3153.yaml, whose two Path entries'
	// matchers reference body_1 and body_2 together.
	pathCorrelated bool
}

// resolvePayloads validates req.Payloads/req.Attack and returns every
// substitution pass real Nuclei's attack mode produces, in a fixed,
// deterministic order (nil, nil when req has no payloads: at all). Shared
// by loader.go's validate (so a bad payload, attack mode, or missing
// wordlist file is a load-time error, not a scan-time surprise) and
// executor.go's runPathRequest/tryRaw (so execution uses the exact
// iterations validation already confirmed). baseDir resolves a file-based
// entry's relative path (see readPayloadFile) — callers pass the
// synced-corpus root: loader.go's validate passes the dir LoadDir/
// LoadDirDetailed was called with directly; executor.go passes the loaded
// Template's own tmpl.sourceDir.
//
// The three modes are Nuclei's own terms, borrowed directly from Burp
// Intruder's identically-named attack types:
//   - pitchfork: every key's list zipped together, index i of every list
//     combined into one pass, for i = 0..min(list length)-1. Real corpus
//     pitchfork templates aren't always equal-length across keys (7 of
//     207 sampled); using the shortest length rather than erroring matches
//     Burp Intruder's own documented Pitchfork behavior (request count =
//     the smallest payload set's size) — not a guess, a known precedent.
//   - clusterbomb: the full Cartesian product across every key's list —
//     every combination. Mismatched lengths are normal and expected here
//     (23 of 34 sampled), not an error condition — that's the point of
//     "every combination."
//   - batteringram: ONE shared list broadcast into every key at once (all
//     positions get the identical value each pass), rather than each key
//     using its own independently-defined list. This project uses the
//     first (sorted) key's list as that shared source. Unverified against
//     a genuine multi-key real example — all 13 real corpus batteringram
//     templates define only one key, where this degenerates to the same
//     single-list iteration every mode already agrees on — but matches the
//     documented Nuclei/Burp Intruder semantic (one payload set applied to
//     every position simultaneously).
func (req HTTPRequest) resolvePayloads(baseDir string) ([]map[string]string, error) {
	if len(req.Payloads) == 0 {
		return nil, nil
	}
	keys := make([]string, 0, len(req.Payloads))
	values := make(map[string][]string, len(req.Payloads))
	for k, node := range req.Payloads {
		switch node.Kind {
		case yaml.SequenceNode:
			vals, err := decodeStringSequence(node)
			if err != nil {
				return nil, fmt.Errorf("payloads.%s: %w", k, err)
			}
			if len(vals) == 0 {
				return nil, fmt.Errorf("payloads.%s: empty payload list", k)
			}
			values[k] = vals
			keys = append(keys, k)
		case yaml.ScalarNode:
			vals, err := readPayloadFile(baseDir, node.Value)
			if err != nil {
				return nil, fmt.Errorf("payloads.%s: %w", k, err)
			}
			values[k] = vals
			keys = append(keys, k)
		default:
			return nil, fmt.Errorf("payloads.%s: unsupported payload shape", k)
		}
	}
	sort.Strings(keys) // deterministic pass order regardless of map iteration order

	switch normalizedAttack(req.Attack) {
	case "batteringram":
		return batteringRamIterations(keys, values), nil
	case "pitchfork":
		return pitchforkIterations(keys, values), nil
	case "clusterbomb":
		return clusterbombIterations(keys, values), nil
	default:
		return nil, fmt.Errorf("attack: %q unsupported — no real corpus usage observed for this mode, see docs/10-implementation-plan-ph1b.md", req.Attack)
	}
}

// decodeStringSequence decodes a YAML sequence node into a []string,
// treating a `null` entry as an empty string rather than dropping it —
// node.Decode(&[]string{}) silently drops `!!null` entries entirely
// (confirmed: `[null]` decodes to a zero-length slice, not `[""]`), which
// would otherwise make a real, legitimate blank-credential entry (e.g.
// upstream's softether-vpn-default-login.yaml: `password: [null]`, a
// genuine "try an empty password" default-login check) look like an empty
// payload list and get rejected outright.
func decodeStringSequence(node yaml.Node) ([]string, error) {
	vals := make([]string, 0, len(node.Content))
	for _, c := range node.Content {
		if c.Tag == "!!null" {
			vals = append(vals, "")
			continue
		}
		var v string
		if err := c.Decode(&v); err != nil {
			return nil, err
		}
		vals = append(vals, v)
	}
	return vals, nil
}

// readPayloadFile reads relPath (a real template's file-based payloads:
// value, e.g. "helpers/wordpress/plugins/wp-crontrol.txt") relative to
// baseDir — the synced-corpus root real Nuclei itself resolves these paths
// against, not the individual template file's own directory (confirmed:
// upstream's http/technologies/wordpress/plugins/*.yaml templates all
// reference "helpers/..." as a corpus-root-relative path). One value per
// non-empty line, trimmed; most real examples are a single line (a plugin's
// current version string for a compare_versions() check — see
// docs/follow-up.md's "file-based payloads:" entry), but a genuine
// multi-line wordlist works the same way. See pkg/templatesync.SupportDirs
// for why "helpers" is synced alongside the http/ template categories.
func readPayloadFile(baseDir, relPath string) ([]string, error) {
	if baseDir == "" {
		return nil, fmt.Errorf("file-based payload %q referenced but this template's source directory is unknown", relPath)
	}
	if filepath.IsAbs(relPath) {
		return nil, fmt.Errorf("file-based payload %q: absolute paths unsupported", relPath)
	}
	cleanBase := filepath.Clean(baseDir)
	full := filepath.Join(cleanBase, relPath)
	// Path-traversal guard: relPath must resolve to somewhere inside
	// baseDir, not escape it via "../" — templates come from a pinned,
	// vetted upstream commit, but this is a cheap, unconditional check
	// worth keeping regardless of how trusted the source is today.
	if full != cleanBase && !strings.HasPrefix(full, cleanBase+string(filepath.Separator)) {
		return nil, fmt.Errorf("file-based payload %q: resolves outside the template source directory", relPath)
	}

	data, err := os.ReadFile(full)
	if err != nil {
		return nil, fmt.Errorf("reading file-based payload %q: %w", relPath, err)
	}
	var vals []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			vals = append(vals, line)
		}
	}
	if len(vals) == 0 {
		return nil, fmt.Errorf("file-based payload %q: no non-empty lines", relPath)
	}
	return vals, nil
}

func normalizedAttack(attack string) string {
	if strings.TrimSpace(attack) == "" {
		return "batteringram"
	}
	return strings.ToLower(strings.TrimSpace(attack))
}

func pitchforkIterations(keys []string, values map[string][]string) []map[string]string {
	n := len(values[keys[0]])
	for _, k := range keys[1:] {
		if len(values[k]) < n {
			n = len(values[k])
		}
	}
	iterations := make([]map[string]string, 0, n)
	for i := 0; i < n; i++ {
		iter := make(map[string]string, len(keys))
		for _, k := range keys {
			iter[k] = values[k][i]
		}
		iterations = append(iterations, iter)
	}
	return iterations
}

func clusterbombIterations(keys []string, values map[string][]string) []map[string]string {
	total := 1
	for _, k := range keys {
		total *= len(values[k])
	}
	iterations := make([]map[string]string, 0, total)
	indices := make([]int, len(keys))
	for {
		iter := make(map[string]string, len(keys))
		for ki, k := range keys {
			iter[k] = values[k][indices[ki]]
		}
		iterations = append(iterations, iter)

		// Odometer increment: advance the last key first, carrying into
		// earlier keys on rollover — same shape as counting in mixed radix.
		// pos ends up -1 once every combination has been emitted.
		pos := len(keys) - 1
		for pos >= 0 {
			indices[pos]++
			if indices[pos] < len(values[keys[pos]]) {
				break
			}
			indices[pos] = 0
			pos--
		}
		if pos < 0 {
			break
		}
	}
	return iterations
}

func batteringRamIterations(keys []string, values map[string][]string) []map[string]string {
	lead := values[keys[0]]
	iterations := make([]map[string]string, 0, len(lead))
	for _, v := range lead {
		iter := make(map[string]string, len(keys))
		for _, k := range keys {
			iter[k] = v
		}
		iterations = append(iterations, iter)
	}
	return iterations
}

// hasAbsoluteRequestLine reports whether raw's first line's request target
// is an absolute URI (e.g. "GET http://192.168.0.1/ HTTP/1.1") rather than
// a path relative to whatever host the connection actually goes to. Real
// templates use this to test open-proxy/SSRF-via-proxy behavior — the
// scanned target is expected to relay the request to the named URI. This
// project has no execution path that can honor that safely: net/http's
// standard client dials whatever URL it's given, so naively sending this
// would connect the scanner directly to the (template-controlled,
// downloaded) URI's own host, never touching the actual authorized target —
// a real out-of-scope-host risk, not just an unsupported feature. Checked
// on the raw, pre-render template text (real templates author the absolute
// URI literally, not via a payload variable), so this is a load-time
// rejection like the other raw:/payloads: exclusions above.
func hasAbsoluteRequestLine(raw string) bool {
	line := raw
	if idx := strings.IndexAny(raw, "\r\n"); idx != -1 {
		line = raw[:idx]
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return false
	}
	target := fields[1]
	return strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://")
}
