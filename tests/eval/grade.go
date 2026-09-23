package eval

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/coverage"
	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/llmfallback"
)

// This file is the measurement half of docs/94-llm-finding-capability-
// strategy.md's Phase 0: grading one run against ground truth and comparing
// arms across repeated runs. It has no build tag and needs no lab, so the
// grading and aggregation are unit-tested (grade_test.go); only actually
// driving `hackerfive agent` against a live target lives behind the eval tag
// (ablation_test.go).
//
// Why a second kind of ground truth: tests/fixtures/expected-findings lists ID
// prefixes the deterministic scan already produces, so every arm "passes" it
// and it cannot show what a model adds. tests/fixtures/known-vulns lists the
// vulnerabilities each lab is *documented* to contain, including ones the
// scanner has missed, so recall on it can move.

// KnownVuln is one documented vulnerability in a lab target. A finding detects
// it when its Target contains EndpointContains (case-insensitive) and its ID has
// one of IDPrefixes. At least one of the two must be set, or every finding
// would match; LoadKnownVulns rejects an entry with neither.
type KnownVuln struct {
	ID               string   `json:"id"`
	Class            string   `json:"class"`
	Description      string   `json:"description"`
	EndpointContains string   `json:"endpoint_contains,omitempty"`
	IDPrefixes       []string `json:"id_prefixes,omitempty"`

	// Baseline is what an earlier, dated measurement recorded for the
	// deterministic scan: "found", "missed" or "unknown". It is context for
	// reading a result, never an input to grading, and is not re-measured here.
	Baseline string `json:"baseline"`
	Source   string `json:"source"`
	Note     string `json:"note,omitempty"`

	// Gated, when set, says why no agent run can reach this vulnerability (a
	// mutating class behind an operator-only flag). Miss attribution reports it
	// as unreachable by design rather than as a pipeline loss.
	Gated string `json:"gated,omitempty"`
}

// KnownVulnsFile is the on-disk shape of tests/fixtures/known-vulns/<lab>.json.
type KnownVulnsFile struct {
	Description string      `json:"description"`
	Vulns       []KnownVuln `json:"vulns"`
}

// LoadKnownVulns reads and validates a known-vulns fixture.
func LoadKnownVulns(path string) (KnownVulnsFile, error) {
	var f KnownVulnsFile
	raw, err := os.ReadFile(path)
	if err != nil {
		return f, err
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return f, fmt.Errorf("%s: %w", path, err)
	}
	seen := map[string]bool{}
	for _, v := range f.Vulns {
		switch {
		case v.ID == "":
			return f, fmt.Errorf("%s: a vuln has no id", path)
		case seen[v.ID]:
			return f, fmt.Errorf("%s: duplicate vuln id %q", path, v.ID)
		case v.EndpointContains == "" && len(v.IDPrefixes) == 0:
			return f, fmt.Errorf("%s: vuln %q sets neither endpoint_contains nor id_prefixes, so it would match every finding", path, v.ID)
		}
		seen[v.ID] = true
	}
	return f, nil
}

func idHasAnyPrefix(id string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(id, p) {
			return true
		}
	}
	return false
}

func (v KnownVuln) matches(f detectors.Finding) bool {
	if v.EndpointContains != "" && !strings.Contains(strings.ToLower(f.Target), strings.ToLower(v.EndpointContains)) {
		return false
	}
	return len(v.IDPrefixes) == 0 || idHasAnyPrefix(f.ID, v.IDPrefixes)
}

// Grade is one run's result against both kinds of ground truth.
type Grade struct {
	Findings int

	// ExpectedTotal/Hit grade expected_id_prefixes (what the deterministic scan
	// is known to produce); MissedPrefixes names the ones with no finding.
	ExpectedTotal, ExpectedHit int
	MissedPrefixes             []string

	// KnownTotal/Hit grade the documented-vulnerability list.
	KnownTotal, KnownHit int
	KnownHitIDs          []string
	KnownMissedIDs       []string

	// Unlabeled counts findings that match no expected prefix and no known
	// vulnerability. These are candidate false positives, not proven ones: the
	// ground truth is a list of what is documented, not of everything true.
	Unlabeled int
}

// GradeRun grades findings against the expected prefixes and known
// vulnerabilities. Either ground-truth list may be empty.
func GradeRun(findings []detectors.Finding, expectedPrefixes []string, known []KnownVuln) Grade {
	g := Grade{Findings: len(findings), ExpectedTotal: len(expectedPrefixes), KnownTotal: len(known)}
	for _, p := range expectedPrefixes {
		hit := false
		for _, f := range findings {
			if strings.HasPrefix(f.ID, p) {
				hit = true
				break
			}
		}
		if hit {
			g.ExpectedHit++
		} else {
			g.MissedPrefixes = append(g.MissedPrefixes, p)
		}
	}
	for _, v := range known {
		hit := false
		for _, f := range findings {
			if v.matches(f) {
				hit = true
				break
			}
		}
		if hit {
			g.KnownHit++
			g.KnownHitIDs = append(g.KnownHitIDs, v.ID)
		} else {
			g.KnownMissedIDs = append(g.KnownMissedIDs, v.ID)
		}
	}
	for _, f := range findings {
		labeled := idHasAnyPrefix(f.ID, expectedPrefixes)
		for _, v := range known {
			if labeled {
				break
			}
			labeled = v.matches(f)
		}
		if !labeled {
			g.Unlabeled++
		}
	}
	return g
}

// agentEvent and agentResult mirror `hackerfive agent`'s JSONL stream
// (cmd/hackerfive/agent.go). Result has no JSON tags on the Go side, so its
// field names decode case-insensitively.
type agentEvent struct {
	Type    string             `json:"type"`
	Finding *detectors.Finding `json:"finding,omitempty"`
	Result  *agentResult       `json:"result,omitempty"`
	Err     string             `json:"error,omitempty"`
}

type agentResult struct {
	Findings      []detectors.Finding
	Iterations    int
	FastLaneTurns int
	SpendUSD      float64
	Degraded      string

	// What miss attribution (attribution.go) reads: the plan tree, the turns that
	// dispatched its leaves, and the endpoints recon observed.
	Tree         *agenttask.PlanTree
	History      []llmfallback.TurnRecord
	Recon        []coverage.Endpoint
	ReconDropped int
}

// ParsedRun is what ParseAgentStream recovers from a run's stdout.
type ParsedRun struct {
	Findings  []detectors.Finding
	Result    agentResult
	SawResult bool
}

// ParseAgentStream reads the agent's JSONL stdout line by line rather than
// requiring a final document, so a run that was killed still yields every
// finding it streamed (LT-163 item 3). When a final "result" event exists its
// Findings are authoritative (a superset of the streamed ones).
func ParseAgentStream(stdout []byte) (ParsedRun, error) {
	var p ParsedRun
	sc := bufio.NewScanner(bytes.NewReader(stdout))
	sc.Buffer(make([]byte, 0, 64*1024), 8<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var ev agentEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			return p, fmt.Errorf("agent output line %q: %w", truncate(string(line), 80), err)
		}
		switch ev.Type {
		case "finding":
			if ev.Finding != nil {
				p.Findings = append(p.Findings, *ev.Finding)
			}
		case "result":
			if ev.Result != nil {
				p.Result, p.SawResult = *ev.Result, true
			}
		}
	}
	if err := sc.Err(); err != nil {
		return p, err
	}
	if p.SawResult {
		p.Findings = p.Result.Findings
	}
	return p, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// RunRecord is one (lab, arm, run) measurement, written one per line to the
// ablation results file so runs can be compared later without re-running them.
type RunRecord struct {
	Lab   string `json:"lab"`
	Arm   string `json:"arm"`
	Run   int    `json:"run"`
	Model string `json:"model,omitempty"` // what answered the model calls; "none" for --no-model
	// Settings records the harness overrides (templates dir, extra flags) the run used.
	Settings string `json:"settings,omitempty"`

	Findings       int      `json:"findings"`
	ExpectedHit    int      `json:"expected_hit"`
	ExpectedTotal  int      `json:"expected_total"`
	KnownHit       int      `json:"known_hit"`
	KnownTotal     int      `json:"known_total"`
	KnownMissedIDs []string `json:"known_missed_ids,omitempty"`
	Unlabeled      int      `json:"unlabeled"`

	// FindingIDs is every finding as "<id> <target>", sorted, so two runs can be
	// diffed exactly instead of inferred equal from their counts (LT-183 item i).
	FindingIDs []string `json:"finding_ids,omitempty"`

	// Miss attribution (LT-185), set by AddAttribution: the stage each known
	// vulnerability reached ("1-no-leaf"), the reason in a sentence, and how many
	// recon endpoints ended at each stage.
	KnownStages    map[string]string `json:"known_stages,omitempty"`
	KnownWhy       map[string]string `json:"known_why,omitempty"`
	ReconEndpoints int               `json:"recon_endpoints,omitempty"`
	EndpointStages map[string]int    `json:"endpoint_stages,omitempty"`

	CostUSD       float64 `json:"cost_usd"`
	ModelTurns    int     `json:"model_turns"`
	FastLaneTurns int     `json:"fast_lane_turns"`
	Degraded      string  `json:"degraded,omitempty"`
	WallSeconds   float64 `json:"wall_seconds"`

	// SawResult is false when the run was killed or crashed before its final
	// result event; its findings are then only what streamed out.
	SawResult bool   `json:"saw_result"`
	Error     string `json:"error,omitempty"`
}

// modelLineRe matches the line `hackerfive agent` writes to stderr naming the
// model, e.g. "agent: model: openrouter:openai/gpt-5.6-luna".
var modelLineRe = regexp.MustCompile(`(?m)^agent: model: (\S+)\s*$`)

// ModelFromStderr returns the model an agent run reported, "" if it reported
// none (an older binary, or a run that died before printing it).
func ModelFromStderr(stderr string) string {
	if m := modelLineRe.FindStringSubmatch(stderr); m != nil {
		return m[1]
	}
	return ""
}

// NewRunRecord assembles a record from a parsed run and its grade.
func NewRunRecord(lab, arm string, run int, p ParsedRun, g Grade, wallSeconds float64, runErr string) RunRecord {
	return RunRecord{
		Lab: lab, Arm: arm, Run: run,
		Findings: g.Findings, ExpectedHit: g.ExpectedHit, ExpectedTotal: g.ExpectedTotal,
		KnownHit: g.KnownHit, KnownTotal: g.KnownTotal, KnownMissedIDs: g.KnownMissedIDs, Unlabeled: g.Unlabeled,
		CostUSD: p.Result.SpendUSD, ModelTurns: p.Result.Iterations, FastLaneTurns: p.Result.FastLaneTurns,
		Degraded: p.Result.Degraded, WallSeconds: wallSeconds, SawResult: p.SawResult, Error: runErr,
		FindingIDs: findingIDs(p.Findings),
	}
}

func findingIDs(fs []detectors.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.ID+" "+f.Target)
	}
	sort.Strings(out)
	return out
}

// Stat is a mean with the range behind it. A model-driven arm is not
// deterministic, so one number would hide the variance the comparison needs.
type Stat struct{ Mean, Min, Max float64 }

func statOf(xs []float64) Stat {
	if len(xs) == 0 {
		return Stat{}
	}
	s := Stat{Min: xs[0], Max: xs[0]}
	var sum float64
	for _, x := range xs {
		sum += x
		if x < s.Min {
			s.Min = x
		}
		if x > s.Max {
			s.Max = x
		}
	}
	s.Mean = sum / float64(len(xs))
	return s
}

// ArmSummary aggregates every run of one arm against one lab.
type ArmSummary struct {
	Lab, Arm string
	Model    string // rows are never merged across models: their results are not comparable
	Runs     int
	Failed   int // runs that never produced a result event
	Degraded int // runs that ended with the model unavailable or disabled

	ExpectedRecall Stat // fraction of expected_id_prefixes hit
	KnownRecall    Stat // fraction of known vulnerabilities hit; meaningful only when KnownTotal > 0
	KnownTotal     int
	Unlabeled      Stat
	CostUSD        Stat
	ModelTurns     Stat
	WallSeconds    Stat
}

func frac(hit, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(hit) / float64(total)
}

// Summarize groups records by lab and arm, in a stable order.
func Summarize(records []RunRecord) []ArmSummary {
	type key struct{ lab, arm, model string }
	groups := map[key][]RunRecord{}
	var keys []key
	for _, r := range records {
		k := key{r.Lab, r.Arm, r.Model}
		if _, ok := groups[k]; !ok {
			keys = append(keys, k)
		}
		groups[k] = append(groups[k], r)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].lab != keys[j].lab {
			return keys[i].lab < keys[j].lab
		}
		if keys[i].arm != keys[j].arm {
			return keys[i].arm < keys[j].arm
		}
		return keys[i].model < keys[j].model
	})

	out := make([]ArmSummary, 0, len(keys))
	for _, k := range keys {
		rs := groups[k]
		s := ArmSummary{Lab: k.lab, Arm: k.arm, Model: k.model, Runs: len(rs), KnownTotal: rs[0].KnownTotal}
		var er, kr, un, cost, turns, wall []float64
		for _, r := range rs {
			if !r.SawResult {
				s.Failed++
			}
			if r.Degraded != "" {
				s.Degraded++
			}
			er = append(er, frac(r.ExpectedHit, r.ExpectedTotal))
			kr = append(kr, frac(r.KnownHit, r.KnownTotal))
			un = append(un, float64(r.Unlabeled))
			cost = append(cost, r.CostUSD)
			turns = append(turns, float64(r.ModelTurns))
			wall = append(wall, r.WallSeconds)
		}
		s.ExpectedRecall, s.KnownRecall, s.Unlabeled = statOf(er), statOf(kr), statOf(un)
		s.CostUSD, s.ModelTurns, s.WallSeconds = statOf(cost), statOf(turns), statOf(wall)
		out = append(out, s)
	}
	return out
}

func pct(s Stat) string {
	if s.Min == s.Max {
		return fmt.Sprintf("%.0f%%", s.Mean*100)
	}
	return fmt.Sprintf("%.0f%% (%.0f-%.0f)", s.Mean*100, s.Min*100, s.Max*100)
}

func num(s Stat, format string) string {
	if s.Min == s.Max {
		return fmt.Sprintf(format, s.Mean)
	}
	return fmt.Sprintf(format+" ("+format+"-"+format+")", s.Mean, s.Min, s.Max)
}

// FormatSummary renders the comparison as a fixed-width table. Read it with the
// run count in mind: with Runs of 1 a model-driven arm's row is an anecdote, and
// the range shown is a single point.
func FormatSummary(sums []ArmSummary) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%-26s %-18s %-34s %4s %4s %-16s %-16s %-10s %-10s %-9s %s\n",
		"lab", "arm", "model", "runs", "fail", "expected recall", "known-vuln recall", "unlabeled", "cost $", "model trn", "wall s")
	for _, s := range sums {
		known := "n/a"
		if s.KnownTotal > 0 {
			known = pct(s.KnownRecall)
		}
		arm := s.Arm
		if s.Degraded > 0 {
			arm += "*"
		}
		model := s.Model
		if model == "" {
			model = "?"
		}
		fmt.Fprintf(&b, "%-26s %-18s %-34s %4d %4d %-16s %-16s %-10s %-10s %-9s %s\n",
			s.Lab, arm, model, s.Runs, s.Failed, pct(s.ExpectedRecall), known,
			num(s.Unlabeled, "%.1f"), num(s.CostUSD, "%.4f"), num(s.ModelTurns, "%.1f"), num(s.WallSeconds, "%.0f"))
	}
	b.WriteString("* = at least one run ended degraded (model disabled or unavailable)\n")
	return b.String()
}
