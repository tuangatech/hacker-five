package planexec

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/scanner"
	"github.com/tuangatech/hacker-five/pkg/templatesync"
)

// writeOneTemplate drops a single always-matching nuclei template (status
// matcher) into a fresh dir and returns the dir — the minimal corpus for the
// doc15 Step 6c once-per-host tests below.
func writeOneTemplate(t *testing.T, id string, status int) string {
	t.Helper()
	dir := t.TempDir()
	body := fmt.Sprintf(`
id: %s
info:
  name: %s
  severity: info
http:
  - method: GET
    path: ["{{BaseURL}}/"]
    matchers:
      - type: status
        status: [%d]
`, id, id, status)
	if err := os.WriteFile(filepath.Join(dir, "t.yaml"), []byte(body), 0o644); err != nil {
		t.Fatalf("writing template: %v", err)
	}
	return dir
}

// countCorpusLoads tallies engine "loaded N nuclei-compatible" log lines by
// N — the once-per-host corpus signal doc15 Step 6c's tests assert on.
func countCorpusLoads(logs []string) (withCorpus, withoutCorpus int) {
	for _, l := range logs {
		switch {
		case strings.Contains(l, "loaded 1 nuclei-compatible"):
			withCorpus++
		case strings.Contains(l, "loaded 0 nuclei-compatible"):
			withoutCorpus++
		}
	}
	return withCorpus, withoutCorpus
}

func testOpts() ExecOptions {
	return ExecOptions{DetConcurrency: 2, LLMConcurrency: 2}
}

// TestRunPlan_SkipsUnexecutableLeaves confirms three of the four skip
// reasons (unrecognized detector/template-ID, missing required field) never
// reach scanner.New — no network call is attempted for them, only the
// eligible leaf is dispatched (against an unreachable address, so it fails
// fast rather than needing a real target — this test is about dispatch
// eligibility, not scan correctness).
func TestRunPlan_SkipsUnexecutableLeaves(t *testing.T) {
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{
		{ID: "template-id-leaf", Target: "http://127.0.0.1:1", Detector: "wordpress-xmlrpc-enabled"}, // raw template ID, not a recognized detector
		{ID: "idor-no-endpoint", Target: "http://127.0.0.1:1", Detector: "idor"},                     // recognized, but EndpointTemplate unset on baseCfg
		{ID: "misconfig-leaf", Target: "http://127.0.0.1:1", Detector: "misconfig"},                  // eligible
	}}}

	baseCfg := scanner.Config{
		Concurrency:  1,
		RateLimit:    50,
		Timeout:      2 * time.Second,
		OutputFormat: "json",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, _, skipped, _ := RunPlan(ctx, tree, baseCfg, nil, testOpts()) // nil templateIndex — "wordpress-xmlrpc-enabled" matches no known template ID either

	if len(skipped) != 2 {
		t.Fatalf("got %d skipped leaves, want 2 (template-id-leaf, idor-no-endpoint); skipped=%v", len(skipped), skipped)
	}

	// The eligible leaf must have been dispatched (its Status moved off
	// pending, whatever the outcome against an unreachable target).
	if tree.Find("misconfig-leaf").Status != agenttask.StatusDone {
		t.Fatalf("got Status=%q for the eligible leaf, want done (dispatched, regardless of scan outcome)", tree.Find("misconfig-leaf").Status)
	}
	// The two skipped leaves must be untouched — never dispatched.
	if tree.Find("template-id-leaf").Status == agenttask.StatusDone {
		t.Fatal("a skipped leaf must not be marked done")
	}
	if tree.Find("idor-no-endpoint").Status == agenttask.StatusDone {
		t.Fatal("a skipped leaf must not be marked done")
	}
}

// TestRunPlan_ExcludedLeafSkipped locks in ExecOptions.Excluded — the new
// mechanism a webui Plan Preview "run this leaf" checkbox (left unchecked)
// uses to keep an otherwise-eligible leaf from being dispatched, reported
// via skipped like any other skip reason rather than silently vanishing.
func TestRunPlan_ExcludedLeafSkipped(t *testing.T) {
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{
		{ID: "excluded-leaf", Target: "http://127.0.0.1:1", Detector: "misconfig"},
	}}}
	baseCfg := scanner.Config{Concurrency: 1, RateLimit: 50, Timeout: 2 * time.Second, OutputFormat: "json"}
	opts := testOpts()
	opts.Excluded = map[string]bool{"excluded-leaf": true}

	_, _, skipped, _ := RunPlan(context.Background(), tree, baseCfg, nil, opts)

	if len(skipped) != 1 {
		t.Fatalf("got skipped=%v, want exactly 1 (excluded-leaf)", skipped)
	}
	if tree.Find("excluded-leaf").Status == agenttask.StatusDone {
		t.Fatal("an excluded leaf must not be dispatched")
	}
}

// TestRunPlan_OnFindingOnLogCalled confirms the live-streaming callbacks
// fire for a dispatched leaf, alongside (not instead of) the returned
// aggregate logs slice — pkg/webui's Plan Preview execute action depends on
// OnLog/OnFinding to stream into a running Job's SSE feed.
func TestRunPlan_OnFindingOnLogCalled(t *testing.T) {
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{
		{ID: "misconfig-leaf", Target: "http://127.0.0.1:1", Detector: "misconfig"},
	}}}
	baseCfg := scanner.Config{Concurrency: 1, RateLimit: 50, Timeout: 2 * time.Second, OutputFormat: "json"}

	var notified []string
	opts := testOpts()
	opts.Notify = func(target, message string) { notified = append(notified, target+": "+message) }

	_, logs, _, _ := RunPlan(context.Background(), tree, baseCfg, nil, opts)

	// Against an unreachable target the engine logs at least a connection
	// error — both the returned aggregate slice and the live Notify
	// callback must see it.
	if len(logs) == 0 {
		t.Fatal("got no logs from a dispatched leaf against an unreachable target, want at least one")
	}
	if len(notified) == 0 {
		t.Fatal("Notify callback never fired for a dispatched leaf")
	}
}

// TestMissingRequiredField covers every detector's field gate — moved here
// from pkg/mcpserver/tools_plan_test.go (idor/authbypass/ssrf/misconfig
// cases) merged with the businesslogic cases that used to live in
// pkg/mcpserver/executor_test.go, now that missingRequiredField itself lives
// in this package. businesslogic's case (P1-1, docs/follow-up.md):
// registry.Resolve can now emit a businesslogic leaf from endpoint signal
// alone, with no idea whether the operator opted into mutating checks —
// this must skip cleanly, not reach cfg.Validate and fail loudly, exactly
// like idor/authbypass/ssrf's own existing field gates.
func TestMissingRequiredField(t *testing.T) {
	cases := []struct {
		name        string
		detector    string
		cfg         scanner.Config
		wantMissing bool
	}{
		{"idor missing endpoint", "idor", scanner.Config{}, true},
		{"idor has endpoint", "idor", scanner.Config{EndpointTemplate: "/x/{{id}}"}, false},
		{"authbypass missing protected paths", "authbypass", scanner.Config{}, true},
		{"authbypass has protected paths", "authbypass", scanner.Config{ProtectedPaths: []string{"/admin"}}, false},
		{"ssrf missing params", "ssrf", scanner.Config{}, true},
		{"ssrf has params", "ssrf", scanner.Config{SSRFParams: []string{"url"}}, false},
		{"misconfig has no requirement", "misconfig", scanner.Config{}, false},
		{"businesslogic neither set", "businesslogic", scanner.Config{}, true},
		{"businesslogic allow-writes only", "businesslogic", scanner.Config{AllowWrites: true}, true},
		{"businesslogic auth-token only", "businesslogic", scanner.Config{AuthToken: "tok"}, true},
		{"businesslogic both set", "businesslogic", scanner.Config{AllowWrites: true, AuthToken: "tok"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reason := missingRequiredField(tc.detector, tc.cfg)
			if tc.wantMissing && reason == "" {
				t.Fatal("got no missing-field reason, want one")
			}
			if !tc.wantMissing && reason != "" {
				t.Fatalf("got missing-field reason %q, want none", reason)
			}
		})
	}
}

// TestRunPlan_DispatchesKnownTemplateIDLeaf locks in the fix for what was
// previously always-skipped: a leaf whose Detector matches a real
// templatesync.Entry.ID (not a built-in detector name) now dispatches as a
// templates-only run instead of landing in skipped.
func TestRunPlan_DispatchesKnownTemplateIDLeaf(t *testing.T) {
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{
		{ID: "template-id-leaf", Target: "http://127.0.0.1:1", Detector: "wordpress-xmlrpc-enabled"},
	}}}
	baseCfg := scanner.Config{Concurrency: 1, RateLimit: 50, Timeout: 2 * time.Second, OutputFormat: "json"}
	templateIndex := []templatesync.Entry{{ID: "wordpress-xmlrpc-enabled", Tags: []string{"wordpress"}}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, _, skipped, _ := RunPlan(ctx, tree, baseCfg, templateIndex, testOpts())

	if len(skipped) != 0 {
		t.Fatalf("got skipped=%v, want none — the leaf's Detector matches a real template ID", skipped)
	}
	if tree.Find("template-id-leaf").Status != agenttask.StatusDone {
		t.Fatalf("got Status=%q, want done (dispatched as a templates-only run, regardless of scan outcome)", tree.Find("template-id-leaf").Status)
	}
}

// TestRunPlan_UnknownTemplateIDStillSkipped confirms a Detector value that
// matches neither a built-in detector name nor any entry in templateIndex
// (a hallucination, or a stale/renamed template) keeps the original
// skip-and-report behavior — no new silent-execution risk from this fix.
func TestRunPlan_UnknownTemplateIDStillSkipped(t *testing.T) {
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{
		{ID: "hallucinated-leaf", Target: "http://127.0.0.1:1", Detector: "totally-made-up-template-id"},
	}}}
	baseCfg := scanner.Config{Concurrency: 1, RateLimit: 50, Timeout: 2 * time.Second, OutputFormat: "json"}
	templateIndex := []templatesync.Entry{{ID: "wordpress-xmlrpc-enabled", Tags: []string{"wordpress"}}}

	_, _, skipped, _ := RunPlan(context.Background(), tree, baseCfg, templateIndex, testOpts())

	if len(skipped) != 1 {
		t.Fatalf("got skipped=%v, want exactly 1 (the hallucinated Detector)", skipped)
	}
	if tree.Find("hallucinated-leaf").Status == agenttask.StatusDone {
		t.Fatal("a hallucinated Detector must not be dispatched")
	}
}

func TestRunPlan_EmptyTree_NoPanic(t *testing.T) {
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root"}} // root itself is a leaf, but has no Detector
	baseCfg := scanner.Config{Concurrency: 1, RateLimit: 50}

	findings, logs, skipped, err := RunPlan(context.Background(), tree, baseCfg, nil, testOpts())
	if findings != nil || logs != nil || skipped != nil || err != nil {
		t.Fatalf("got (%v, %v, %v, %v), want all zero values for a tree with no Detector on its only leaf", findings, logs, skipped, err)
	}
}

// TestRunPlan_CorpusLoadsOncePerHost locks in doc15 Step 6c: the additive
// template corpus attaches to only the first builtin-capability leaf per host,
// not once per leaf (docs/follow-up.md LT-18). Three misconfig leaves on one
// host, a one-template corpus: exactly one leaf loads it, the other two run
// their detector alone.
func TestRunPlan_CorpusLoadsOncePerHost(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)

	dir := writeOneTemplate(t, "corpus-probe", http.StatusNotFound)
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{
		{ID: "leaf-a", Target: server.URL, Detector: "misconfig"},
		{ID: "leaf-b", Target: server.URL, Detector: "misconfig"},
		{ID: "leaf-c", Target: server.URL, Detector: "misconfig"},
	}}}
	baseCfg := scanner.Config{TemplatePaths: []string{dir}, Concurrency: 1, RateLimit: 50, Timeout: 3 * time.Second, OutputFormat: "json"}

	var mu sync.Mutex
	var logs []string
	opts := testOpts()
	opts.OnLog = func(_ *agenttask.PlanNode, _, msg string) { mu.Lock(); logs = append(logs, msg); mu.Unlock() }

	if _, _, _, err := RunPlan(context.Background(), tree, baseCfg, nil, opts); err != nil {
		t.Fatalf("RunPlan: %v", err)
	}

	withCorpus, withoutCorpus := countCorpusLoads(logs)
	if withCorpus != 1 {
		t.Fatalf("got %d leaves loading the corpus, want 1 (once per host); logs=%v", withCorpus, logs)
	}
	if withoutCorpus != 2 {
		t.Fatalf("got %d leaves running detector-only, want 2; logs=%v", withoutCorpus, logs)
	}
}

// TestRunPlan_CorpusLoadsPerDistinctHost is the counterpart: two builtin
// leaves on two different hosts each load the corpus once — the dedup key is
// the host, not the whole plan.
func TestRunPlan_CorpusLoadsPerDistinctHost(t *testing.T) {
	s1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) }))
	t.Cleanup(s1.Close)
	s2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) }))
	t.Cleanup(s2.Close)

	dir := writeOneTemplate(t, "corpus-probe", http.StatusNotFound)
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{
		{ID: "h1", Target: s1.URL, Detector: "misconfig"},
		{ID: "h2", Target: s2.URL, Detector: "misconfig"},
	}}}
	baseCfg := scanner.Config{TemplatePaths: []string{dir}, Concurrency: 2, RateLimit: 50, Timeout: 3 * time.Second, OutputFormat: "json"}

	var mu sync.Mutex
	var logs []string
	opts := testOpts()
	opts.OnLog = func(_ *agenttask.PlanNode, _, msg string) { mu.Lock(); logs = append(logs, msg); mu.Unlock() }

	if _, _, _, err := RunPlan(context.Background(), tree, baseCfg, nil, opts); err != nil {
		t.Fatalf("RunPlan: %v", err)
	}

	if withCorpus, _ := countCorpusLoads(logs); withCorpus != 2 {
		t.Fatalf("got %d corpus loads across 2 distinct hosts, want 2; logs=%v", withCorpus, logs)
	}
}

// TestRunPlan_TemplateIDLeafKeepsCorpus confirms Step 6c's caveat: a
// specific-template leaf always loads the corpus (it needs a full parse to
// resolve its id:), even when a builtin leaf on the same host already carries
// the once-per-host pass — so both load it here.
func TestRunPlan_TemplateIDLeafKeepsCorpus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	dir := writeOneTemplate(t, "pick-me", http.StatusOK)
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{
		{ID: "builtin", Target: server.URL, Detector: "misconfig"},
		{ID: "by-id", Target: server.URL, Detector: "pick-me"},
	}}}
	baseCfg := scanner.Config{TemplatePaths: []string{dir}, Concurrency: 1, RateLimit: 50, Timeout: 3 * time.Second, OutputFormat: "json"}

	var mu sync.Mutex
	var logs []string
	opts := testOpts()
	opts.OnLog = func(_ *agenttask.PlanNode, _, msg string) { mu.Lock(); logs = append(logs, msg); mu.Unlock() }

	if _, _, skipped, err := RunPlan(context.Background(), tree, baseCfg, []templatesync.Entry{{ID: "pick-me"}}, opts); err != nil || len(skipped) != 0 {
		t.Fatalf("RunPlan: err=%v skipped=%v", err, skipped)
	}

	if withCorpus, _ := countCorpusLoads(logs); withCorpus != 2 {
		t.Fatalf("got %d corpus loads, want 2 (builtin bearer + template-ID leaf); logs=%v", withCorpus, logs)
	}
}
