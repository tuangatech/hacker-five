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
	"sync/atomic"
	"testing"
	"time"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/scanner"
	"github.com/tuangatech/hacker-five/pkg/scanner/scope"
	"github.com/tuangatech/hacker-five/pkg/templatesync"
)

// writeOneTemplate drops a single always-matching nuclei template (status
// matcher) into a fresh dir and returns the dir — the minimal corpus for the
// doc15 Step 6c once-per-host tests below.
func writeOneTemplate(t *testing.T, id string, status int) string {
	t.Helper()
	dir := t.TempDir()
	// LT-137: tagged "misconfig" so it survives runLeaf's doc15 Step 6a
	// detector-category-floor narrowing — every caller here dispatches a
	// Detector: "misconfig" leaf (or a template-ID leaf, which matches by
	// exact id: instead and ignores tags entirely).
	body := fmt.Sprintf(`
id: %s
info:
  name: %s
  severity: info
  tags: misconfig
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
		{"ssrf has body params only", "ssrf", scanner.Config{SSRFBodyParams: []string{"repair_url"}}, false},
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

// TestApplyLeafReconFields_UUIDSeedCopiedAlongsideTemplate covers LT-95
// (docs/follow-up.md): EndpointSeedID/EndpointIDIsUUID must copy into cfg
// only together with EndpointTemplate, and only when the leaf actually
// marks the candidate UUID-shaped — a sibling int-shaped leaf (no
// EndpointIDIsUUID) must leave cfg.IDOREndpointIsUUID false.
func TestApplyLeafReconFields_UUIDSeedCopiedAlongsideTemplate(t *testing.T) {
	leaf := &agenttask.PlanNode{
		Detector:         "idor",
		EndpointTemplate: "/vehicle/{{id}}/location",
		EndpointSeedID:   "1b4e28ba-2fa1-11d2-883f-0016d3cca427",
		EndpointIDIsUUID: true,
	}
	var cfg scanner.Config
	applyLeafReconFields(&cfg, leaf, nil)

	if cfg.EndpointTemplate != leaf.EndpointTemplate {
		t.Fatalf("got EndpointTemplate %q, want %q", cfg.EndpointTemplate, leaf.EndpointTemplate)
	}
	if !cfg.IDOREndpointIsUUID {
		t.Fatal("got IDOREndpointIsUUID false, want true")
	}
	if cfg.IDORSeedID != leaf.EndpointSeedID {
		t.Fatalf("got IDORSeedID %q, want %q", cfg.IDORSeedID, leaf.EndpointSeedID)
	}
}

func TestApplyLeafReconFields_IntShapedLeaf_NoUUIDFieldsCopied(t *testing.T) {
	leaf := &agenttask.PlanNode{Detector: "idor", EndpointTemplate: "/orders/{{id}}"}
	var cfg scanner.Config
	applyLeafReconFields(&cfg, leaf, nil)

	if cfg.IDOREndpointIsUUID {
		t.Fatal("got IDOREndpointIsUUID true, want false for a plain int-shaped leaf")
	}
	if cfg.IDORSeedID != "" {
		t.Fatalf("got IDORSeedID %q, want empty", cfg.IDORSeedID)
	}
}

// TestApplyLeafReconFields_CouponFieldsCopied is LT-135's regression: a
// leaf carrying a spec-derived coupon mint/apply path + field-name pair
// fills a blank Config, and an already-set CouponMintPath/CouponApplyPath
// (an explicit --coupon-mint-path/--coupon-apply-path) is never overwritten.
func TestApplyLeafReconFields_CouponFieldsCopied(t *testing.T) {
	leaf := &agenttask.PlanNode{
		Detector:          "businesslogic",
		CouponMintPath:    "/api/v2/promo/new",
		CouponApplyPath:   "/api/v1/promo/apply",
		CouponCodeField:   "voucher_code",
		CouponAmountField: "value",
	}
	var cfg scanner.Config
	applyLeafReconFields(&cfg, leaf, nil)

	if cfg.CouponMintPath != leaf.CouponMintPath || cfg.CouponApplyPath != leaf.CouponApplyPath {
		t.Fatalf("got mint/apply %q/%q, want %q/%q", cfg.CouponMintPath, cfg.CouponApplyPath, leaf.CouponMintPath, leaf.CouponApplyPath)
	}
	if cfg.CouponCodeField != leaf.CouponCodeField || cfg.CouponAmountField != leaf.CouponAmountField {
		t.Fatalf("got fields %q/%q, want %q/%q", cfg.CouponCodeField, cfg.CouponAmountField, leaf.CouponCodeField, leaf.CouponAmountField)
	}

	// An explicit flag already set must never be overwritten.
	cfg2 := scanner.Config{CouponMintPath: "/manual/mint", CouponApplyPath: "/manual/apply"}
	applyLeafReconFields(&cfg2, leaf, nil)
	if cfg2.CouponMintPath != "/manual/mint" || cfg2.CouponApplyPath != "/manual/apply" {
		t.Fatalf("an already-set coupon path must not be overwritten, got %q/%q", cfg2.CouponMintPath, cfg2.CouponApplyPath)
	}
	if cfg2.CouponCodeField != "" {
		t.Fatalf("got CouponCodeField %q, want empty when the path pair was already set manually", cfg2.CouponCodeField)
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

// TestRunPlan_OnOutOfScope_HaltsBeforeDispatch covers doc15 Step 3's B4
// scope-creep gate: if an approved plan carries a leaf whose target is
// outside baseCfg.Scope, RunPlan invokes OnOutOfScope with the distinct
// out-of-scope hosts and, on a non-nil return, dispatches nothing.
func TestRunPlan_OnOutOfScope_HaltsBeforeDispatch(t *testing.T) {
	var hit int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hit, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sc, err := scope.New([]string{"127.0.0.1"}) // the httptest server's host; evil.example is not covered
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{
		{ID: "in-scope", Target: server.URL, Detector: "misconfig"},
		{ID: "creep", Target: "https://evil.example/x", Detector: "misconfig"},
	}}}
	baseCfg := scanner.Config{Scope: sc, Concurrency: 1, RateLimit: 50, Timeout: 2 * time.Second, OutputFormat: "json"}

	var gotHosts []string
	opts := testOpts()
	opts.OnOutOfScope = func(hosts []string) error {
		gotHosts = hosts
		return fmt.Errorf("halted: %s outside approved scope", strings.Join(hosts, ", "))
	}

	findings, _, _, err := RunPlan(context.Background(), tree, baseCfg, nil, opts)
	if err == nil {
		t.Fatal("expected RunPlan to return the OnOutOfScope error")
	}
	if len(gotHosts) != 1 || !strings.Contains(gotHosts[0], "evil.example") {
		t.Fatalf("OnOutOfScope got %v, want just the evil.example host", gotHosts)
	}
	if len(findings) != 0 || atomic.LoadInt32(&hit) != 0 {
		t.Fatalf("nothing must be dispatched once the gate fires: findings=%d serverHits=%d", len(findings), hit)
	}
	if tree.Find("in-scope").Status == agenttask.StatusDone {
		t.Fatal("the in-scope leaf must not have run either — the whole plan is halted")
	}
}

// TestRunPlan_OnOutOfScope_NotCalledWhenEveryLeafInScope confirms the gate is
// silent for a clean plan (the normal case — registry.Resolve only builds
// in-scope leaves).
func TestRunPlan_OnOutOfScope_NotCalledWhenEveryLeafInScope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sc, err := scope.New([]string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{
		{ID: "a", Target: server.URL, Detector: "misconfig"},
	}}}
	baseCfg := scanner.Config{Scope: sc, Concurrency: 1, RateLimit: 50, Timeout: 3 * time.Second, OutputFormat: "json"}

	called := false
	opts := testOpts()
	opts.OnOutOfScope = func([]string) error { called = true; return fmt.Errorf("should not fire") }

	if _, _, _, err := RunPlan(context.Background(), tree, baseCfg, nil, opts); err != nil {
		t.Fatalf("RunPlan: %v", err)
	}
	if called {
		t.Fatal("OnOutOfScope must not fire when every leaf is in scope")
	}
	if tree.Find("a").Status != agenttask.StatusDone {
		t.Fatal("the in-scope leaf should have dispatched normally")
	}
}

// slowServer returns an httptest server that sleeps delay before every
// response (200) — the injected per-request latency the timing test below
// measures parallelism against.
func slowServer(t *testing.T, delay time.Duration) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(delay)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(s.Close)
	return s
}

// TestRunPlan_MultiLeafRunsInParallel is doc15 Open Issue #4 / the Step 2
// DoD line "not yet live-confirmed with a real multi-leaf timing check
// (elapsed time close to the slowest single leaf)". Four builtin-capability
// leaves, each a one-request template against its own server that sleeps
// 300ms per request, dispatched with DetConcurrency 4: wall-clock must stay
// close to one leaf, not the 4x a serial dispatch would cost.
func TestRunPlan_MultiLeafRunsInParallel(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	const (
		delay  = 300 * time.Millisecond
		nLeaf  = 4
		tmplID = "slowprobe"
	)
	dir := writeOneTemplate(t, tmplID, http.StatusOK)
	index := []templatesync.Entry{{ID: tmplID}}
	baseCfg := scanner.Config{TemplatePaths: []string{dir}, Concurrency: 1, RateLimit: 50, Timeout: 5 * time.Second, OutputFormat: "json"}

	run := func(n int) time.Duration {
		children := make([]*agenttask.PlanNode, n)
		for i := 0; i < n; i++ {
			children[i] = &agenttask.PlanNode{ID: fmt.Sprintf("leaf-%d", i), Target: slowServer(t, delay).URL, Detector: tmplID}
		}
		tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: children}}
		opts := ExecOptions{DetConcurrency: nLeaf, LLMConcurrency: nLeaf}
		start := time.Now()
		if _, _, skipped, err := RunPlan(context.Background(), tree, baseCfg, index, opts); err != nil || len(skipped) != 0 {
			t.Fatalf("RunPlan(n=%d): err=%v skipped=%v", n, err, skipped)
		}
		return time.Since(start)
	}

	one := run(1)
	many := run(nLeaf)
	t.Logf("1 leaf: %s | %d leaves: %s | serial would be ~%s", one, nLeaf, many, time.Duration(nLeaf)*one)

	// Genuine parallelism: nLeaf leaves finish in well under 2x a single
	// leaf. A serial dispatch would be ~nLeaf x one (~4x here).
	if many > 2*one {
		t.Fatalf("multi-leaf wall-clock %s exceeds 2x the single-leaf time %s — leaves are not running in parallel", many, one)
	}
}

// --- C7 (doc16 Phase 7 Step 3, ph7-step3b) ---

// TestRunPlan_SkipsVetoedLeaf: a StatusVetoed leaf (C7b's "drop" verdict)
// is reported in skipped with the veto reason and never dispatched.
func TestRunPlan_SkipsVetoedLeaf(t *testing.T) {
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{
		{ID: "vetoed", Target: "http://127.0.0.1:1", Detector: "misconfig", Status: agenttask.StatusVetoed,
			Rationale: "plausibility veto (dropped): premise is an SPA catch-all"},
		{ID: "live", Target: "http://127.0.0.1:1", Detector: "misconfig", Status: agenttask.StatusPending},
	}}}
	baseCfg := scanner.Config{Concurrency: 1, RateLimit: 50, Timeout: 2 * time.Second, OutputFormat: "json"}

	_, _, skipped, _ := RunPlan(context.Background(), tree, baseCfg, nil, testOpts())

	var found bool
	for _, s := range skipped {
		if strings.Contains(s, "vetoed") && strings.Contains(s, "plausibility veto") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the vetoed leaf in skipped with its reason; got %v", skipped)
	}
	if tree.Find("vetoed").Status != agenttask.StatusVetoed {
		t.Fatalf("a skipped vetoed leaf must keep StatusVetoed, got %q", tree.Find("vetoed").Status)
	}
}

// TestEndpointSeedFromFindings: URLs pulled from a completed leaf's findings
// seed a same-host idor leaf's EndpointTemplate and a same-host ssrf leaf's
// params; a cross-host candidate is never seeded.
func TestEndpointSeedFromFindings(t *testing.T) {
	done := &agenttask.PlanNode{ID: "m1", Target: "http://h.test", Detector: "misconfig"}
	findings := []detectors.Finding{
		{ID: "f1", Type: "misconfig", Target: "http://h.test/api/orders/42"},
		{ID: "f2", Type: "misconfig", Target: "http://h.test/fetch", Evidence: map[string]string{"observed_url": "http://h.test/fetch?dest=https://internal.h.test/x"}},
	}
	candidates := []*agenttask.PlanNode{
		{ID: "l-idor", Target: "http://h.test", Detector: "idor", Status: agenttask.StatusPending},
		{ID: "l-ssrf", Target: "http://h.test", Detector: "ssrf", Status: agenttask.StatusPending},
		{ID: "l-idor-other", Target: "http://other.test", Detector: "idor", Status: agenttask.StatusPending},
	}

	seeds := EndpointSeedFromFindings(done, findings, candidates)

	byTarget := map[string]LeafSeed{}
	for _, s := range seeds {
		byTarget[s.TargetLeafID] = s
	}
	if s, ok := byTarget["l-idor"]; !ok || !strings.Contains(s.EndpointTemplate, "{{id}}") {
		t.Fatalf("expected an idor seed with an {{id}}-templated endpoint, got %+v", byTarget["l-idor"])
	}
	if s, ok := byTarget["l-ssrf"]; !ok || len(s.SSRFParams) == 0 {
		t.Fatalf("expected an ssrf seed with params, got %+v", byTarget["l-ssrf"])
	}
	if _, ok := byTarget["l-idor-other"]; ok {
		t.Fatal("a cross-host candidate must never be seeded")
	}
}

// TestRunPlan_SeedFillsBlankEndpoint_DeferredGate: an idor leaf with no
// EndpointTemplate is normally skipped pre-dispatch; with a SeedFn that
// supplies one from an earlier same-host leaf, the pre-dispatch gate is
// deferred and the leaf runs instead.
func TestRunPlan_SeedFillsBlankEndpoint_DeferredGate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer srv.Close()

	newTree := func() *agenttask.PlanTree {
		return &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{
			{ID: "m1", Target: srv.URL, Detector: "misconfig", Status: agenttask.StatusPending, Priority: agenttask.PriorityHigh},
			{ID: "i1", Target: srv.URL, Detector: "idor", Status: agenttask.StatusPending, Priority: agenttask.PriorityLow},
		}}}
	}
	baseCfg := scanner.Config{Concurrency: 1, RateLimit: 50, Timeout: 3 * time.Second, OutputFormat: "json"}

	idorSkipped := func(skipped []string) bool {
		for _, s := range skipped {
			if strings.HasPrefix(s, "i1:") {
				return true
			}
		}
		return false
	}

	// Control: no SeedFn -> i1 skipped for the missing field, pre-dispatch.
	_, _, skipped, _ := RunPlan(context.Background(), newTree(), baseCfg, nil, ExecOptions{DetConcurrency: 1, LLMConcurrency: 1})
	if !idorSkipped(skipped) {
		t.Fatalf("without a SeedFn the endpoint-less idor leaf must be skipped; got %v", skipped)
	}

	// With a SeedFn seeding i1 from m1's completion, the deferred gate passes.
	seedFn := func(d *agenttask.PlanNode, _ []detectors.Finding, cands []*agenttask.PlanNode) []LeafSeed {
		if d.ID != "m1" {
			return nil
		}
		var out []LeafSeed
		for _, c := range cands {
			if c.Detector == "idor" {
				out = append(out, LeafSeed{TargetLeafID: c.ID, EndpointTemplate: "/item/{{id}}"})
			}
		}
		return out
	}
	_, _, skipped, _ = RunPlan(context.Background(), newTree(), baseCfg, nil, ExecOptions{DetConcurrency: 1, LLMConcurrency: 1, SeedFn: seedFn})
	if idorSkipped(skipped) {
		t.Fatalf("with a SeedFn supplying the endpoint, the idor leaf must run, not skip; got %v", skipped)
	}
}

// TestRunPlan_LeafEndpointTemplate_RunsWithoutSeedOrLLM covers LT-91: an
// idor leaf that carries its own EndpointTemplate (registry's per-candidate
// fan-out) passes the pre-dispatch gate and enumerates that template — no
// SeedFn, no baseCfg endpoint, no LLM.
func TestRunPlan_LeafEndpointTemplate_RunsWithoutSeedOrLLM(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{
		{ID: "i-orders", Target: srv.URL, Detector: "idor", Status: agenttask.StatusPending,
			EndpointTemplate: "/orders/{{id}}"},
		{ID: "i-bare", Target: srv.URL, Detector: "idor", Status: agenttask.StatusPending},
	}}}
	baseCfg := scanner.Config{Concurrency: 1, RateLimit: 200, Timeout: 3 * time.Second, OutputFormat: "json"}

	_, _, skipped, err := RunPlan(context.Background(), tree, baseCfg, nil, ExecOptions{DetConcurrency: 1, LLMConcurrency: 1})
	if err != nil {
		t.Fatalf("RunPlan: %v", err)
	}

	// The bare leaf (no template anywhere) is still skipped; the templated one runs.
	bareSkipped, templatedSkipped := false, false
	for _, s := range skipped {
		if strings.HasPrefix(s, "i-bare:") {
			bareSkipped = true
		}
		if strings.HasPrefix(s, "i-orders:") {
			templatedSkipped = true
		}
	}
	if !bareSkipped {
		t.Fatalf("the endpoint-less idor leaf must still be skipped; got %v", skipped)
	}
	if templatedSkipped {
		t.Fatalf("the leaf carrying its own EndpointTemplate must run, not skip; got %v", skipped)
	}

	mu.Lock()
	defer mu.Unlock()
	hitTemplated := false
	for _, p := range paths {
		if strings.HasPrefix(p, "/orders/") {
			hitTemplated = true
		}
	}
	if !hitTemplated {
		t.Fatalf("expected the idor enumeration to request /orders/<id>; saw %v", paths)
	}
}

// TestRunPlan_LeafProtectedPaths_RunsWithoutBaseCfgPreFill covers LT-94: an
// endpoint-driven authbypass leaf that carries its own ProtectedPaths on the
// PlanNode passes the pre-dispatch gate and probes them — no baseCfg
// pre-fill by the caller, no SeedFn, no LLM.
func TestRunPlan_LeafProtectedPaths_RunsWithoutBaseCfgPreFill(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusOK) // 200 with no auth -> a missing-auth finding
	}))
	defer srv.Close()

	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{
		{ID: "ab", Target: srv.URL, Detector: "authbypass", Status: agenttask.StatusPending,
			ProtectedPaths: []string{"/admin/settings", "/api/private"}},
		{ID: "ab-bare", Target: srv.URL, Detector: "authbypass", Status: agenttask.StatusPending},
	}}}
	baseCfg := scanner.Config{Concurrency: 1, RateLimit: 200, Timeout: 3 * time.Second, OutputFormat: "json"}

	findings, _, skipped, err := RunPlan(context.Background(), tree, baseCfg, nil, ExecOptions{DetConcurrency: 1, LLMConcurrency: 1})
	if err != nil {
		t.Fatalf("RunPlan: %v", err)
	}

	bareSkipped, carriedSkipped := false, false
	for _, s := range skipped {
		if strings.HasPrefix(s, "ab-bare:") {
			bareSkipped = true
		}
		if strings.HasPrefix(s, "ab:") {
			carriedSkipped = true
		}
	}
	if !bareSkipped {
		t.Fatalf("the authbypass leaf with no protected paths anywhere must still be skipped; got %v", skipped)
	}
	if carriedSkipped {
		t.Fatalf("the leaf carrying its own ProtectedPaths must run, not skip; got %v", skipped)
	}

	mu.Lock()
	defer mu.Unlock()
	hitAdmin := false
	for _, p := range paths {
		if p == "/admin/settings" {
			hitAdmin = true
		}
	}
	if !hitAdmin {
		t.Fatalf("expected authbypass to probe /admin/settings; saw %v", paths)
	}
	if len(findings) == 0 {
		t.Fatalf("expected a missing-auth finding from the 200-without-auth endpoint")
	}
}

// TestRunPlan_HigherPriorityDispatchedFirst: with DetConcurrency 1 the pool
// runs leaves in submit order, which C7a sorts by descending Priority.
func TestRunPlan_HigherPriorityDispatchedFirst(t *testing.T) {
	var (
		mu    sync.Mutex
		order []string
		seen  = map[string]bool{}
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		for _, tag := range []string{"/p10", "/p20", "/p30"} {
			if strings.HasPrefix(r.URL.Path, tag) && !seen[tag] {
				seen[tag] = true
				order = append(order, tag)
			}
		}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{
		{ID: "l10", Target: srv.URL + "/p10", Detector: "misconfig", Status: agenttask.StatusPending, Priority: 10},
		{ID: "l30", Target: srv.URL + "/p30", Detector: "misconfig", Status: agenttask.StatusPending, Priority: 30},
		{ID: "l20", Target: srv.URL + "/p20", Detector: "misconfig", Status: agenttask.StatusPending, Priority: 20},
	}}}
	baseCfg := scanner.Config{Concurrency: 1, RateLimit: 50, Timeout: 3 * time.Second, OutputFormat: "json"}

	if _, _, skipped, err := RunPlan(context.Background(), tree, baseCfg, nil, ExecOptions{DetConcurrency: 1, LLMConcurrency: 1}); err != nil || len(skipped) != 0 {
		t.Fatalf("RunPlan: err=%v skipped=%v", err, skipped)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(order) != 3 || order[0] != "/p30" || order[1] != "/p20" || order[2] != "/p10" {
		t.Fatalf("leaves did not run in descending-priority order: %v", order)
	}
}
