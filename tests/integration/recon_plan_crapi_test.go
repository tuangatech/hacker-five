//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/registry"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
	"github.com/tuangatech/hacker-five/pkg/templatesync"
)

// templateIndexFile mirrors cmd/hackerfive/templates.go's and
// pkg/webui/handlers_plan.go's own type of the same name — the on-disk
// shape of templates/index.json. Duplicated locally rather than imported,
// since tests/integration can import neither package main
// (cmd/hackerfive) nor pkg/webui's unexported loader; same small,
// proportionate duplication doc14 Step 4 already established across that
// boundary.
type templateIndexFile struct {
	GeneratedAt time.Time            `json:"generated_at"`
	Templates   []templatesync.Entry `json:"templates"`
}

// loadTemplateIndex reads path relative to the repo root. A missing file
// returns (nil, err) — callers degrade to skipping template-tag-leaf
// assertions, same graceful posture as cmd/hackerfive/plan.go and
// pkg/webui/handlers_plan.go: an unsynced corpus is a real, named
// possibility in CI, never a hard test failure.
func loadTemplateIndex(path string) ([]templatesync.Entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f templateIndexFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	return f.Templates, nil
}

// flattenPlanTree walks tree depth-first into a flat leaf slice — the same
// shape both new recon/plan integration tests inspect, since PlanTree only
// nests two levels deep in practice (root -> host -> leaf) but nothing
// guarantees that structurally.
func flattenPlanTree(tree *agenttask.PlanTree) []*agenttask.PlanNode {
	var out []*agenttask.PlanNode
	var walk func(n *agenttask.PlanNode)
	walk = func(n *agenttask.PlanNode) {
		if n == nil {
			return
		}
		out = append(out, n)
		for _, c := range n.Children {
			walk(c)
		}
	}
	walk(tree.Root)
	return out
}

// pendingDetectors returns the set of Detector names among StatusPending
// leaves in leaves.
func pendingDetectors(leaves []*agenttask.PlanNode) map[string]bool {
	set := make(map[string]bool)
	for _, n := range leaves {
		if n.Status == agenttask.StatusPending && n.Detector != "" {
			set[n.Detector] = true
		}
	}
	return set
}

// unresolvedRationales returns every StatusUnresolved leaf's Rationale.
func unresolvedRationales(leaves []*agenttask.PlanNode) []string {
	var out []string
	for _, n := range leaves {
		if n.Status == agenttask.StatusUnresolved {
			out = append(out, n.Rationale)
		}
	}
	return out
}

// TestReconAndPlan_AgainstCRAPI turns doc14 Step 3/4's manual
// crAPI verification into a permanent regression test: real pkg/recon at
// active depth, schema-validated, then real registry.Resolve. Opt-in via
// CRAPI_BASE_URL, same convention idor_crapi_test.go already uses — skipped
// rather than failed when crAPI isn't running.
func TestReconAndPlan_AgainstCRAPI(t *testing.T) {
	baseURL := os.Getenv("CRAPI_BASE_URL")
	if baseURL == "" {
		t.Skip("set CRAPI_BASE_URL to run this test (e.g. http://localhost:8888)")
	}

	schemaPath, err := filepath.Abs(filepath.Join("..", "..", "docs", "schema", "recon-result.schema.json"))
	require.NoError(t, err)
	schema, err := jsonschema.Compile(schemaPath)
	require.NoError(t, err)

	client := httpclient.New(httpclient.Config{Timeout: 15 * time.Second, MaxRedirects: 5})
	r := recon.New(client)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	result, err := r.Run(ctx, baseURL, recon.DepthActive)
	require.NoError(t, err)
	require.NotEmpty(t, result.TechStack, "expected at least one tech fact from crAPI's real httpx/fingerprint signals")

	raw, err := json.Marshal(result)
	require.NoError(t, err)
	var asAny any
	require.NoError(t, json.Unmarshal(raw, &asAny))
	assert.NoError(t, schema.Validate(asAny), "ReconResult must satisfy docs/schema/recon-result.schema.json: %s", raw)

	index, err := loadTemplateIndex(filepath.Join("..", "..", "templates", "index.json"))
	if err != nil {
		t.Logf("templates/index.json not available (%v) — template-tag-leaf assertions skipped, registry-capability assertions still run", err)
	}

	tree := registry.Resolve(result, index)
	leaves := flattenPlanTree(tree)

	detectors := pendingDetectors(leaves)
	assert.True(t, detectors["misconfig"], "expected a pending misconfig leaf from crAPI's OpenResty/PHP tech facts, got detectors: %v", detectors)
	assert.True(t, detectors["idor"], "expected a pending idor leaf from crAPI's OpenResty tech fact, got detectors: %v", detectors)
	assert.True(t, detectors["authbypass"], "expected a pending authbypass leaf from crAPI's OpenResty tech fact, got detectors: %v", detectors)

	// Which tech facts go unresolved (Debian, crAPI's own favicon match, ...)
	// varies run-to-run — live httpx tech-detect against a live container
	// isn't perfectly deterministic (found empirically running this test:
	// one real run reported only crAPI's favicon match unresolved, a
	// separate manual run the same session reported both Debian and crAPI).
	// The structural guarantee this test actually needs to prove is
	// Decision 6's: an unmatched tech fact stays a visible, inspectable
	// leaf rather than being silently dropped — not which exact tech name
	// triggers it on any given run.
	unresolved := unresolvedRationales(leaves)
	assert.NotEmpty(t, unresolved, "expected at least one visible unresolved leaf — crAPI's real tech stack always has something the registry doesn't map (e.g. Debian, or crAPI's own favicon match)")
	t.Logf("unresolved leaves this run: %v", unresolved)
}
