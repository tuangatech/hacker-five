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

	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/registry"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
)

// TestReconAndPlan_AgainstDVWA is TestReconAndPlan_AgainstCRAPI's DVWA
// counterpart, closing the same doc14 Step 3/4 manual-verification gap for
// the second lab target. DVWA's real tech facts (Apache/PHP) only ever
// match the misconfig registry rule — unlike crAPI's OpenResty, nothing
// here maps to idor/authbypass, so this test doesn't assert either. Opt-in
// via DVWA_BASE_URL, same convention misconfig_dvwa_test.go already uses.
func TestReconAndPlan_AgainstDVWA(t *testing.T) {
	baseURL := os.Getenv("DVWA_BASE_URL")
	if baseURL == "" {
		t.Skip("set DVWA_BASE_URL to run this test (e.g. http://localhost:80)")
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
	require.NotEmpty(t, result.TechStack, "expected at least one tech fact from DVWA's real httpx/fingerprint signals")

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
	assert.True(t, detectors["misconfig"], "expected a pending misconfig leaf from DVWA's Apache/PHP tech facts, got detectors: %v", detectors)
	if index != nil {
		assert.True(t, detectors["php-detect"], "expected a real php-detect template-tag leaf once the corpus is synced, got detectors: %v", detectors)
	}

	// Same live-non-determinism caveat as TestReconAndPlan_AgainstCRAPI:
	// which exact tech fact goes unresolved can vary run-to-run, so this
	// only asserts the structural guarantee (a visible leaf exists), not a
	// specific tech name.
	unresolved := unresolvedRationales(leaves)
	assert.NotEmpty(t, unresolved, "expected at least one visible unresolved leaf — DVWA's real tech stack always has something the registry doesn't map (e.g. Debian)")
	t.Logf("unresolved leaves this run: %v", unresolved)
}
