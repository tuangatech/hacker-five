//go:build eval

package eval

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/detectors"
)

// expectedFindings mirrors the shape of tests/fixtures/expected-findings/*.json.
type expectedFindings struct {
	Description        string   `json:"description"`
	ExpectedIDPrefixes []string `json:"expected_id_prefixes"`
}

// binPath is the hackerfive binary built once by TestMain, shared by every
// Scenario in TestEvalHarness.
var binPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "hackerfive-eval-*")
	if err != nil {
		panic(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	binPath = filepath.Join(dir, "hackerfive")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-o", binPath, "./cmd/hackerfive")
	build.Dir = repoRoot()
	if out, err := build.CombinedOutput(); err != nil {
		panic("building hackerfive for eval harness: " + err.Error() + "\n" + string(out))
	}

	os.Exit(m.Run())
}

// repoRoot walks up from the test binary's working directory (tests/eval)
// to the repo root, so `go build ./cmd/hackerfive` resolves regardless of
// which directory `go test` was invoked from.
func repoRoot() string {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	return filepath.Join(wd, "..", "..")
}

// TestEvalHarness is Phase 5 Step 1's "G1" eval harness stub
// (docs/14-implementation-plan-ph5.md): it runs the real hackerfive scan
// CLI against each live lab target already used throughout this project,
// and grades the result as a fixed, binary pass/fail challenge set — one
// challenge per expected_id_prefixes entry in that target's existing
// tests/fixtures/expected-findings/*.json fixture. No agent is involved;
// this only proves the harness mechanism and produces today's detector-only
// baseline, per doc14's own framing.
func TestEvalHarness(t *testing.T) {
	for _, sc := range Scenarios {
		sc := sc
		t.Run(sc.Name, func(t *testing.T) {
			for _, envVar := range sc.RequiredEnv {
				if os.Getenv(envVar) == "" {
					t.Skipf("%s not set — skipping (see docs/20-setup-testing-targets.md)", envVar)
				}
			}

			var expected expectedFindings
			expectedRaw, err := os.ReadFile(filepath.Join(repoRoot(), sc.ExpectedFile))
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(expectedRaw, &expected))

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			cmd := exec.CommandContext(ctx, binPath, sc.Args()...)
			cmd.Dir = repoRoot()
			out, _ := cmd.Output() // a scan finding nothing still exits 0; treat as "[]" below

			var findings []detectors.Finding
			trimmed := strings.TrimSpace(string(out))
			if trimmed != "" {
				require.NoError(t, json.Unmarshal([]byte(trimmed), &findings), "scan output: %s", trimmed)
			}

			unexpected := 0
			for _, f := range findings {
				if !matchesAnyPrefix(f.ID, expected.ExpectedIDPrefixes) {
					unexpected++
				}
			}
			t.Logf("%s: %d findings, %d unexpected (candidate FPs) — baseline, not a gate", sc.Name, len(findings), unexpected)

			for _, prefix := range expected.ExpectedIDPrefixes {
				prefix := prefix
				t.Run("finds_"+strconv.Quote(prefix), func(t *testing.T) {
					if contains(sc.SkipPrefixes, prefix) {
						t.Skipf("%q intentionally not exercised by this Scenario's Args — see its comment in challenges.go", prefix)
					}
					if !anyHasPrefix(findings, prefix) {
						t.Errorf("no finding with ID prefix %q — expected per %s", prefix, sc.ExpectedFile)
					}
				})
			}
		})
	}
}

func matchesAnyPrefix(id string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(id, p) {
			return true
		}
	}
	return false
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func anyHasPrefix(findings []detectors.Finding, prefix string) bool {
	for _, f := range findings {
		if strings.HasPrefix(f.ID, prefix) {
			return true
		}
	}
	return false
}
