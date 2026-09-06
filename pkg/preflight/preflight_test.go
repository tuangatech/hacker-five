package preflight

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writePolicy(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "policy.yaml")
	require.NoError(t, os.WriteFile(p, []byte(body), 0o644))
	return p
}

const samplePolicy = `
targets:
  - match: "*.blocked.example"
    automated_scanning: disallowed
    notes: "policy bans scanners"
  - match: "capped.example"
    automated_scanning: allowed
    max_runs_per_day: 5
  - match: "*.maybe.example"
    automated_scanning: unknown
`

// TestCheck_Disallowed_HardFails: a target matching a disallowed entry makes
// Check return an error, and the caller must not run.
func TestCheck_Disallowed_HardFails(t *testing.T) {
	_, err := Check([]string{"https://api.blocked.example/x"}, Options{PolicyPath: writePolicy(t, samplePolicy)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disallows automated scanning")
	assert.Contains(t, err.Error(), "api.blocked.example")
}

// TestCheck_Disallowed_OverrideDowngradesToWarning: --allow-policy-override
// turns the hard error into a loud warning.
func TestCheck_Disallowed_OverrideDowngradesToWarning(t *testing.T) {
	warns, err := Check([]string{"https://api.blocked.example"}, Options{PolicyPath: writePolicy(t, samplePolicy), Override: true})
	require.NoError(t, err)
	assert.True(t, containsSubstr(warns, "OVERRIDE"), "override must surface a loud warning: %v", warns)
}

// TestCheck_Unknown_WarnsAndProceeds: a target with no matching entry (or an
// explicit unknown) warns but never blocks.
func TestCheck_Unknown_WarnsAndProceeds(t *testing.T) {
	path := writePolicy(t, samplePolicy)
	for _, target := range []string{"https://nowhere.example", "https://staging.maybe.example"} {
		warns, err := Check([]string{target}, Options{PolicyPath: path})
		require.NoError(t, err)
		assert.True(t, containsSubstr(warns, "no entry in "), "unknown verdict must warn: %v", warns)
	}
}

// TestCheck_NoPolicyFile_WarnsAndProceeds: absent PolicyPath is not an error,
// every target is Unknown, and a single softer warning is emitted.
func TestCheck_NoPolicyFile_WarnsAndProceeds(t *testing.T) {
	warns, err := Check([]string{"https://anything.example"}, Options{})
	require.NoError(t, err)
	assert.True(t, containsSubstr(warns, "no policy file given"), "%v", warns)
}

// TestCheck_MissingPolicyFile_TreatedAsAbsent: a PolicyPath that doesn't exist
// on disk degrades to "no declarations", not an error.
func TestCheck_MissingPolicyFile_TreatedAsAbsent(t *testing.T) {
	_, err := Check([]string{"https://anything.example"}, Options{PolicyPath: filepath.Join(t.TempDir(), "nope.yaml")})
	require.NoError(t, err)
}

// TestCheck_MalformedPolicyFile_IsAnError: a present-but-corrupt policy must
// not silently degrade to no-enforcement.
func TestCheck_MalformedPolicyFile_IsAnError(t *testing.T) {
	_, err := Check([]string{"https://x.example"}, Options{PolicyPath: writePolicy(t, "targets: [ this is not valid")})
	require.Error(t, err)
}

// TestCheck_Allowed_SurfacesRunCap: an allowed entry with max_runs_per_day
// emits an advisory reminder (HackerFive can't enforce it).
func TestCheck_Allowed_SurfacesRunCap(t *testing.T) {
	warns, err := Check([]string{"https://capped.example"}, Options{PolicyPath: writePolicy(t, samplePolicy)})
	require.NoError(t, err)
	assert.True(t, containsSubstr(warns, "5 run(s)/day"), "%v", warns)
}

// TestCheck_LabTarget_Skipped: a loopback/private/localhost target is never
// checked, even against a disallow-all policy.
func TestCheck_LabTarget_Skipped(t *testing.T) {
	path := writePolicy(t, "targets:\n  - match: \"0.0.0.0/0\"\n    automated_scanning: disallowed\n")
	for _, target := range []string{"http://127.0.0.1:8080", "http://localhost:3000", "http://192.168.1.10", "http://10.0.0.5/app"} {
		warns, err := Check([]string{target}, Options{PolicyPath: path})
		require.NoError(t, err, target)
		assert.Empty(t, warns, "a lab target must produce no policy warnings: %s -> %v", target, warns)
	}
}

// TestVerdict_FirstMatchWins: entries are consulted in file order.
func TestVerdict_FirstMatchWins(t *testing.T) {
	ps, err := Load(writePolicy(t, `
targets:
  - match: "special.blocked.example"
    automated_scanning: allowed
  - match: "*.blocked.example"
    automated_scanning: disallowed
`))
	require.NoError(t, err)

	v, _ := ps.Verdict("https://special.blocked.example")
	assert.Equal(t, VerdictAllowed, v, "the more specific earlier entry wins")
	v, _ = ps.Verdict("https://other.blocked.example")
	assert.Equal(t, VerdictDisallowed, v)
}

// TestVerdict_BareDomainTarget: a scheme-less target still resolves.
func TestVerdict_BareDomainTarget(t *testing.T) {
	ps, err := Load(writePolicy(t, samplePolicy))
	require.NoError(t, err)
	v, _ := ps.Verdict("api.blocked.example")
	assert.Equal(t, VerdictDisallowed, v)
}

func TestSignalWarnings(t *testing.T) {
	assert.Nil(t, SignalWarnings(nil))

	w := SignalWarnings(&Signals{RobotsDisallowAll: true})
	assert.True(t, containsSubstr(w, "robots.txt disallows all crawling"))

	w = SignalWarnings(&Signals{SecurityTxt: "Contact: mailto:x@y.z\nPolicy: https://y.z/policy\n"})
	assert.True(t, containsSubstr(w, "links a disclosure Policy"))

	w = SignalWarnings(&Signals{SecurityTxt: "Note: automated scanning is not permitted against production."})
	assert.True(t, containsSubstr(w, "restricting automated scanning"))
}

// TestRequestHeaders_ParsedIntoMap: a `request_headers:` list is exposed as
// a name->value map, colon-split and trimmed (LT-36).
func TestRequestHeaders_ParsedIntoMap(t *testing.T) {
	ps, err := Load(writePolicy(t, `
request_headers:
  - "X-Hackerone: tonytran"
  - "X-Trace:   abc123  "
targets:
  - match: "example.com"
    automated_scanning: allowed
`))
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"X-Hackerone": "tonytran", "X-Trace": "abc123"}, ps.RequestHeaders())
}

func TestRequestHeaders_AbsentOrNilSet_ReturnsNil(t *testing.T) {
	ps, err := Load(writePolicy(t, samplePolicy))
	require.NoError(t, err)
	assert.Nil(t, ps.RequestHeaders())

	var nilSet *PolicySet
	assert.Nil(t, nilSet.RequestHeaders())
}

func TestRequestHeaders_MalformedEntry_IsAnError(t *testing.T) {
	_, err := Load(writePolicy(t, "request_headers:\n  - \"no-colon-here\"\n"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), `must be in "Name: Value" form`)
}

func containsSubstr(hay []string, needle string) bool {
	for _, s := range hay {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}
