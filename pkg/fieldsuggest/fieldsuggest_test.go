package fieldsuggest

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/recon"
)

func result(endpoints ...recon.EndpointFact) *recon.ReconResult {
	return &recon.ReconResult{Target: "https://example.com", Endpoints: endpoints}
}

// suggestionFor looks a suggestion up by field name so assertions read by name
// rather than slice index — order is not part of Deterministic's contract.
func suggestionFor(t *testing.T, got []agenttask.FieldSuggestion, field string) agenttask.FieldSuggestion {
	t.Helper()
	for _, s := range got {
		if s.Field == field {
			return s
		}
	}
	t.Fatalf("no suggestion for field %q in %+v", field, got)
	return agenttask.FieldSuggestion{}
}

func TestDeterministic_NilResult(t *testing.T) {
	sugs, misses := Deterministic(nil, map[string]bool{"idor": true})
	assert.Nil(t, sugs)
	assert.Nil(t, misses)
}

// TestDeterministic_GatedByWant: an idor endpoint is present but idor is not
// in want, so there is neither a suggestion nor a Miss — a caller that only
// runs I4 on returned misses never fires it for a detector with no leaf.
func TestDeterministic_GatedByWant(t *testing.T) {
	r := result(recon.EndpointFact{URL: "https://example.com/api/report?report_id=482"})

	sugs, misses := Deterministic(r, map[string]bool{"misconfig": true})

	assert.Empty(t, sugs)
	assert.Empty(t, misses)
}

func TestDeterministic_IdorSingleCandidate_AutoFills(t *testing.T) {
	r := result(recon.EndpointFact{URL: "https://example.com/api/report?report_id=482"})

	sugs, misses := Deterministic(r, map[string]bool{"idor": true})

	require.Len(t, sugs, 1)
	assert.Equal(t, "idor", sugs[0].Detector)
	assert.Equal(t, "endpoint_template", sugs[0].Field)
	assert.Equal(t, "/api/report?report_id={{id}}", sugs[0].SuggestedValue)
	assert.Empty(t, misses)
}

func TestDeterministic_IdorNoCandidate_IsAMiss(t *testing.T) {
	r := result(recon.EndpointFact{URL: "https://example.com/about"})

	sugs, misses := Deterministic(r, map[string]bool{"idor": true})

	assert.Empty(t, sugs)
	require.Len(t, misses, 1)
	assert.Equal(t, "idor", misses[0].Detector)
	assert.Equal(t, "endpoint_template", misses[0].Field)
}

func TestDeterministic_AuthbypassSingleProtected_AutoFills(t *testing.T) {
	r := result(
		recon.EndpointFact{URL: "https://example.com/admin", StatusCode: 403},
		recon.EndpointFact{URL: "https://example.com/login"},
		recon.EndpointFact{URL: "https://example.com/logout"},
	)

	sugs, misses := Deterministic(r, map[string]bool{"authbypass": true})

	assert.Empty(t, misses)
	assert.Equal(t, "/admin", suggestionFor(t, sugs, "protected_paths").SuggestedValue)
	assert.Equal(t, "/login", suggestionFor(t, sugs, "login_paths").Candidates[0])
	assert.Equal(t, "/logout", suggestionFor(t, sugs, "logout_paths").Candidates[0])
}

func TestDeterministic_AuthbypassNoProtected_IsAMiss(t *testing.T) {
	r := result(recon.EndpointFact{URL: "https://example.com/about"})

	_, misses := Deterministic(r, map[string]bool{"authbypass": true})

	require.Len(t, misses, 1)
	assert.Equal(t, "authbypass", misses[0].Detector)
	assert.Equal(t, "protected_paths", misses[0].Field)
}

func TestDeterministic_AuthbypassMultipleProtected_AllUsableNoMiss(t *testing.T) {
	r := result(
		recon.EndpointFact{URL: "https://example.com/admin", StatusCode: 403},
		recon.EndpointFact{URL: "https://example.com/settings", StatusCode: 401},
	)

	sugs, misses := Deterministic(r, map[string]bool{"authbypass": true})

	assert.Empty(t, misses)
	p := suggestionFor(t, sugs, "protected_paths")
	assert.Empty(t, p.SuggestedValue)
	assert.ElementsMatch(t, []string{"/admin", "/settings"}, p.Candidates)
}

func TestDeterministic_SSRFParams_AllUsableNoMiss(t *testing.T) {
	r := result(recon.EndpointFact{URL: "https://example.com/proxy?url=http://internal"})

	sugs, misses := Deterministic(r, map[string]bool{"ssrf": true})

	assert.Empty(t, misses)
	assert.Contains(t, suggestionFor(t, sugs, "ssrf_params").Candidates, "url")
}
