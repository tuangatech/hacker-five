package unit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/template/nuclei"
)

// TestNucleiPromptInjectionSamples_LoadFirstPartyTemplates is a regression
// test against templates/nuclei-samples/promptinjection/ (see that
// directory's README for what each template checks, its AIGoat test-target
// provenance, and live-verification status). Only checks load behavior —
// deterministic, no live target needed; live-run results still need
// confirming against a real target, per that README.
func TestNucleiPromptInjectionSamples_LoadFirstPartyTemplates(t *testing.T) {
	templates, errs := nuclei.LoadDir("../../templates/nuclei-samples/promptinjection")

	require.Empty(t, errs)

	require.Len(t, templates, 2)
	var ids []string
	for _, tmpl := range templates {
		ids = append(ids, tmpl.ID)
	}
	assert.ElementsMatch(t, []string{"prompt-injection-system-prompt-leak", "prompt-injection-seeded-secret-exfil-lab"}, ids)
}
