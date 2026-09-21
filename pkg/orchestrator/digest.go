package orchestrator

import (
	"fmt"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/llmfallback"
	"github.com/tuangatech/hacker-five/pkg/recon"
)

// maxDigestWarnings / maxDigestWarningLen bound how much of recon's own
// warning list reaches the model: enough to tell it recon was thin or
// partial, not a transcript.
const (
	maxDigestWarnings   = 5
	maxDigestWarningLen = 160
)

// reconDigest accumulates the recon facts worth showing the model across the
// initial recon and every later recon.refresh (LT-171, docs/follow-up.md). The
// plan tree carries what registry.Resolve turned into leaves; this carries
// what recon actually observed, including what produced no leaf at all.
// Technology facts union across observations; every other field keeps its
// latest value.
type reconDigest struct {
	tech         []string
	techSeen     map[string]bool
	surface      string
	apiSpec      string
	endpoints    int
	endpointsOK  int
	secrets      int
	walls        []string
	warnings     []string
	haveObserved bool
}

func (d *reconDigest) observe(r *recon.ReconResult) {
	if r == nil {
		return
	}
	d.haveObserved = true
	if d.techSeen == nil {
		d.techSeen = map[string]bool{}
	}
	for _, t := range r.TechStack {
		line := fmt.Sprintf("tech: %s (%s, %s confidence)", t.Name, t.Host, t.Confidence)
		if !d.techSeen[line] {
			d.techSeen[line] = true
			d.tech = append(d.tech, line)
		}
	}

	d.surface = ""
	if r.AppSurface != nil {
		d.surface = fmt.Sprintf("app surface: %s — %s", r.AppSurface.Verdict, r.AppSurface.Reason)
	}
	d.apiSpec = ""
	if r.APISpec != nil {
		d.apiSpec = fmt.Sprintf("api spec: %s at %s", r.APISpec.Kind, r.APISpec.URL)
	}

	d.endpoints, d.endpointsOK = len(r.Endpoints), 0
	for _, e := range r.Endpoints {
		if e.StatusCode >= 200 && e.StatusCode < 300 {
			d.endpointsOK++
		}
	}
	d.secrets = len(r.Secrets)

	d.walls = d.walls[:0]
	for _, u := range r.UniformResponses {
		d.walls = append(d.walls, fmt.Sprintf("uniform response on %s: %s", u.Host, u.Kind))
	}

	d.warnings = d.warnings[:0]
	for _, w := range r.Warnings {
		if len(d.warnings) == maxDigestWarnings {
			break
		}
		if len(w) > maxDigestWarningLen {
			w = w[:maxDigestWarningLen] + "..."
		}
		d.warnings = append(d.warnings, "recon warning: "+w)
	}
}

// lines renders the digest as the one-fact-per-line list
// llmfallback.RunDigest.Recon carries.
func (d *reconDigest) lines() []string {
	if d == nil || !d.haveObserved {
		return nil
	}
	var out []string
	out = append(out, d.tech...)
	if d.surface != "" {
		out = append(out, d.surface)
	}
	if d.apiSpec != "" {
		out = append(out, d.apiSpec)
	}
	out = append(out, fmt.Sprintf("endpoints observed: %d (%d answered 2xx)", d.endpoints, d.endpointsOK))
	if d.secrets > 0 {
		out = append(out, fmt.Sprintf("hardcoded secrets flagged in served JavaScript: %d", d.secrets))
	}
	out = append(out, d.walls...)
	out = append(out, d.warnings...)
	return out
}

// buildRunDigest assembles NextAction's per-call RunDigest from the running
// recon digest and every distinct finding confirmed so far.
func buildRunDigest(rd *reconDigest, findings []detectors.Finding) llmfallback.RunDigest {
	digest := llmfallback.RunDigest{Recon: rd.lines()}
	for _, f := range findings {
		digest.Findings = append(digest.Findings, llmfallback.FindingDigest{
			ID: f.ID, Type: f.Type, Severity: f.Severity, Target: strings.TrimSpace(f.Target),
		})
	}
	return digest
}
