package webui

import (
	"html/template"
	"strings"
)

// stepDisplayNames maps the internal names WaveStatus.Name carries (pkg/recon's
// raw "wave0".."wave3", and scanner.Config.Detector's raw detector keys) to
// what a user should actually see — presentation-only, so pkg/recon and the
// detector-selection logic keep using their own plain internal names.
var stepDisplayNames = map[string]string{
	"wave0":         "Wave 0",
	"wave1":         "Wave 1",
	"wave2":         "Wave 2",
	"wave3":         "Wave 3",
	"misconfig":     "Misconfig",
	"idor":          "IDOR",
	"authbypass":    "Auth Bypass",
	"ssrf":          "SSRF",
	"businesslogic": "Business Logic",
}

func prettyStepName(raw string) string {
	if name, ok := stepDisplayNames[raw]; ok {
		return name
	}
	return raw
}

// stepChain renders one arrow-separated pipeline line (recon waves or the
// detector run order) — used by fragment_progress.html for both the "Recon:"
// and "Detectors:" lines. A step not yet reached ("pending") is muted, the
// currently running one is highlighted, and a finished one renders as normal
// text — the same running/done vocabulary pkg/recon.WithProgressCallback
// already uses, plus "pending" for a step this Job has pre-seeded but not
// yet started (see runLaunchJob).
func stepChain(steps []WaveStatus) template.HTML {
	if len(steps) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<span class="step-chain">`)
	for i, s := range steps {
		if i > 0 {
			b.WriteString(`<span class="step-arrow"> → </span>`)
		}
		class := "step-pending"
		switch s.Status {
		case "running":
			class = "step-running"
		case "done":
			class = "step-done"
		}
		b.WriteString(`<span class="`)
		b.WriteString(class)
		b.WriteString(`">`)
		b.WriteString(template.HTMLEscapeString(prettyStepName(s.Name)))
		b.WriteString(`</span>`)
	}
	b.WriteString(`</span>`)
	return template.HTML(b.String())
}
