package reporter

import (
	"html/template"
	"io"

	"github.com/tuangatech/hacker-five/pkg/detectors"
)

// htmlReportTemplate renders the same content as markdownExporter, styled as
// a single self-contained HTML file (inline <style>, no external assets —
// consistent with this project's no-new-dependency discipline). Evidence and
// description are rendered through html/template's default auto-escaping,
// which matters here specifically: Finding.Evidence routinely contains
// attacker-controlled payload text (e.g. an XSS/SSRF probe's own request
// body) that must not be interpreted as live HTML in the report itself.
var htmlReportTemplate = template.Must(template.New("report").Parse(`<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>HackerFive Scan Report</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 960px; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; }
table { border-collapse: collapse; margin-bottom: 2rem; }
th, td { border: 1px solid #ccc; padding: 0.4rem 0.8rem; text-align: left; }
.finding { border: 1px solid #ddd; border-radius: 6px; padding: 1rem; margin-bottom: 1rem; }
.sev-critical { border-left: 6px solid #b91c1c; }
.sev-high { border-left: 6px solid #ea580c; }
.sev-medium { border-left: 6px solid #ca8a04; }
.sev-low { border-left: 6px solid #16a34a; }
.meta { color: #555; font-size: 0.9em; }
pre { background: #f5f5f5; padding: 0.75rem; overflow-x: auto; white-space: pre-wrap; word-break: break-word; }
</style>
</head>
<body>
<h1>HackerFive Scan Report</h1>
<p>{{len .Findings}} finding(s)</p>
{{if .Findings}}
<table>
<tr><th>Severity</th><th>Count</th></tr>
{{range .SeverityRows}}<tr><td>{{.Severity}}</td><td>{{.Count}}</td></tr>
{{end}}
</table>
{{range .Findings}}
<div class="finding sev-{{.Severity}}">
<h2>[{{.Severity}}] {{.Type}} — {{.Target}}</h2>
<p class="meta">ID: <code>{{.ID}}</code> · Confidence: {{.Confidence}}</p>
{{if .Description}}<p>{{.Description}}</p>{{end}}
{{range .EvidenceRows}}<h3>{{.Key}}</h3><pre>{{.Value}}</pre>
{{end}}
</div>
{{end}}
{{end}}
</body>
</html>
`))

type htmlSeverityRow struct {
	Severity string
	Count    int
}

type htmlEvidenceRow struct {
	Key, Value string
}

type htmlFinding struct {
	detectors.Finding
	EvidenceRows []htmlEvidenceRow
}

type htmlReportData struct {
	Findings     []htmlFinding
	SeverityRows []htmlSeverityRow
}

type htmlExporter struct{}

func (htmlExporter) Export(w io.Writer, findings []detectors.Finding) error {
	data := htmlReportData{}

	counts := severityCounts(findings)
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		if n := counts[sev]; n > 0 {
			data.SeverityRows = append(data.SeverityRows, htmlSeverityRow{Severity: sev, Count: n})
		}
	}

	for _, f := range sortBySeverity(findings) {
		hf := htmlFinding{Finding: f}
		for _, key := range sortedEvidenceKeys(f.Evidence) {
			hf.EvidenceRows = append(hf.EvidenceRows, htmlEvidenceRow{Key: key, Value: f.Evidence[key]})
		}
		data.Findings = append(data.Findings, hf)
	}

	return htmlReportTemplate.Execute(w, data)
}
