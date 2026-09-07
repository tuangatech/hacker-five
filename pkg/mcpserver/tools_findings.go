package mcpserver

import (
	"bytes"
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/reporter"
)

// findingsExportInput's Findings are echoed back by the caller (typically
// scan's own output) — this package holds no cross-call job state in Step
// 1, so export operates on whatever finding list it's handed, the same way
// `hackerfive scan -o` always has (doc13 Step 4's Exporter work).
type findingsExportInput struct {
	Findings []detectors.Finding `json:"findings"`
	Format   string              `json:"format,omitempty" jsonschema:"one of json (default), markdown, html, hackerone-json"`
	// CitedFindingIDs enforces C3's evidence-linked claims (doc16 Phase 7
	// Step 3): if the coordinator is drafting narrative report text alongside
	// this export, it passes every Finding.ID that text cites here — the
	// export is rejected if any named ID is absent from findings, so a draft
	// can never reference evidence that does not exist. Empty = no claim to
	// check.
	CitedFindingIDs []string `json:"cited_finding_ids,omitempty" jsonschema:"Finding.ID values an accompanying agent-drafted narrative cites; every one must exist in findings or the export is rejected"`
	Reason          string   `json:"reason,omitempty" jsonschema:"optional — the coordinator's stated reason for this call; recorded verbatim in the session.log, advisory only"`
}

type findingsExportOutput struct {
	Content string `json:"content"`
}

func addFindingsExportTool(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "findings.export",
		Description: "Render a finding list to json, markdown, html, or hackerone-json via pkg/reporter's Exporter.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in findingsExportInput) (res *mcp.CallToolResult, out findingsExportOutput, err error) {
		finish := sessionLog.Begin("findings.export", in.Reason, exportParamsSummary(in))
		defer func() { finish(exportResultSummary(out), err) }()

		exporter, err := reporter.ExporterFor(in.Format)
		if err != nil {
			return nil, findingsExportOutput{}, err
		}
		if err := reporter.ValidateCitations(in.CitedFindingIDs, in.Findings); err != nil {
			return nil, findingsExportOutput{}, err
		}
		var buf bytes.Buffer
		if err := exporter.Export(&buf, in.Findings); err != nil {
			return nil, findingsExportOutput{}, err
		}
		return nil, findingsExportOutput{Content: buf.String()}, nil
	})
}
