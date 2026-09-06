package mcpserver

import (
	"fmt"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
)

// The summarizers below feed pkg/agenttask.SessionLog.Begin. They
// deliberately drop every secret-bearing field — auth_token,
// other_auth_token, extra_headers — and keep only what's useful to
// reconstruct what the agent asked for. Result strings are one-liners:
// enough to scan the log, not a second copy of the tool output.

func scanParamsSummary(in scanInput) map[string]any {
	return map[string]any{
		"targets":       in.Targets,
		"scope":         in.Scope,
		"detector":      in.Detector,
		"tags":          in.Tags,
		"all_templates": in.AllTemplates,
	}
}

func scanResultSummary(out scanOutput) string {
	return fmt.Sprintf("%d finding(s), %d log line(s)", len(out.Findings), len(out.Logs))
}

func reconParamsSummary(in reconInput) map[string]any {
	return map[string]any{"target": in.Target, "scope": in.Scope, "depth": in.Depth}
}

func reconResultSummary(out reconOutput) string {
	if out.Result == nil {
		return "no result"
	}
	return fmt.Sprintf("%d tech fact(s), %d endpoint(s), %d host(s), %d out-of-scope",
		len(out.Result.TechStack), len(out.Result.Endpoints), len(out.Result.Hosts), len(out.Result.OutOfScope))
}

func planParamsSummary(in planInput) map[string]any {
	return map[string]any{
		"target":       in.Target,
		"scope":        in.Scope,
		"depth":        in.Depth,
		"allow_writes": in.AllowWrites,
	}
}

func planResultSummary(out planOutput) string {
	if out.Tree == nil {
		return "no tree" + noteSuffix(out.Note)
	}
	total, unresolved := 0, 0
	for _, leaf := range agenttask.Leaves(out.Tree.Root) {
		total++
		if leaf.Status == agenttask.StatusUnresolved {
			unresolved++
		}
	}
	return fmt.Sprintf("approved=%t, %d leaf/leaves (%d unresolved), %d finding(s), spend $%.4f%s",
		out.Approved, total, unresolved, len(out.Findings), out.SpendUSD, noteSuffix(out.Note))
}

func exportParamsSummary(in findingsExportInput) map[string]any {
	return map[string]any{"format": in.Format, "finding_count": len(in.Findings)}
}

func exportResultSummary(out findingsExportOutput) string {
	return fmt.Sprintf("%d byte(s) rendered", len(out.Content))
}

func triageParamsSummary(in findingsTriageInput) map[string]any {
	return map[string]any{"finding_count": len(in.Findings)}
}

func triageResultSummary(out findingsTriageOutput) string {
	if out.EscalateToHuman != "" {
		return "escalated: " + out.EscalateToHuman
	}
	return fmt.Sprintf("approved=%t, %d ranked", out.Approved, len(out.Ranked))
}

func noteSuffix(note string) string {
	if note == "" {
		return ""
	}
	return " — " + note
}
