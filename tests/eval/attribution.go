package eval

import (
	"fmt"
	"sort"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/coverage"
)

// This file is the harness half of LT-185 (docs/94-llm-finding-capability-
// strategy.md §6 step 0b): it turns "5 of 7 known vulnerabilities missed" into
// "lost at stage N" by handing one run's recon endpoints, plan tree, turn history
// and findings to pkg/coverage. The classifier is a library on purpose; only the
// mapping from a KnownVuln to a coverage.Target and the per-arm reporting live here.

// coverageTarget maps a documented vulnerability onto what pkg/coverage traces.
func (v KnownVuln) coverageTarget() coverage.Target {
	return coverage.Target{
		Name:             v.ID,
		EndpointContains: v.EndpointContains,
		FindingPrefixes:  v.IDPrefixes,
		Gated:            v.Gated,
	}
}

func (p ParsedRun) coverageRun() coverage.Run {
	return coverage.Run{Endpoints: p.Result.Recon, Tree: p.Result.Tree, History: p.Result.History, Findings: p.Findings}
}

// AddAttribution records, on rec, the stage each known vulnerability reached and
// how far each recon endpoint got. It does nothing for a run with no final
// result event: without the tree and turn history every miss would read as
// "no leaf", which is a claim the run cannot support.
func (r *RunRecord) AddAttribution(p ParsedRun, known []KnownVuln) {
	if !p.SawResult {
		return
	}
	run := p.coverageRun()
	if len(known) > 0 {
		r.KnownStages = map[string]string{}
		r.KnownWhy = map[string]string{}
		for _, v := range known {
			a := coverage.Attribute(run, v.coverageTarget())
			r.KnownStages[v.ID] = a.Stage.String()
			r.KnownWhy[v.ID] = a.Why
		}
	}
	rows, _ := coverage.EndpointStages(run)
	r.ReconEndpoints = len(p.Result.Recon)
	r.EndpointStages = map[string]int{}
	for st, n := range coverage.Histogram(rows) {
		r.EndpointStages[st.String()] = n
	}
}

// FormatMissAttribution renders, per (lab, arm, model), the stage each known
// vulnerability reached across that arm's runs and the recon endpoints' stage
// counts. Only records with attribution are shown; "" when there are none.
func FormatMissAttribution(records []RunRecord) string {
	type key struct{ lab, arm, model string }
	groups := map[key][]RunRecord{}
	var keys []key
	for _, r := range records {
		if r.KnownStages == nil && r.EndpointStages == nil {
			continue
		}
		k := key{r.Lab, r.Arm, r.Model}
		if _, ok := groups[k]; !ok {
			keys = append(keys, k)
		}
		groups[k] = append(groups[k], r)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.lab != b.lab {
			return a.lab < b.lab
		}
		if a.arm != b.arm {
			return a.arm < b.arm
		}
		return a.model < b.model
	})

	var b strings.Builder
	for _, k := range keys {
		rs := groups[k]
		model := k.model
		if model == "" {
			model = "?"
		}
		fmt.Fprintf(&b, "\n%s / %s [%s] (%d run(s)):\n", k.lab, k.arm, model, len(rs))

		var ids []string
		for id := range rs[0].KnownStages {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		perStage := map[string]float64{}
		for _, id := range ids {
			counts := map[string]int{}
			for _, r := range rs {
				counts[r.KnownStages[id]]++
				perStage[r.KnownStages[id]] += 1 / float64(len(rs))
			}
			fmt.Fprintf(&b, "  %-34s %-28s %s\n", id, stageCounts(counts), rs[len(rs)-1].KnownWhy[id])
		}
		if len(ids) > 0 {
			fmt.Fprintf(&b, "  lost at (mean vulns per run): %s\n", meanStages(perStage))
		}
		last := rs[len(rs)-1]
		if last.ReconEndpoints > 0 {
			fmt.Fprintf(&b, "  recon endpoints: %d (static assets excluded from the stages): %s\n", last.ReconEndpoints, endpointStages(last.EndpointStages))
		}
	}
	return b.String()
}

// stageCounts renders {"1-no-leaf":3} as "1-no-leaf" and a split as "1-no-leaf x2, 4-no-finding x1".
func stageCounts(counts map[string]int) string {
	labels := sortedKeys(counts)
	if len(labels) == 1 {
		return labels[0]
	}
	parts := make([]string, 0, len(labels))
	for _, l := range labels {
		parts = append(parts, fmt.Sprintf("%s x%d", l, counts[l]))
	}
	return strings.Join(parts, ", ")
}

func meanStages(m map[string]float64) string {
	labels := make([]string, 0, len(m))
	for l := range m {
		labels = append(labels, l)
	}
	sort.Strings(labels)
	parts := make([]string, 0, len(labels))
	for _, l := range labels {
		parts = append(parts, fmt.Sprintf("%s %.1f", l, m[l]))
	}
	return strings.Join(parts, ", ")
}

func endpointStages(m map[string]int) string {
	labels := sortedKeys(m)
	parts := make([]string, 0, len(labels))
	for _, l := range labels {
		parts = append(parts, fmt.Sprintf("%s %d", l, m[l]))
	}
	return strings.Join(parts, ", ")
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
