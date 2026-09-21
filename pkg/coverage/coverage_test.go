package coverage

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/llmfallback"
	"github.com/tuangatech/hacker-five/pkg/recon"
)

func TestRedactURL_KeepsNamesAndDropsValues(t *testing.T) {
	cases := []struct {
		in, want string
		keys     []string
	}{
		{"https://t.example/api/orders/123?token=abc&x=1#frag", "https://t.example/api/orders/{id}?token=&x=", []string{"token", "x"}},
		{"https://t.example/v/9b2e1c4a-1f3d-4e5a-8b6c-7d8e9f0a1b2c/location", "https://t.example/v/{id}/location", nil},
		{"https://t.example/u/bob@example.com/profile", "https://t.example/u/{id}/profile", nil},
		{"https://t.example/users/{userId}/keys", "https://t.example/users/{userId}/keys", nil}, // a spec placeholder holds no value, and must not be percent-encoded
		{"https://user:pw@t.example/a?report_id=", "https://t.example/a?report_id=", []string{"report_id"}},
	}
	for _, c := range cases {
		got, keys := RedactURL(c.in)
		assert.Equal(t, c.want, got, c.in)
		assert.Equal(t, c.keys, keys, c.in)
	}
}

func TestFromRecon_IncludesBodyKeysAndNoValues(t *testing.T) {
	eps := FromRecon(&recon.ReconResult{Endpoints: []recon.EndpointFact{
		{URL: "https://t.example/api/contact?to=5", Source: "api-spec", StatusCode: 401, AuthRequired: true, BodyParamKeys: []string{"mechanic_api", "number_of_repeats"}},
	}})
	require.Len(t, eps, 1)
	assert.Equal(t, "GET", eps[0].Method)
	assert.Equal(t, "https://t.example/api/contact?to=", eps[0].URL)
	assert.Equal(t, []string{"mechanic_api", "number_of_repeats", "to"}, eps[0].Params)
	assert.True(t, eps[0].AuthRequired)
}

func TestEndpointSet_DedupesAndCaps(t *testing.T) {
	var s EndpointSet
	s.Add([]Endpoint{{Method: "GET", URL: "https://t/a"}, {Method: "GET", URL: "https://t/a"}, {Method: "POST", URL: "https://t/a"}})
	assert.Len(t, s.List(), 2, "the same method+URL is one entry; another method is another")

	var full EndpointSet
	var many []Endpoint
	for i := 0; i < MaxLedgerEndpoints+7; i++ {
		many = append(many, Endpoint{Method: "GET", URL: "https://t/" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)) + string(rune('a'+i/676))})
	}
	full.Add(many)
	assert.Len(t, full.List(), MaxLedgerEndpoints)
	assert.Equal(t, 7, full.Dropped())
}

// ---- Attribute ------------------------------------------------------------

const host = "t.example"

func leaf(id, detector string, mod func(*agenttask.PlanNode)) *agenttask.PlanNode {
	l := &agenttask.PlanNode{ID: id, Target: host, Detector: detector, Status: agenttask.StatusPending}
	if mod != nil {
		mod(l)
	}
	return l
}

func treeOf(leaves ...*agenttask.PlanNode) *agenttask.PlanTree {
	return &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: leaves}}
}

func turn(id, summary, errText string) llmfallback.TurnRecord {
	return llmfallback.TurnRecord{Action: llmfallback.Action{Kind: "scan.leaf", NodeID: id}, ResultSummary: summary, Error: errText}
}

var idorTarget = Target{Name: "bola-orders", EndpointContains: "/shop/orders/", FindingPrefixes: []string{"idor-"}}

func TestAttribute_EachStage(t *testing.T) {
	orders := Endpoint{Method: "GET", URL: "https://t.example/shop/orders/{id}"}
	ordersLeaf := func(mod func(*agenttask.PlanNode)) *agenttask.PlanNode {
		return leaf("l1", "idor", func(l *agenttask.PlanNode) {
			l.EndpointTemplate = "/shop/orders/{{id}}"
			if mod != nil {
				mod(l)
			}
		})
	}
	cases := []struct {
		name string
		run  Run
		tgt  Target
		want Stage
	}{
		{"recon never saw it", Run{Endpoints: []Endpoint{{Method: "GET", URL: "https://t.example/other"}}}, idorTarget, StageNotObserved},
		{"seen, no leaf", Run{Endpoints: []Endpoint{orders}, Tree: treeOf(leaf("x", "misconfig", nil))}, idorTarget, StageNoLeaf},
		{"seen, only a leaf for a different path", Run{Endpoints: []Endpoint{orders}, Tree: treeOf(leaf("x", "idor", func(l *agenttask.PlanNode) { l.EndpointTemplate = "/other/{{id}}" }))}, idorTarget, StageNoLeaf},
		{"leaf skipped on a missing field", Run{Endpoints: []Endpoint{orders}, Tree: treeOf(ordersLeaf(nil)),
			History: []llmfallback.TurnRecord{turn("l1", "skipped: l1: missing required field", "")}}, idorTarget, StageBlocked},
		{"leaf unresolved", Run{Endpoints: []Endpoint{orders}, Tree: treeOf(ordersLeaf(func(l *agenttask.PlanNode) { l.Status = agenttask.StatusUnresolved }))}, idorTarget, StageBlocked},
		{"runnable, never dispatched", Run{Endpoints: []Endpoint{orders}, Tree: treeOf(ordersLeaf(nil))}, idorTarget, StageNotDispatched},
		{"dispatched, nothing found", Run{Endpoints: []Endpoint{orders}, Tree: treeOf(ordersLeaf(nil)),
			History: []llmfallback.TurnRecord{turn("l1", "0 new finding(s), 3 log line(s)", "")}}, idorTarget, StageNoFinding},
		{"dispatched, same-class findings elsewhere", Run{Endpoints: []Endpoint{orders}, Tree: treeOf(ordersLeaf(nil)),
			History:  []llmfallback.TurnRecord{turn("l1", "0 new finding(s)", "")},
			Findings: []detectors.Finding{{ID: "idor-1", Target: "https://t.example/report?id=1"}}}, idorTarget, StageMismatch},
		{"found", Run{Endpoints: []Endpoint{orders}, Tree: treeOf(ordersLeaf(nil)),
			Findings: []detectors.Finding{{ID: "idor-1", Target: "https://t.example/shop/orders/3"}}}, idorTarget, StageFound},
		{"gated", Run{Endpoints: []Endpoint{orders}}, Target{EndpointContains: "/shop/orders/", FindingPrefixes: []string{"mutatebfla-"}, Gated: "needs an operator flag"}, StageGated},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Attribute(c.run, c.tgt)
			assert.Equal(t, c.want, got.Stage, got.Why)
			assert.NotEmpty(t, got.Why)
		})
	}
}

func TestAttribute_BestAttemptWins(t *testing.T) {
	// A field-miss retry turns a skip into a run: the leaf counts as dispatched.
	run := Run{
		Endpoints: []Endpoint{{Method: "GET", URL: "https://t.example/shop/orders/{id}"}},
		Tree:      treeOf(leaf("l1", "idor", func(l *agenttask.PlanNode) { l.EndpointTemplate = "/shop/orders/{{id}}" })),
		History:   []llmfallback.TurnRecord{turn("l1", "skipped: missing field", ""), turn("l1", "0 new finding(s)", "")},
	}
	assert.Equal(t, StageNoFinding, Attribute(run, idorTarget).Stage)
}

func TestAttribute_EndpointlessTargetUsesAnyLeafOfTheClass(t *testing.T) {
	jwt := Target{Name: "jwt", FindingPrefixes: []string{"authbypass-jwt-"}}
	run := Run{
		Endpoints: []Endpoint{{Method: "GET", URL: "https://t.example/api/me"}},
		Tree:      treeOf(leaf("a1", "authbypass", nil)), // a host-wide authbypass leaf with no protected paths
		History:   []llmfallback.TurnRecord{turn("a1", "skipped: a1: missing required field ProtectedPaths", "")},
	}
	got := Attribute(run, jwt)
	assert.Equal(t, StageBlocked, got.Stage)
	assert.Contains(t, got.Why, "ProtectedPaths", "the skip reason is the answer to LT-180's question")
	assert.Equal(t, []string{"a1"}, got.LeafIDs)
}

func TestAttribute_ParameterNamedLeafCoversEndpointsCarryingIt(t *testing.T) {
	ssrf := Target{EndpointContains: "contact_mechanic", FindingPrefixes: []string{"ssrf-"}}
	ep := Endpoint{Method: "POST", URL: "https://t.example/api/contact_mechanic", Params: []string{"mechanic_api"}}
	withParam := leaf("s1", "ssrf", func(l *agenttask.PlanNode) { l.SSRFBodyParams = []string{"mechanic_api"} })
	otherParam := leaf("s2", "ssrf", func(l *agenttask.PlanNode) { l.SSRFParams = []string{"redirect"} })

	assert.Equal(t, StageNotDispatched, Attribute(Run{Endpoints: []Endpoint{ep}, Tree: treeOf(withParam)}, ssrf).Stage)
	assert.Equal(t, StageNoLeaf, Attribute(Run{Endpoints: []Endpoint{ep}, Tree: treeOf(otherParam)}, ssrf).Stage,
		"a leaf naming a parameter the endpoint does not carry does not cover it")
}

func TestClassMatches(t *testing.T) {
	assert.True(t, classMatches("idor", []string{"idor-"}))
	assert.True(t, classMatches("authbypass", []string{"authbypass-jwt-"}))
	assert.True(t, classMatches("misconfig-exposed-path", []string{"misconfig-exposed-path-"}), "a template-ID detector matches the finding IDs it names")
	assert.False(t, classMatches("sqli", []string{"idor-"}))
	assert.False(t, classMatches("", []string{"idor-"}))
	assert.True(t, classMatches("anything", nil), "no prefixes accepts any leaf")
}

// ---- EndpointStages -------------------------------------------------------

func TestEndpointStages_CountsEndpointsNoLeafNamesAndIgnoresHostWideLeaves(t *testing.T) {
	run := Run{
		Endpoints: []Endpoint{
			{Method: "GET", URL: "https://t.example/shop/orders/{id}"},
			{Method: "GET", URL: "https://t.example/api/users"},
			{Method: "GET", URL: "https://t.example/static/app.js"},
		},
		Tree: treeOf(
			leaf("l1", "idor", func(l *agenttask.PlanNode) { l.EndpointTemplate = "/shop/orders/{{id}}" }),
			leaf("m1", "misconfig", nil), // sweeps the host: says nothing about /api/users
		),
		History:  []llmfallback.TurnRecord{turn("l1", "0 new finding(s)", "")},
		Findings: nil,
	}
	rows, skipped := EndpointStages(run)
	assert.Equal(t, 1, skipped, "static assets are left out")
	require.Len(t, rows, 2)
	assert.Equal(t, StageNoFinding, rows[0].Stage)
	assert.Equal(t, StageNoLeaf, rows[1].Stage)
	assert.Equal(t, "1-no-leaf: 1, 4-no-finding: 1", FormatHistogram(Histogram(rows)))
}

func TestEndpointStages_FindingOnTheEndpointIsFound(t *testing.T) {
	run := Run{
		Endpoints: []Endpoint{{Method: "GET", URL: "https://t.example/shop/orders/{id}"}},
		Tree:      treeOf(leaf("l1", "idor", func(l *agenttask.PlanNode) { l.EndpointTemplate = "/shop/orders/{{id}}" })),
		Findings:  []detectors.Finding{{ID: "idor-1", Target: "https://t.example/shop/orders/4"}},
	}
	rows, _ := EndpointStages(run)
	require.Len(t, rows, 1)
	assert.Equal(t, StageFound, rows[0].Stage)
}

func TestStageString(t *testing.T) {
	assert.Equal(t, "1-no-leaf", StageNoLeaf.String())
	assert.Equal(t, "7-found", StageFound.String())
}
