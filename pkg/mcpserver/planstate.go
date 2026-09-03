package mcpserver

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/llmfallback"
	"github.com/tuangatech/hacker-five/pkg/scanner"
)

// pendingPlanTTL bounds how long a resolved-but-unapproved plan sits in
// this in-memory cache waiting for the client's SEP-2322 multi-round-trip
// retry. Real finding (2026-09-02, live-testing against a real in-memory
// MCP client on protocol version 2026-07-28): a tool handler cannot call
// ServerSession.Elicit synchronously mid-request under this protocol
// version — it errors "cannot be sent while serving a request... return an
// InputRequests map instead". The real, correct mechanism is: return
// InputRequests + an opaque RequestState from round 1, then the client
// (transparently, via its own default-enabled multi-round-trip middleware)
// fulfills the elicitation and retries the same tool call with
// InputResponses + the echoed RequestState. Between those two calls, the
// resolved tree has to live somewhere — this cache, keyed by RequestState.
// This is bounded and short-lived (10 minutes, single retry expected
// promptly), not a durable/replayable resource: doc15 B1's original
// "no plan-ID string to mint/store/trust the agent not to replay" concern
// was about a long-lived, human-approved-whenever plan resource; a
// RequestState token scoped to one logical CallTool exchange's own retry
// loop is a materially different, much narrower thing, and it's SEP-2322's
// own sanctioned mechanism, not a hand-rolled substitute for it.
const pendingPlanTTL = 10 * time.Minute

type pendingPlan struct {
	tree             *agenttask.PlanTree
	fieldSuggestions []agenttask.FieldSuggestion
	baseCfg          scanner.Config
	escalations      []string
	createdAt        time.Time
}

var (
	pendingPlansMu sync.Mutex
	pendingPlans   = map[string]*pendingPlan{}
)

// storePendingPlan caches p and returns a fresh opaque ID to use as
// RequestState. Also sweeps any entry older than pendingPlanTTL — a lazy
// eviction on the same lock rather than a background goroutine, since
// activity (new plan calls) is exactly when it's worth paying the sweep
// cost.
func storePendingPlan(p *pendingPlan) string {
	pendingPlansMu.Lock()
	defer pendingPlansMu.Unlock()
	sweepExpiredPlansLocked()
	id := mintStateID()
	p.createdAt = time.Now()
	pendingPlans[id] = p
	return id
}

// takePendingPlan removes and returns the cached plan for id — one-shot: a
// RequestState is only ever expected to be echoed back once, per SEP-2322's
// own single-retry contract for this handler's shape.
func takePendingPlan(id string) (*pendingPlan, bool) {
	pendingPlansMu.Lock()
	defer pendingPlansMu.Unlock()
	p, ok := pendingPlans[id]
	if ok {
		delete(pendingPlans, id)
	}
	return p, ok
}

func sweepExpiredPlansLocked() {
	cutoff := time.Now().Add(-pendingPlanTTL)
	for id, p := range pendingPlans {
		if p.createdAt.Before(cutoff) {
			delete(pendingPlans, id)
		}
	}
}

// mintStateID returns a random 32-hex-char token — collision-resistant
// enough for a short-lived, single-use, process-local cache key (not a
// security boundary on its own; scope/approval are enforced elsewhere).
func mintStateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// pendingTriage is findings.triage's own small analog of pendingPlan — same
// SEP-2322 two-round-trip need (a ranking is computed, then elicited),
// same short-lived cache shape, kept separate rather than generalized since
// each tool's cached state and TTL considerations are independent and the
// two structs are simple enough that sharing a generic wrapper wouldn't
// meaningfully reduce code.
type pendingTriage struct {
	ranked    []llmfallback.RankedFinding
	createdAt time.Time
}

var (
	pendingTriagesMu sync.Mutex
	pendingTriages   = map[string]*pendingTriage{}
)

func storePendingTriage(p *pendingTriage) string {
	pendingTriagesMu.Lock()
	defer pendingTriagesMu.Unlock()
	cutoff := time.Now().Add(-pendingPlanTTL)
	for id, existing := range pendingTriages {
		if existing.createdAt.Before(cutoff) {
			delete(pendingTriages, id)
		}
	}
	id := mintStateID()
	p.createdAt = time.Now()
	pendingTriages[id] = p
	return id
}

func takePendingTriage(id string) (*pendingTriage, bool) {
	pendingTriagesMu.Lock()
	defer pendingTriagesMu.Unlock()
	p, ok := pendingTriages[id]
	if ok {
		delete(pendingTriages, id)
	}
	return p, ok
}
