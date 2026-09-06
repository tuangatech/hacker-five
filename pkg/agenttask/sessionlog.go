// sessionlog.go implements doc15 Phase 6 Step 5's C1 (minimal): a
// structured, append-only record of every MCP tool call an agent
// coordinator makes in one server session — the tool name, the
// coordinator's stated reason for the call (a courtesy field the tool
// schemas accept, never something HackerFive can force an agent to fill
// honestly), a redacted parameter summary, and the raw result outcome.
//
// This is the "the log exists, is queryable, and is complete" deliverable,
// not yet the Web UI's live Agent tab (Phase 7 Step 3). pkg/mcpserver holds
// one process-wide SessionLog (one long-lived stdio connection == one
// session) and exposes it through the session.log tool; an optional JSONL
// sink persists it for external inspection.
package agenttask

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// SessionLogEntry is one completed tool call. Params is a redacted summary
// the caller supplies — never raw auth tokens or full request bodies; this
// package marshals whatever it is handed and does not itself strip secrets.
type SessionLogEntry struct {
	Seq        int64           `json:"seq"`
	Tool       string          `json:"tool"`
	Reason     string          `json:"reason,omitempty"`
	Params     json.RawMessage `json:"params,omitempty"`
	StartedAt  time.Time       `json:"started_at"`
	FinishedAt time.Time       `json:"finished_at"`
	DurationMS int64           `json:"duration_ms"`
	Result     string          `json:"result,omitempty"`
	Error      string          `json:"error,omitempty"`
}

// SessionLog is an append-only, concurrency-safe list of SessionLogEntry.
// Multiple tool handlers run concurrently (the SDK dispatches each
// tools/call on its own goroutine), so both the append and the sequence
// counter are mutex-guarded.
type SessionLog struct {
	mu      sync.Mutex
	seq     int64
	entries []SessionLogEntry
	sink    io.Writer // optional; one JSON object per line, best-effort
}

// NewSessionLog returns a SessionLog. If sink is non-nil, every completed
// entry is also written to it as a single JSON line (JSONL); a write error
// on the sink is ignored — the in-memory log is the source of truth and a
// broken sink must not fail a tool call.
func NewSessionLog(sink io.Writer) *SessionLog {
	return &SessionLog{sink: sink}
}

// Begin records the start of a tool call and returns a finish function to
// call (typically via defer) once the call completes. params is marshalled
// now so a later mutation of the caller's struct can't change what was
// logged; if it can't be marshalled the entry keeps a null params rather
// than failing the call.
func (l *SessionLog) Begin(tool, reason string, params any) func(resultSummary string, err error) {
	started := time.Now().UTC()

	l.mu.Lock()
	l.seq++
	seq := l.seq
	l.mu.Unlock()

	var raw json.RawMessage
	if params != nil {
		if b, err := json.Marshal(params); err == nil {
			raw = b
		}
	}

	return func(resultSummary string, err error) {
		finished := time.Now().UTC()
		entry := SessionLogEntry{
			Seq:        seq,
			Tool:       tool,
			Reason:     reason,
			Params:     raw,
			StartedAt:  started,
			FinishedAt: finished,
			DurationMS: finished.Sub(started).Milliseconds(),
			Result:     resultSummary,
		}
		if err != nil {
			entry.Error = err.Error()
		}

		l.mu.Lock()
		l.entries = append(l.entries, entry)
		sink := l.sink
		l.mu.Unlock()

		if sink != nil {
			if b, mErr := json.Marshal(entry); mErr == nil {
				_, _ = sink.Write(append(b, '\n'))
			}
		}
	}
}

// Entries returns a copy of every recorded entry, in call-completion order.
func (l *SessionLog) Entries() []SessionLogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]SessionLogEntry, len(l.entries))
	copy(out, l.entries)
	return out
}

// Query returns recorded entries filtered by tool name (exact match, or all
// tools when toolFilter is "") and capped at the most recent limit entries
// (all of them when limit <= 0). Completion order is preserved.
func (l *SessionLog) Query(toolFilter string, limit int) []SessionLogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()

	var out []SessionLogEntry
	for _, e := range l.entries {
		if toolFilter == "" || e.Tool == toolFilter {
			out = append(out, e)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}
