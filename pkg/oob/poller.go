package oob

import (
	"context"
	"strings"
	"sync"
	"time"
)

// Poller wraps a registered Client with a background polling loop that
// dispatches decrypted interactions to whichever caller is waiting on the
// nonce that interaction's hostname embeds. A single Client's Poll returns
// "everything recorded since the last poll" and implicitly clears it
// server-side — fine for one caller polling sequentially (see
// pkg/detectors/ssrf/oob_check.go's checkOOBCallback), but wrong once more
// than one caller can share the same registered session concurrently
// (pkg/template/nuclei's Executor, shared across a scan's worker-pool
// goroutines — many targets' template executions can be waiting on
// distinct probes at the same moment): an uncoordinated second Poll call
// around the same time could silently consume the interaction a first,
// still-waiting caller needed. Poller centralizes every Poll call behind
// one background loop and a nonce->waiter map so callers never call Poll
// directly once wrapped this way — only Wait.
type Poller struct {
	client   *Client
	interval time.Duration

	mu      sync.Mutex
	waiters map[string]chan Interaction

	startOnce sync.Once
	cancel    context.CancelFunc
}

// NewPoller wraps client with a background poll loop that ticks every
// interval once started (see Start). Constructing a Poller talks to the
// network for nothing by itself — nothing polls until Start is called.
func NewPoller(client *Client, interval time.Duration) *Poller {
	return &Poller{client: client, interval: interval, waiters: make(map[string]chan Interaction)}
}

// NewPayloadHost passes through to the wrapped Client — see its own doc
// comment. Safe to call concurrently: Client has no mutable state after
// construction.
func (p *Poller) NewPayloadHost() (host, nonce string) {
	return p.client.NewPayloadHost()
}

// Start begins the background poll loop if it isn't already running —
// idempotent (sync.Once-guarded), safe to call redundantly. ctx should be
// long-lived (e.g. context.Background(), owned by whoever constructs this
// Poller) and NOT a single caller's own per-request context: the loop is
// shared by every concurrent Wait caller, so one caller's context being
// canceled must never stop polling for the others still waiting. Call Stop
// to end the loop deliberately.
func (p *Poller) Start(ctx context.Context) {
	p.startOnce.Do(func() {
		loopCtx, cancel := context.WithCancel(ctx)
		p.cancel = cancel
		go p.run(loopCtx)
	})
}

// Stop ends the background poll loop and best-effort deregisters the
// wrapped Client's session (same fire-and-forget semantics as
// Client.Deregister — a failure here doesn't matter enough to surface).
// Safe to call even if Start was never reached (e.g. a scan that never
// actually fired an interactsh-url probe).
func (p *Poller) Stop() {
	if p.cancel != nil {
		p.cancel()
	}
	p.client.Deregister(context.Background())
}

func (p *Poller) run(ctx context.Context) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			interactions, err := p.client.Poll(ctx)
			if err != nil {
				continue // transient — next tick tries again
			}
			p.dispatch(interactions)
		}
	}
}

// dispatch delivers each interaction to the one waiter (if any) whose nonce
// it embeds, per Interactsh's own hostname shape (correlationID+nonce
// subdomain — see Client.NewPayloadHost). An interaction matching no
// current waiter is dropped, not queued for one that registers later —
// same best-effort correlation this project's existing checkOOBCallback
// already accepts.
func (p *Poller) dispatch(interactions []Interaction) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, it := range interactions {
		for nonce, ch := range p.waiters {
			if !strings.Contains(it.FullID, nonce) && !strings.Contains(it.UniqueID, nonce) {
				continue
			}
			select {
			case ch <- it:
			default:
			}
			delete(p.waiters, nonce)
			break
		}
	}
}

// Wait blocks until an interaction matching nonce arrives, timeout elapses,
// or ctx is done — whichever first. Requires Start to have already been
// called by this Poller's owner (Wait does not start the loop itself —
// see Start's own doc comment for why that responsibility can't live on a
// per-call path). Returns (Interaction{}, false) on timeout/cancellation —
// callers must treat that as "no callback observed," not an error: a
// non-vulnerable target legitimately never triggers one.
func (p *Poller) Wait(ctx context.Context, nonce string, timeout time.Duration) (Interaction, bool) {
	ch := make(chan Interaction, 1)
	p.mu.Lock()
	p.waiters[nonce] = ch
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		delete(p.waiters, nonce)
		p.mu.Unlock()
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case it := <-ch:
		return it, true
	case <-timer.C:
		return Interaction{}, false
	case <-ctx.Done():
		return Interaction{}, false
	}
}
