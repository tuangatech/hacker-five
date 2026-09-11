package netservice

import (
	"context"
	"fmt"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/template/tcpproto"
)

// checkRedisUnauth dials addr and sends a single RESP inline PING —
// read-only, no data written or removed either way. A "+PONG" reply means
// the server executed a command with no AUTH exchange at all: unauthenticated
// access. A "-NOAUTH ..." (or any other) reply means it didn't — clean
// non-match, not an error.
func (d *Detector) checkRedisUnauth(ctx context.Context, addr, target string) ([]detectors.Finding, error) {
	timeout := timeoutOrDefault(d.timeout)
	reply, err := tcpproto.Probe(ctx, addr, timeout, []byte("PING\r\n"), 0)
	if err != nil {
		return nil, nil
	}
	if !redisIsPong(reply) {
		return nil, nil
	}

	return []detectors.Finding{{
		ID:          fmt.Sprintf("netservice-redis-unauth-%s", sanitizeID(addr)),
		Type:        "misconfig",
		Severity:    "high",
		Confidence:  "high",
		Target:      target,
		Description: fmt.Sprintf("Redis at %s accepted a PING with no authentication (no requirepass, or AUTH not enforced)", addr),
		Evidence: map[string]string{
			"reply": string(reply),
		},
	}}, nil
}

// redisIsPong reports whether reply is RESP's simple-string "+PONG" reply
// (the exact, well-known success shape for an unauthenticated PING) — a
// literal prefix check, not a substring one, so a coincidental "PONG"
// appearing inside an unrelated error/banner can't false-positive.
func redisIsPong(reply []byte) bool {
	const want = "+PONG"
	return len(reply) >= len(want) && string(reply[:len(want)]) == want
}
