package main

import (
	"fmt"
	"io"

	"github.com/tuangatech/hacker-five/pkg/scanner/scope"
)

// requireScopeOrOptOut is P2-6's CLI hard-fail (docs/follow-up.md), used by
// `plan`/`recon` — unlike `scan`, whose --targets is already an exact,
// explicit list, `plan`/`recon` can silently wander into whatever recon
// discovers (a subdomain, a CNAME'd CDN/vendor host, ...) via the old
// implicit "no --scope = everything is in-scope" default. Refuses outright
// unless a --scope file is given or the caller explicitly passes
// --allow-no-scope. A "*.example.com" scope entry still authorizes recon to
// explore that whole subdomain tree freely (scope.Scope.Allowed) — this
// hard-fail only prevents running with NO boundary at all, not narrow
// exploration; set the scope file once per engagement (see
// .engagements/{meesho,shopify}/scope.txt for real examples, or generate one
// from a live HackerOne program via `hackerfive report scopes --team
// <slug>`) and every subsequent run proceeds fully unattended.
// `scan` deliberately keeps its own separate warn-only behavior — its
// --targets is already the exact host list, no discovery-driven expansion
// happens there the way it does in recon's own subfinder/katana waves.
func requireScopeOrOptOut(scopeFile string, allowNoScope bool, stderr io.Writer) (*scope.Scope, error) {
	if scopeFile == "" {
		if allowNoScope {
			_, _ = fmt.Fprintln(stderr, "warning: --allow-no-scope set — every host discovered is treated as in-scope, including anything outside the intended target (e.g. shared CDN/vendor infrastructure)")
			return nil, nil
		}
		return nil, fmt.Errorf("--scope is required (pass a target allow-list file — see .engagements/*/scope.txt for the format — or --allow-no-scope to proceed with no boundary at all; not recommended)")
	}
	s, err := scope.Parse(scopeFile)
	if err != nil {
		return nil, fmt.Errorf("parsing --scope: %w", err)
	}
	return s, nil
}
