package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/preflight"
	"github.com/tuangatech/hacker-five/pkg/recon"
)

// signalWarningsFromRecon turns a completed recon pass's fetched
// security.txt/robots.txt into advisory pre-flight warnings — the D2 signals
// only exist after recon runs, so the plan command emits them separately from
// its pre-recon policy-file block.
func signalWarningsFromRecon(r *recon.ReconResult) []string {
	if r == nil || r.Policy == nil {
		return nil
	}
	return preflight.SignalWarnings(&preflight.Signals{
		SecurityTxt:       r.Policy.SecurityTxt,
		RobotsDisallowAll: r.Policy.RobotsDisallowAll,
	})
}

// resolvePolicyPath picks the policy.yaml the D2 pre-flight check consults
// (doc15 Step 3): an explicit --policy-file wins; otherwise the sibling of
// the --scope file (.engagements/<name>/policy.yaml, matching how scope.txt
// is laid out); otherwise a top-level .engagements/policy.yaml if present;
// otherwise "" — no file, so the check can only warn, never block.
func resolvePolicyPath(policyFile, scopeFile string) string {
	if policyFile != "" {
		return policyFile
	}
	if scopeFile != "" {
		if sib := filepath.Join(filepath.Dir(scopeFile), "policy.yaml"); fileExists(sib) {
			return sib
		}
	}
	if def := filepath.Join(".engagements", "policy.yaml"); fileExists(def) {
		return def
	}
	return ""
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// policyRequestHeaders loads the `request_headers:` list from the same
// policy.yaml the D2 pre-flight check consults and returns it as a
// name->value map (LT-36). A missing file or absent list yields (nil, nil).
// A malformed file is a hard error — the same posture Load/Check take, since
// a program-mandated identifying header silently not being sent is exactly
// the failure this is meant to prevent.
func policyRequestHeaders(policyFile, scopeFile string) (map[string]string, error) {
	path := resolvePolicyPath(policyFile, scopeFile)
	if path == "" {
		return nil, nil
	}
	ps, err := preflight.Load(path)
	if err != nil {
		return nil, err
	}
	return ps.RequestHeaders(), nil
}

// mergeHeaders overlays flag-supplied headers onto policy-supplied ones,
// case-insensitively on the header name so a `--header "x-hackerone: me"`
// still overrides a policy `X-Hackerone:` rather than sending both. Returns
// the merged map plus the sorted names of policy headers that survived
// (for an operator-visible "applying required header" log line).
func mergeHeaders(policy, flag map[string]string) (merged map[string]string, fromPolicy []string) {
	merged = make(map[string]string, len(policy)+len(flag))
	canonical := make(map[string]string, len(policy)) // lower(name) -> stored name
	for k, v := range policy {
		merged[k] = v
		canonical[strings.ToLower(k)] = k
		fromPolicy = append(fromPolicy, k)
	}
	for k, v := range flag {
		if existing, ok := canonical[strings.ToLower(k)]; ok {
			merged[existing] = v // flag wins, keep the policy's spelling of the name
			continue
		}
		merged[k] = v
	}
	sort.Strings(fromPolicy)
	return merged, fromPolicy
}

// runPreflight runs D2's program-policy pre-flight for a CLI command: it
// prints advisory warnings to stderr and returns a hard error only when a
// target's policy verdict is "disallowed" and override is false. sig is the
// recon-derived security.txt/robots.txt signal set when the command has one
// (plan), nil otherwise (scan, recon-before-it-runs).
func runPreflight(targets []string, policyFile, scopeFile string, override bool, sig *preflight.Signals, stderr io.Writer) error {
	warns, err := preflight.Check(targets, preflight.Options{
		PolicyPath: resolvePolicyPath(policyFile, scopeFile),
		Override:   override,
		Signals:    sig,
	})
	for _, w := range warns {
		_, _ = fmt.Fprintln(stderr, "preflight: "+w)
	}
	return err
}
