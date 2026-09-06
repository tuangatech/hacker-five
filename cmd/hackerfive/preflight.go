package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

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
