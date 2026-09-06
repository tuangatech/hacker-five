// Package preflight is HackerFive's D2 program-policy pre-flight check
// (docs/15-implementation-plan-ph6.md Step 3). Before a scan/recon/plan run
// against a non-lab target, Check refuses outright when the operator has
// declared automated scanning disallowed for that target, and folds a fetched
// security.txt / robots.txt into non-blocking warnings.
//
// The authoritative signal is an operator-maintained policy.yaml — a
// machine-readable companion to the human-vetted docs/22-authorized-targets.md
// entries and the per-engagement .engagements/*/scope.txt files. It hard-fails
// ONLY on an explicit "disallowed": an absent file, or a target with no entry,
// warns and proceeds, since every lab / owned-site / ad-hoc-authorized run
// legitimately has no such declaration. This is the one backlog item with a
// documented real-world cost of skipping it (XBOW's own program removal,
// doc90 §2) — hence a hard block, unlike --scope's softer warn.
package preflight

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/tuangatech/hacker-five/pkg/scanner/scope"
)

// Verdict is a policy.yaml lookup outcome for one target.
type Verdict string

const (
	VerdictAllowed    Verdict = "allowed"
	VerdictDisallowed Verdict = "disallowed"
	VerdictUnknown    Verdict = "unknown"
)

// maxSecurityTxtScan caps how much of a fetched security.txt body a caller
// should hand to SignalWarnings — the body is only substring-scanned, never
// parsed, so a truncated copy is fine and an unbounded one is a memory risk.
const maxSecurityTxtScan = 16 << 10

// TargetPolicy is one entry in a policy.yaml `targets:` list.
type TargetPolicy struct {
	// Match is a scope-file-syntax pattern: an exact domain, a "*."-prefixed
	// suffix (that domain and any subdomain), or a CIDR (literal-IP hosts).
	Match string `yaml:"match"`
	// AutomatedScanning is "allowed", "disallowed", or "unknown" (the default
	// for any other/blank value). Only "disallowed" ever blocks.
	AutomatedScanning string `yaml:"automated_scanning"`
	// MaxRunsPerDay is informational only — surfaced as a reminder, never
	// enforced (HackerFive has no run counter; see doc22's aalberts.com note).
	MaxRunsPerDay int    `yaml:"max_runs_per_day"`
	Notes         string `yaml:"notes"`
}

// PolicySet is a parsed policy.yaml. A nil *PolicySet is valid and means "no
// declarations" — Verdict then always returns VerdictUnknown.
type PolicySet struct {
	entries    []policyEntry
	reqHeaders []headerKV
}

// headerKV is one parsed `request_headers:` entry, split on the first colon.
type headerKV struct {
	name  string
	value string
}

type policyEntry struct {
	pol   TargetPolicy
	match *scope.Scope
}

type policyFile struct {
	Targets []TargetPolicy `yaml:"targets"`
	// RequestHeaders are static "Name: Value" strings HackerFive must send on
	// every request it makes against an in-scope target — a bug-bounty program
	// that mandates an identifying header (Meesho's `X-Hackerone: <user>`)
	// declares it here so recon/scan/plan pick it up without a per-command
	// flag to forget (LT-36). Applies to the whole file, not per-target.
	RequestHeaders []string `yaml:"request_headers"`
}

// Load reads a policy.yaml from path. A missing file is not an error — it
// returns (nil, nil), the "no declarations" set. A present-but-malformed file
// IS an error: a corrupt policy must not silently degrade to no-enforcement.
func Load(path string) (*PolicySet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading policy file %s: %w", path, err)
	}
	var f policyFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parsing policy file %s: %w", path, err)
	}
	ps := &PolicySet{}
	for i, tp := range f.Targets {
		if strings.TrimSpace(tp.Match) == "" {
			return nil, fmt.Errorf("policy file %s: targets[%d] has no match pattern", path, i)
		}
		sc, err := scope.New([]string{tp.Match})
		if err != nil {
			return nil, fmt.Errorf("policy file %s: targets[%d] match %q: %w", path, i, tp.Match, err)
		}
		ps.entries = append(ps.entries, policyEntry{pol: tp, match: sc})
	}
	for i, raw := range f.RequestHeaders {
		name, value, ok := strings.Cut(raw, ":")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			return nil, fmt.Errorf("policy file %s: request_headers[%d] %q must be in \"Name: Value\" form", path, i, raw)
		}
		ps.reqHeaders = append(ps.reqHeaders, headerKV{name: name, value: strings.TrimSpace(value)})
	}
	return ps, nil
}

// RequestHeaders returns the static headers declared in the policy file's
// `request_headers:` list as a name->value map (LT-36). Nil-safe: a nil
// *PolicySet, or a file with no such list, returns nil.
func (ps *PolicySet) RequestHeaders() map[string]string {
	if ps == nil || len(ps.reqHeaders) == 0 {
		return nil
	}
	m := make(map[string]string, len(ps.reqHeaders))
	for _, h := range ps.reqHeaders {
		m[h.name] = h.value
	}
	return m
}

// Verdict returns the automated-scanning verdict for target plus the matching
// entry (nil when none matched). The first matching entry in file order wins,
// so list more specific patterns first — same convention as a scope file.
func (ps *PolicySet) Verdict(target string) (Verdict, *TargetPolicy) {
	if ps == nil {
		return VerdictUnknown, nil
	}
	norm := normalizeTarget(target)
	for i := range ps.entries {
		e := &ps.entries[i]
		if !e.match.Allowed(norm) {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(e.pol.AutomatedScanning)) {
		case "allowed":
			return VerdictAllowed, &e.pol
		case "disallowed":
			return VerdictDisallowed, &e.pol
		default:
			return VerdictUnknown, &e.pol
		}
	}
	return VerdictUnknown, nil
}

// Signals carries the non-authoritative, fetched artifacts D2 folds into a
// warning (never a block): a security.txt body and whether robots.txt
// disallows all crawling. Advisory only — security.txt has no standard
// "no scanners" field, and robots is a crawler convention, not a testing ban.
type Signals struct {
	SecurityTxt       string
	RobotsDisallowAll bool
}

// Options configures Check.
type Options struct {
	// PolicyPath is the policy.yaml to consult. "" means no policy file — every
	// verdict is Unknown, so Check can only ever warn, never block.
	PolicyPath string
	// Override downgrades a Disallowed verdict from a hard error to a loud
	// warning — the CLI's --allow-policy-override, for an operator with
	// out-of-band authorization contradicting a stale file. The MCP tools
	// never set this.
	Override bool
	// Signals, if set, is from a prior recon pass (the plan flow). nil
	// elsewhere.
	Signals *Signals
}

// Check runs the D2 pre-flight for targets. It returns advisory warnings
// (always safe to proceed) and, separately, a hard error when any target's
// policy verdict is Disallowed and Options.Override is false — in which case
// the caller must not run.
func Check(targets []string, opts Options) (warnings []string, err error) {
	var ps *PolicySet
	if opts.PolicyPath != "" {
		var loadErr error
		if ps, loadErr = Load(opts.PolicyPath); loadErr != nil {
			return nil, loadErr
		}
	}

	var disallowed []string
	for _, t := range targets {
		if IsLabTarget(t) {
			continue
		}
		host := hostOf(t)
		v, entry := ps.Verdict(t)
		switch v {
		case VerdictDisallowed:
			note := ""
			if entry != nil && strings.TrimSpace(entry.Notes) != "" {
				note = " — " + strings.TrimSpace(entry.Notes)
			}
			match := ""
			if entry != nil {
				match = fmt.Sprintf(" (matched %q)", entry.Match)
			}
			disallowed = append(disallowed, host+match+note)
		case VerdictAllowed:
			if entry != nil && entry.MaxRunsPerDay > 0 {
				warnings = append(warnings, fmt.Sprintf("%s: policy permits automated scanning, capped at %d run(s)/day — HackerFive does not count runs, track this yourself", host, entry.MaxRunsPerDay))
			}
		case VerdictUnknown:
			if opts.PolicyPath == "" {
				warnings = append(warnings, fmt.Sprintf("%s: no policy file given — automated-scanning authorization is on the operator (see .engagements/*/policy.yaml, doc15 Step 3)", host))
			} else {
				warnings = append(warnings, fmt.Sprintf("%s: no entry in %s — add one declaring automated_scanning: allowed|disallowed to make this explicit", host, opts.PolicyPath))
			}
		}
	}

	warnings = append(warnings, SignalWarnings(opts.Signals)...)

	if len(disallowed) > 0 {
		msg := "program policy disallows automated scanning for: " + strings.Join(disallowed, "; ")
		if opts.Override {
			warnings = append(warnings, "OVERRIDE: "+msg+" — proceeding only because --allow-policy-override was passed")
			return warnings, nil
		}
		return warnings, fmt.Errorf("%s (pass --allow-policy-override on the CLI if you hold out-of-band authorization; there is no MCP override)", msg)
	}
	return warnings, nil
}

// SignalWarnings turns fetched security.txt / robots.txt signals into advisory
// warning strings. Exported so the plan flow, which only has these after its
// recon pass completes, can emit them separately from Check's pre-recon block.
func SignalWarnings(s *Signals) []string {
	if s == nil {
		return nil
	}
	var w []string
	if s.RobotsDisallowAll {
		w = append(w, "robots.txt disallows all crawling (Disallow: / for User-agent: *) — a crawler convention, not a testing ban, but confirm automated scanning is permitted here")
	}
	body := s.SecurityTxt
	if len(body) > maxSecurityTxtScan {
		body = body[:maxSecurityTxtScan]
	}
	lower := strings.ToLower(body)
	switch {
	case strings.Contains(lower, "no automated") || strings.Contains(lower, "no scanner") || strings.Contains(lower, "do not scan") || strings.Contains(lower, "automated scanning is not"):
		w = append(w, "security.txt text mentions restricting automated scanning — read it in full and confirm before running (this is a warning, not a block; declare it in policy.yaml to enforce)")
	case strings.Contains(lower, "policy:"):
		w = append(w, "security.txt links a disclosure Policy — read it and confirm automated scanning is in scope")
	}
	return w
}

// IsLabTarget reports whether t is a loopback/private/link-local host or a
// *.local(host) name — Check skips these entirely (a real disclosure policy
// can't apply to a machine on your own network).
func IsLabTarget(t string) bool {
	h := hostOf(t)
	if h == "" || h == "localhost" || strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".localhost") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
	}
	return false
}

// normalizeTarget prepends https:// when t carries no scheme, so a bare
// domain ("example.com") resolves through scope.Scope.Allowed the same way a
// full URL does.
func normalizeTarget(t string) string {
	if !strings.Contains(t, "://") {
		return "https://" + t
	}
	return t
}

func hostOf(t string) string {
	u, err := url.Parse(normalizeTarget(t))
	if err != nil {
		return t
	}
	return u.Hostname()
}
