package recon

import "net/url"

// DeadPaths returns the distinct URL paths this recon pass observed return
// HTTP 404, normalized to a leading slash with no trailing slash (except
// root). `hackerfive scan --recon-file` threads these into
// scanner.Config.KnownDeadPaths so the nuclei executor can skip a lone
// matcher-only path: template whose only path recon already saw 404
// (Phase 7 Step 4 D5, docs/follow-up.md LT-55).
//
// Only GET (or method-unspecified) observations count: a 404 to a
// HEAD/POST/OPTIONS probe is not evidence a GET template's path is dead.
// The consuming side additionally gates the skip to a scan running with no
// --header credential — recon is always unauthenticated, and an
// unauthenticated 404 is not a guaranteed authenticated-scan 404.
func (r *ReconResult) DeadPaths() []string {
	if r == nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	for _, ep := range r.Endpoints {
		if ep.StatusCode != 404 {
			continue
		}
		if ep.Method != "" && ep.Method != "GET" {
			continue
		}
		u, err := url.Parse(ep.URL)
		if err != nil {
			continue
		}
		p := normalizeDeadPath(u.Path)
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// normalizeDeadPath canonicalizes a URL path for known-dead matching:
// leading slash, no trailing slash except root. Kept byte-for-byte in sync
// with pkg/template/nuclei's own normalizeDeadPath so the produced and
// consumed sets line up.
func normalizeDeadPath(p string) string {
	if p == "" {
		return "/"
	}
	if p[0] != '/' {
		p = "/" + p
	}
	for len(p) > 1 && p[len(p)-1] == '/' {
		p = p[:len(p)-1]
	}
	return p
}
