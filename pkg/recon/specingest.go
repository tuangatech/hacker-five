package recon

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
	"github.com/tuangatech/hacker-five/pkg/scanner/scope"
)

// SpecIngestResult is what IngestOpenAPISpecs produced from one or more
// operator-supplied OpenAPI documents — the caller folds these into the
// ReconResult / aggregator exactly as if probeCommonPaths had found the spec
// served.
type SpecIngestResult struct {
	Endpoints  []EndpointFact
	APISpec    *APISpecFact
	OutOfScope []string
	Warnings   []string
}

// IngestOpenAPISpecs walks each ref — a local file path or an http(s) URL —
// into api-spec EndpointFacts via the same walkOpenAPISpec path Wave 3 uses
// for a spec it finds served (LT-89, docs/follow-up.md). It exists for the
// common case where the real document is on disk (an H1 attachment, a repo)
// or behind auth (crAPI serves its spec only at a 401'd springdoc path), so
// an unauthenticated recon never reaches it and the walker never runs.
//
// Routes rebase onto a URL ref's own host, else target's host —
// walkOpenAPISpec only ever takes a path prefix from the document's
// servers[].url / basePath, never a different host, and every produced fact
// is scope-checked here too. sc may be nil (no enforcement). client/headers
// are used only to GET a URL ref. Read-only: a file is read, a URL is GET
// through the caller's rate-limited client.
func IngestOpenAPISpecs(ctx context.Context, client *httpclient.Client, sc *scope.Scope, headers map[string]string, refs []string, target string) SpecIngestResult {
	var out SpecIngestResult
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			continue
		}
		body, specURL, err := loadOpenAPISpecRef(ctx, client, headers, ref, target)
		if err != nil {
			out.Warnings = append(out.Warnings, fmt.Sprintf("--openapi-spec %s: %v — skipped", ref, err))
			continue
		}
		facts, truncated := walkOpenAPISpec(specURL, body)
		if len(facts) == 0 {
			out.Warnings = append(out.Warnings, fmt.Sprintf("--openapi-spec %s: not a recognisable OpenAPI 2.0/3.x document (no routes walked)", ref))
			continue
		}
		kept := 0
		for _, ef := range facts {
			if sc != nil && !sc.Allowed(ef.URL) {
				out.OutOfScope = append(out.OutOfScope, hostOnly(ef.URL))
				continue
			}
			out.Endpoints = append(out.Endpoints, ef)
			kept++
		}
		if kept == 0 {
			out.Warnings = append(out.Warnings, fmt.Sprintf("--openapi-spec %s: every walked route was outside --scope — nothing recorded", ref))
			continue
		}
		if out.APISpec == nil {
			out.APISpec = &APISpecFact{Kind: "openapi", URL: specURL}
		}
		if truncated {
			out.Warnings = append(out.Warnings, fmt.Sprintf("--openapi-spec %s: walked the first %d route(s) of a larger set into endpoint candidates (LT-89)", ref, kept))
		} else {
			out.Warnings = append(out.Warnings, fmt.Sprintf("--openapi-spec %s: walked %d route(s) into endpoint candidates (LT-89)", ref, kept))
		}
	}
	return out
}

// loadOpenAPISpecRef returns a spec body plus the URL walkOpenAPISpec should
// rebase its routes onto: the fetch URL for an http(s) ref, else target for
// a local file. Both paths are bounded to maxSpecBodyBytes.
func loadOpenAPISpecRef(ctx context.Context, client *httpclient.Client, headers map[string]string, ref, target string) (body []byte, specURL string, err error) {
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		if client == nil {
			return nil, "", fmt.Errorf("a URL spec ref needs an HTTP client")
		}
		req, rerr := http.NewRequestWithContext(ctx, http.MethodGet, ref, nil)
		if rerr != nil {
			return nil, "", rerr
		}
		if !hasUserAgentOverride(headers) {
			req.Header.Set("User-Agent", DefaultBrowserUserAgent)
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, derr := client.Do(req)
		if derr != nil {
			return nil, "", derr
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, "", fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		b, rerr := io.ReadAll(io.LimitReader(resp.Body, maxSpecBodyBytes))
		return b, ref, rerr
	}
	b, ferr := os.ReadFile(ref)
	if ferr != nil {
		return nil, "", ferr
	}
	if len(b) > maxSpecBodyBytes {
		b = b[:maxSpecBodyBytes]
	}
	return b, target, nil
}
