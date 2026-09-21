package recon

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// API routes from a served documentation page (LT-189).
//
// A crawl follows links, and a target's API documentation is often not linked
// from anywhere a crawler starts: vAPI's front page only says, in prose, "Browse
// http://localhost/vapi/ for Documentation". That page is a Redoc rendering whose
// link anchors spell out every route with its method
// (href="#tag/API1/paths/~1vapi~1api1~1user~1{api1_id}/get"), i.e. the whole API
// of the target, in a page that is one GET away.
//
// So this step (1) fetches each seed's root and a few conventional documentation
// paths, (2) follows same-host URLs the root page merely mentions in its text, and
// (3) reads Redoc-style route anchors from every HTML page it got. It is read-only,
// scope-gated, capped, and records names only: routes and methods, no page content.

const (
	maxDocPages     = 6
	maxDocPageBytes = 4 << 20
	maxDocRoutes    = 200
)

// docCandidatePaths are tried under each seed alongside any URL the root page mentions.
var docCandidatePaths = []string{"/docs", "/redoc", "/api-docs", "/documentation"}

var (
	// docAnchorRe matches a Redoc "paths" anchor: #tag/<Tag>/paths/<JSON-pointer path>/<method>,
	// where the path's slashes are written "~1" and the method follows the last slash.
	docAnchorRe = regexp.MustCompile(`#tag/[^/"'\s]+/paths/(~1[^/"'\s]*)/(get|put|post|delete|patch|head|options)\b`)
	// docMentionRe matches an absolute URL written in page text or a link.
	docMentionRe = regexp.MustCompile(`https?://[A-Za-z0-9._-]+(?::[0-9]{1,5})?(/[A-Za-z0-9._~/%-]*)?`)
)

type docRoute struct{ Method, Path string }

// extractDocAnchorRoutes reads Redoc-style route anchors out of an HTML page,
// deduplicated, in first-seen order. The JSON-pointer escapes are undone ("~1" is
// "/", "~0" is "~"); a path-parameter placeholder such as {api1_id} is kept.
func extractDocAnchorRoutes(html string) []docRoute {
	var out []docRoute
	seen := map[string]bool{}
	for _, m := range docAnchorRe.FindAllStringSubmatch(html, -1) {
		path := strings.NewReplacer("~1", "/", "~0", "~").Replace(m[1])
		if dec, err := url.PathUnescape(path); err == nil {
			path = dec
		}
		key := m[2] + " " + path
		if seen[key] || !strings.HasPrefix(path, "/") {
			continue
		}
		seen[key] = true
		out = append(out, docRoute{Method: strings.ToUpper(m[2]), Path: path})
	}
	return out
}

// sameHostMentions returns the paths of absolute URLs in body whose hostname is
// host, with no port or the seed's own: "Browse http://localhost/vapi/ for
// Documentation" gives "/vapi/". A different host or port is a different origin
// and is never followed. Static assets and the bare root are dropped; the result
// is sorted so the step is deterministic.
func sameHostMentions(body, host, port string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range docMentionRe.FindAllStringSubmatch(body, -1) {
		u, err := url.Parse(m[0])
		if err != nil || !strings.EqualFold(u.Hostname(), host) {
			continue
		}
		if p := u.Port(); p != "" && p != port {
			continue
		}
		path := m[1]
		if len(path) < 2 || IsStaticAssetPath(path) || seen[path] {
			continue
		}
		seen[path] = true
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

// discoverDocRoutes is the step described at the top of this file.
func (r *Recon) discoverDocRoutes(ctx context.Context, agg *aggregator, seeds []string) {
	routesAdded, pagesRead := 0, 0
	done := map[string]bool{}
	for _, seed := range seeds {
		u, err := url.Parse(seed)
		if err != nil || u.Host == "" {
			continue
		}
		origin := u.Scheme + "://" + u.Host
		if done[origin] {
			continue
		}
		done[origin] = true

		rootBody, ok := r.fetchDocPage(ctx, agg, seed)
		var pageOrder []string // fetch order, so the routes come out in a stable order
		pages := map[string]string{}
		if ok {
			pages[seed] = rootBody
			pageOrder = append(pageOrder, seed)
		}
		var candidates []string
		if ok {
			for _, p := range sameHostMentions(rootBody, u.Hostname(), u.Port()) {
				candidates = append(candidates, origin+p)
			}
		}
		for _, p := range docCandidatePaths {
			candidates = append(candidates, origin+p)
		}
		fetched := 0
		for _, c := range candidates {
			if fetched >= maxDocPages || pages[c] != "" || c == strings.TrimRight(seed, "/") {
				continue
			}
			fetched++
			if body, ok := r.fetchDocPage(ctx, agg, c); ok {
				pages[c] = body
				pageOrder = append(pageOrder, c)
			}
		}

		for _, page := range pageOrder {
			routes := extractDocAnchorRoutes(pages[page])
			if len(routes) == 0 {
				continue
			}
			pagesRead++
			for _, rt := range routes {
				if routesAdded >= maxDocRoutes {
					agg.addWarning("wave3: documentation routes capped at %d", maxDocRoutes)
					return
				}
				routeURL := origin + rt.Path
				if r.scope != nil && !r.scope.Allowed(routeURL) {
					agg.addOutOfScope(hostOnly(routeURL))
					continue
				}
				agg.addEndpoint(EndpointFact{URL: routeURL, Method: rt.Method, Source: "docs-anchor", Confidence: ConfidenceMedium})
				routesAdded++
			}
		}
	}
	if routesAdded > 0 {
		agg.addWarning("wave3: read %d API route(s) from the route anchors of %d documentation page(s)", routesAdded, pagesRead)
	}
}

// fetchDocPage GETs one URL and returns its body when it is a 200 HTML page, under
// the same scope gate, rate limit and per-host circuit breaker as every other
// live probe here. Nothing is recorded; the caller reads routes from the body.
func (r *Recon) fetchDocPage(ctx context.Context, agg *aggregator, pageURL string) (string, bool) {
	host := hostOnly(pageURL)
	if r.hostErrors.ShouldSkip(host) {
		return "", false
	}
	if r.scope != nil && !r.scope.Allowed(pageURL) {
		agg.addOutOfScope(host)
		return "", false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return "", false
	}
	r.applyHeaders(req)
	req.Header.Set("Accept", "text/html")
	resp, err := r.client.Do(req)
	if err != nil {
		if !isRequestTimeout(err) {
			r.hostErrors.RecordError(host)
		}
		return "", false
	}
	defer func() { _ = resp.Body.Close() }()
	r.hostErrors.RecordSuccess(host)
	if resp.StatusCode != http.StatusOK || !strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "html") {
		return "", false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDocPageBytes))
	if err != nil {
		return "", false
	}
	return string(body), true
}
