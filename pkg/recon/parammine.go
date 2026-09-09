package recon

import (
	"bufio"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/scanner/scope"
)

//go:embed wordlists/params.txt
var embeddedParamWordlist string

const (
	// maxParamMineRequests is the hard ceiling on requests the whole
	// hidden-parameter pass issues in one recon run — it can't starve the
	// shared --rate-limit bucket (LT-98, docs/follow-up.md).
	// --param-mining-request-cap overrides it.
	maxParamMineRequests = 160
	// maxParamMineEndpoints bounds how many seed endpoints get mined so the
	// request cap buys real depth on a few endpoints rather than a shallow
	// sweep of many.
	maxParamMineEndpoints = 6
	// paramMineBatchSize is how many candidate names ride one request.
	paramMineBatchSize = 24
	// paramMineBodyCap bounds the response body the diff oracle reads.
	paramMineBodyCap = 256 << 10
	// paramMineMaxPerEndpoint caps distinct params emitted for one endpoint;
	// exceeding it means the endpoint echoes/accepts params indiscriminately,
	// so its whole result set is dropped as a reflect-all sink.
	paramMineMaxPerEndpoint = 6
	// paramMineReflectAllThreshold: a single batch reflecting more than this
	// many distinct markers is a reflect-all endpoint.
	paramMineReflectAllThreshold = 8
	// paramMineMaxNames caps a large --param-mining-wordlist so it can't blow
	// past the per-host request-cap intent.
	paramMineMaxNames = 2000
)

// validParamName is the shape a candidate name must have to be probed —
// leading letter/underscore, then word chars / dot / dash, <= 40 long. Keeps
// a malformed wordlist line out of the query string.
var validParamName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,39}$`)

// paramNameEchoStoplist are candidate names common enough to appear in an
// ordinary page body (nav labels, microdata, other forms) — a name-echo
// signal on one of these is not evidence the endpoint honours it, so
// name-echo is not counted for them. Reflection of the sent marker value
// still is.
var paramNameEchoStoplist = map[string]bool{
	"id": true, "no": true, "num": true, "number": true, "name": true, "key": true,
	"page": true, "data": true, "type": true, "view": true, "date": true, "year": true,
	"month": true, "day": true, "from": true, "to": true, "end": true, "start": true,
	"q": true, "s": true, "search": true, "query": true, "sort": true, "order_by": true,
	"filter": true, "status": true, "state": true, "category": true, "cat": true,
	"tag": true, "tags": true, "count": true, "limit": true, "offset": true,
	"role": true, "access": true, "admin": true, "test": true, "mode": true,
	"show": true, "edit": true, "config": true, "title": true, "content": true,
	"message": true, "error": true, "url": true, "link": true, "source": true,
	"user": true, "account": true, "email": true, "lang": true, "language": true,
}

// reqBudget is a simple shared request counter for the per-host cap.
type reqBudget struct {
	n   int
	max int
}

func (b *reqBudget) spent() int { return b.n }
func (b *reqBudget) exhausted() bool {
	return b.n >= b.max
}
func (b *reqBudget) inc() { b.n++ }

// runParamMining is LT-100's opt-in hidden-parameter pass (docs/follow-up.md):
// for the most promising GET endpoints it probes a curated candidate-name
// list through the rate-limited recon client and emits only params the app
// measurably honours (>= 2 independent diff-oracle signals) as
// wave3-param-mining EndpointFacts, which SuggestSSRFParamsFromRecon /
// SuggestIDOREndpointCandidates then read like any other observed param.
// Bounded by a hard per-host request cap so it can't starve --rate-limit.
func (r *Recon) runParamMining(ctx context.Context, agg *aggregator, seeds []string) {
	if !r.paramMining {
		return
	}
	names, provenance, err := r.paramCandidateNames()
	if err != nil {
		agg.addWarning("wave3: param-mining: %v — skipped", err)
		return
	}
	reqCap := r.paramMineRequestCap
	if reqCap <= 0 {
		reqCap = maxParamMineRequests
	}

	targets := selectParamMineTargets(agg.endpoints, seeds, r.scope)
	if len(targets) == 0 {
		return
	}

	nonce := "hfpm" + randToken()
	budget := &reqBudget{max: reqCap}
	discovered, reflectAll := 0, 0
	for _, epURL := range targets {
		if budget.exhausted() {
			break
		}
		found, sink := r.mineEndpointParams(ctx, agg, epURL, names, nonce, budget)
		discovered += found
		if sink {
			reflectAll++
		}
	}
	if budget.spent() == 0 {
		return
	}
	msg := fmt.Sprintf("wave3: param-mining probed %d candidate name(s) over %d endpoint(s) in %d request(s) (cap %d): %d undocumented param(s) corroborated",
		len(names), len(targets), budget.spent(), reqCap, discovered)
	if reflectAll > 0 {
		msg += fmt.Sprintf(", %d endpoint(s) skipped as reflect-all sinks", reflectAll)
	}
	if provenance != "" {
		msg += " [" + provenance + "]"
	}
	agg.addWarning("%s", msg)
}

// paramCandidateNames loads and normalises the candidate list — the embedded
// default, or --param-mining-wordlist when set. Returns a short provenance
// label for the summary warning.
func (r *Recon) paramCandidateNames() (names []string, provenance string, err error) {
	src := embeddedParamWordlist
	provenance = "built-in list"
	if r.paramMiningWordlist != "" {
		b, e := os.ReadFile(r.paramMiningWordlist)
		if e != nil {
			return nil, "", fmt.Errorf("reading --param-mining-wordlist: %w", e)
		}
		src = string(b)
		provenance = "wordlist " + filepath.Base(r.paramMiningWordlist)
	}
	seen := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(src))
	for sc.Scan() {
		line := strings.ToLower(strings.TrimSpace(sc.Text()))
		if line == "" || strings.HasPrefix(line, "#") || seen[line] || !validParamName.MatchString(line) {
			continue
		}
		seen[line] = true
		names = append(names, line)
	}
	if len(names) == 0 {
		return nil, "", errors.New("no usable candidate names in the wordlist")
	}
	if len(names) > paramMineMaxNames {
		names = names[:paramMineMaxNames]
	}
	return names, provenance, nil
}

// selectParamMineTargets ranks the aggregated endpoints and returns the top
// maxParamMineEndpoints worth mining: GET, in-scope, a real (non-asset,
// plausible) path, and a status that means the endpoint exists (2xx / 401 /
// 403). An endpoint that already carries a query string, or sits under an
// API-ish path, ranks higher. Deduplicated by path.
func selectParamMineTargets(endpoints []EndpointFact, seeds []string, sc *scope.Scope) []string {
	seedHosts := make(map[string]bool, len(seeds))
	for _, s := range seeds {
		seedHosts[NormalizeHost(hostOnly(s))] = true
	}
	type cand struct {
		url  string
		rank int
	}
	var cands []cand
	seenPath := map[string]bool{}
	for _, ep := range endpoints {
		if ep.Method != "" && !strings.EqualFold(ep.Method, http.MethodGet) {
			continue
		}
		switch {
		case ep.StatusCode >= 200 && ep.StatusCode < 300:
		case ep.StatusCode == http.StatusUnauthorized || ep.StatusCode == http.StatusForbidden:
		default:
			continue
		}
		u, err := url.Parse(ep.URL)
		if err != nil || u.Host == "" {
			continue
		}
		host := hostOnly(ep.URL)
		if !seedHosts[NormalizeHost(host)] {
			if sc == nil || !sc.Allowed("https://"+host) {
				continue
			}
		}
		p := u.Path
		if p == "" || IsNonRouteAssetPath(p) || !IsPlausibleURLPath(p) {
			continue
		}
		key := host + " " + p
		if seenPath[key] {
			continue
		}
		seenPath[key] = true

		rank := 0
		if u.RawQuery != "" {
			rank += 2
		}
		lp := strings.ToLower(p)
		if strings.Contains(lp, "/api/") || strings.HasPrefix(lp, "/api") || strings.Contains(lp, "/v1/") || strings.Contains(lp, "/v2/") {
			rank += 2
		}
		if strings.Count(strings.Trim(p, "/"), "/") >= 1 {
			rank++
		}
		cands = append(cands, cand{url: ep.URL, rank: rank})
	}
	sort.SliceStable(cands, func(a, b int) bool { return cands[a].rank > cands[b].rank })
	if len(cands) > maxParamMineEndpoints {
		cands = cands[:maxParamMineEndpoints]
	}
	out := make([]string, len(cands))
	for i, c := range cands {
		out[i] = c.url
	}
	return out
}

// mineEndpointParams probes every candidate name against one endpoint and
// records the corroborated ones as wave3-param-mining EndpointFacts. Returns
// how many it emitted and whether the endpoint was a reflect-all sink
// (nothing emitted, endpoint abandoned).
func (r *Recon) mineEndpointParams(ctx context.Context, agg *aggregator, epURL string, names []string, nonce string, budget *reqBudget) (found int, reflectAllSink bool) {
	host := hostOnly(epURL)
	if r.hostErrors.ShouldSkip(host) {
		return 0, false
	}
	base, ok := r.paramMineBaseline(ctx, epURL, nonce, budget)
	if !ok {
		return 0, false
	}
	if base.reflectsNonce {
		agg.addWarning("wave3: param-mining: %s reflects an unsent marker — skipped as a reflect-all sink", epURL)
		return 0, true
	}

	hits := map[string]int{} // param name -> observed status on the batch that corroborated it
	for start := 0; start < len(names); start += paramMineBatchSize {
		if budget.exhausted() {
			break
		}
		batch := names[start:min(start+paramMineBatchSize, len(names))]
		markers := make([]string, len(batch))
		for i := range batch {
			markers[i] = fmt.Sprintf("%sp%03d", nonce, start+i)
		}
		status, bodyLow, err := r.paramMineProbe(ctx, epURL, batch, markers, budget)
		if err != nil {
			if !isRequestTimeout(err) {
				r.hostErrors.RecordError(host)
			}
			continue
		}
		r.hostErrors.RecordSuccess(host)

		reflected := indexSet(markers, func(m string) bool { return strings.Contains(bodyLow, strings.ToLower(m)) })
		if n := countTrue(reflected); n > paramMineReflectAllThreshold {
			agg.addWarning("wave3: param-mining: %s reflected %d markers in one batch — skipped as a reflect-all sink", epURL, n)
			return 0, true
		}
		nameEcho := indexSet(batch, func(name string) bool {
			return len(name) >= 4 && !paramNameEchoStoplist[name] &&
				strings.Contains(bodyLow, name) && !strings.Contains(base.bodyLow, name)
		})
		statusChanged := !base.statusNoisy && statusClass(status) != statusClass(base.status)
		lenShift := !base.lenNoisy && bodyLenShiftSignificant(len(bodyLow), base.bodyLen)

		pinpointed := union(reflected, nameEcho)
		solePinpoint := countTrue(pinpointed) == 1

		for i, name := range batch {
			sig := 0
			if reflected[i] {
				sig++
			}
			if nameEcho[i] {
				sig++
			}
			if solePinpoint && pinpointed[i] && statusChanged {
				sig++
			}
			if solePinpoint && pinpointed[i] && lenShift {
				sig++
			}
			if sig >= 2 {
				if _, dup := hits[name]; !dup {
					hits[name] = status
				}
			}
		}
		if len(hits) > paramMineMaxPerEndpoint {
			agg.addWarning("wave3: param-mining: %s corroborated %d params (> %d) — treating as a reflect-all sink, dropping all", epURL, len(hits), paramMineMaxPerEndpoint)
			return 0, true
		}
	}

	ordered := make([]string, 0, len(hits))
	for name := range hits {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)
	for _, name := range ordered {
		agg.addEndpoint(paramMineFact(epURL, name, hits[name]))
		found++
	}
	return found, false
}

// paramMineBaseline is the diff-oracle control: two identical requests, each
// carrying only an unsent-marker param, establish the endpoint's stable
// status and body length and whether it is too dynamic to trust a
// length/status signal (statusNoisy / lenNoisy). reflectsNonce is the
// reflect-all tell.
type paramMineBaseline struct {
	status        int
	bodyLen       int
	bodyLow       string
	statusNoisy   bool
	lenNoisy      bool
	reflectsNonce bool
}

func (r *Recon) paramMineBaseline(ctx context.Context, epURL, nonce string, budget *reqBudget) (paramMineBaseline, bool) {
	ctrl := []string{nonce + "z"}
	mark := []string{nonce + "zctl"}
	s1, b1, err := r.paramMineProbe(ctx, epURL, ctrl, mark, budget)
	if err != nil {
		return paramMineBaseline{}, false
	}
	if budget.exhausted() {
		return paramMineBaseline{status: s1, bodyLen: len(b1), bodyLow: b1,
			reflectsNonce: strings.Contains(b1, strings.ToLower(nonce))}, true
	}
	s2, b2, err := r.paramMineProbe(ctx, epURL, ctrl, mark, budget)
	if err != nil {
		return paramMineBaseline{status: s1, bodyLen: len(b1), bodyLow: b1,
			reflectsNonce: strings.Contains(b1, strings.ToLower(nonce))}, true
	}
	return paramMineBaseline{
		status:        s2,
		bodyLen:       len(b2),
		bodyLow:       b2,
		statusNoisy:   s1 != s2,
		lenNoisy:      absInt(len(b1)-len(b2)) > max(128, len(b2)/5),
		reflectsNonce: strings.Contains(b1, strings.ToLower(nonce)) || strings.Contains(b2, strings.ToLower(nonce)),
	}, true
}

// paramMineProbe issues one GET with the endpoint's own query string plus
// name=marker for each candidate in the batch, returning the status and a
// lower-cased, capped copy of the body. Counts against the budget.
func (r *Recon) paramMineProbe(ctx context.Context, epURL string, names, markers []string, budget *reqBudget) (status int, bodyLow string, err error) {
	u, err := url.Parse(epURL)
	if err != nil {
		return 0, "", err
	}
	raw := u.RawQuery
	for i, name := range names {
		if raw != "" {
			raw += "&"
		}
		raw += url.QueryEscape(name) + "=" + url.QueryEscape(markers[i])
	}
	u.RawQuery = raw

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, "", err
	}
	r.applyHeaders(req)
	budget.inc()
	resp, err := r.client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, paramMineBodyCap))
	return resp.StatusCode, strings.ToLower(string(body)), nil
}

// paramMineFact builds the wave3-param-mining EndpointFact for a corroborated
// param. An id-shaped key name gets a concrete "1" value so
// idShapedQueryCandidate templates it into an IDOR candidate; every other
// key is left value-less, which SuggestSSRFParamsFromRecon reads on a
// keyword match exactly like a documented spec query key.
func paramMineFact(epURL, name string, status int) EndpointFact {
	u, _ := url.Parse(epURL)
	val := ""
	if looksLikeIDKey(name) {
		val = "1"
	}
	add := name + "=" + val
	if u.RawQuery != "" {
		u.RawQuery += "&" + add
	} else {
		u.RawQuery = add
	}
	return EndpointFact{
		URL:        u.String(),
		Method:     http.MethodGet,
		StatusCode: status,
		Source:     "wave3-param-mining",
		Confidence: ConfidenceMedium,
	}
}

func statusClass(code int) int { return code / 100 }

// bodyLenShiftSignificant reports whether got differs from base by both an
// absolute (> 64 bytes) and a relative (> 5%) margin — a real change in what
// the endpoint returned, not render jitter.
func bodyLenShiftSignificant(got, base int) bool {
	d := absInt(got - base)
	if d <= 64 {
		return false
	}
	if base == 0 {
		return true
	}
	return float64(d)/float64(base) > 0.05
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// indexSet returns a bool slice marking which elements of xs satisfy pred.
func indexSet[T any](xs []T, pred func(T) bool) []bool {
	out := make([]bool, len(xs))
	for i, x := range xs {
		out[i] = pred(x)
	}
	return out
}

// union returns a bool slice true where either a or b is true (same length).
func union(a, b []bool) []bool {
	out := make([]bool, len(a))
	for i := range a {
		out[i] = a[i] || b[i]
	}
	return out
}

func countTrue(xs []bool) int {
	n := 0
	for _, x := range xs {
		if x {
			n++
		}
	}
	return n
}

func randToken() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
