package llmfallback

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Env vars, per CLAUDE.md ("load credentials from environment variables
// only; never hardcode them"). Prices are per-1M-tokens and env-overridable
// rather than hardcoded as fact — model pricing changes independently of
// this codebase; confirm the real current OpenRouter/local-runtime prices
// at deployment time rather than trusting the fallback defaults below.
const (
	envOpenRouterKey        = "OPENROUTER_API_KEY"
	envOpenRouterModel      = "HACKERFIVE_OPENROUTER_MODEL"
	envOpenRouterInputPrice = "HACKERFIVE_OPENROUTER_PRICE_PER_1M_INPUT_USD"
	envOpenRouterOutPrice   = "HACKERFIVE_OPENROUTER_PRICE_PER_1M_OUTPUT_USD"
	envLocalModelURL        = "HACKERFIVE_LOCAL_MODEL_URL"
	envLocalModelName       = "HACKERFIVE_LOCAL_MODEL_NAME"

	defaultOpenRouterBaseURL = "https://openrouter.ai/api/v1"
	defaultLocalModelURL     = "http://localhost:11434"
	defaultLocalModelName    = "llama3.1"
	// defaultOpenRouterModel is a placeholder, not a verified-current model
	// ID — HACKERFIVE_OPENROUTER_MODEL should be set explicitly per
	// CLAUDE.md's "don't rely on your own knowledge of library/framework
	// versions" discipline, which applies just as much to a model catalog
	// that changes on its own schedule.
	defaultOpenRouterModel = "openrouter/auto"

	// requestTimeout bounds a per-leaf/classification call: ResolveLeaf's
	// classification call and its draft-template authoring follow-up (a
	// full YAML template plus, for reasoning-capable models, hidden
	// reasoning tokens — observed live to exceed 60s), ResolveField.
	requestTimeout = 240 * time.Second

	// requestTimeoutLong bounds the handful of single-shot calls that reason
	// over a whole dataset rather than one leaf/field: PlanFromRecon (the
	// whole summarized recon output), VetPendingLeaves (every StatusPending
	// leaf), TriageFindings and Suggest (every finding in a scan). LT-146
	// (docs/follow-up.md): PlanFromRecon's and VetPendingLeaves' calls both
	// timed out live at the old shared 240s ceiling in one real run against
	// a 24-host target — this gives the whole "one call over everything"
	// shape more room, not just those two observed failures, since
	// TriageFindings/Suggest are structurally identical and would hit the
	// same wall on a large enough scan.
	requestTimeoutLong = 420 * time.Second
)

// heartbeatInterval is LT-146's "still waiting" signal: a call outstanding
// this long gets a periodic log line (via logCB) instead of staying silent
// until it times out or returns — previously indistinguishable from a
// genuine hang, the single biggest complaint from the same live round (zero
// mid-call visibility, only a completion/failure line at the very end). A
// var, not a const, so a test can shrink it rather than waiting out a real
// 30s tick — same convention as pkg/scanner's dispatchHeartbeatInterval.
var heartbeatInterval = 30 * time.Second

// ErrNoTierAvailable is returned when neither a local runtime nor
// OpenRouter is reachable/configured — the caller should treat this exactly
// like an EscalateToHuman result, not a hard failure of the whole plan.
var ErrNoTierAvailable = errors.New("llmfallback: no local model or OpenRouter tier configured/reachable")

// Client is a stateless, tiered chat-completion caller. Safe for concurrent
// use — it holds no per-call state, matching every method's one-shot
// input->output contract.
type Client struct {
	httpClient *http.Client

	localURL       string // always set (defaults to defaultLocalModelURL) — use localAvailable to check usability
	localModel     string
	localAvailable bool // set once at New(), from a startup reachability probe

	openRouterKey       string // "" if unset — frontier tier unavailable
	openRouterModel     string
	openRouterInputUSD  float64 // per 1M input tokens
	openRouterOutputUSD float64 // per 1M output tokens

	logCB func(level, msg string) // nil-safe; see WithLogCallback
}

// Option configures a Client at construction — the same functional-options
// shape idor.Option/misconfig.Option already use in this codebase.
type Option func(*Client)

// WithLogCallback registers fn to receive LT-146's heartbeat ("still
// waiting on <call>, Ns elapsed") and bounded-retry ("<call> timed out —
// retrying once") lines. Additive: a Client with no callback registered
// just never calls it (log/logf below are nil-safe), so every existing
// caller's behavior is unchanged until it opts in. Callers that already
// have a log sink wire it through (CLI's cmd.ErrOrStderr(), webui's
// Job.AppendLog); pkg/mcpserver's plan/triage tools have no sink of their
// own yet (LT-131, docs/follow-up.md) and simply omit this.
func WithLogCallback(fn func(level, msg string)) Option {
	return func(c *Client) { c.logCB = fn }
}

// New builds a Client from environment variables. It does not error when a
// tier is unconfigured — a Client with only one tier available is valid
// (e.g. local-only in an offline lab environment); it only errors when
// neither tier is usable, since every fallback call would otherwise fail
// anyway.
func New(opts ...Option) (*Client, error) {
	c := &Client{
		// The shared http.Client-level timeout is fixed at the longer of
		// the two per-call ceilings below so it never preempts a shorter
		// per-call ctx deadline (completeOnce wraps every real call in its
		// own context.WithTimeout) — this is just the outer backstop.
		httpClient: &http.Client{Timeout: requestTimeoutLong},

		localURL:   strings.TrimSuffix(getenvDefault(envLocalModelURL, defaultLocalModelURL), "/"),
		localModel: getenvDefault(envLocalModelName, defaultLocalModelName),

		openRouterKey:   os.Getenv(envOpenRouterKey),
		openRouterModel: getenvDefault(envOpenRouterModel, defaultOpenRouterModel),
	}
	for _, opt := range opts {
		opt(c)
	}
	c.openRouterInputUSD = getenvFloat(envOpenRouterInputPrice, 3.0)
	c.openRouterOutputUSD = getenvFloat(envOpenRouterOutPrice, 15.0)
	c.localAvailable = c.localReachable()

	if c.openRouterKey == "" && !c.localAvailable {
		return nil, ErrNoTierAvailable
	}
	return c, nil
}

func (c *Client) logf(level, format string, args ...any) {
	if c.logCB != nil {
		c.logCB(level, fmt.Sprintf(format, args...))
	}
}

// getenvDefault falls back to fallback only when key is entirely unset —
// an operator who explicitly sets key to an empty value (e.g.
// HACKERFIVE_LOCAL_MODEL_URL= in a .env, to say "I have no local model
// runtime, don't try") gets that empty value honored, not silently
// replaced with the built-in default (found live, 2026-09-04: the old
// os.Getenv-based check couldn't tell "explicitly cleared" apart from
// "never set" — clearing HACKERFIVE_LOCAL_MODEL_URL still fell back to
// http://localhost:11434, so New() kept probing and failing against a
// runtime that was never installed). A literal "null" (any case,
// surrounding whitespace trimmed) is treated the same as empty — a common
// way an operator unfamiliar with .env's blank-means-unset convention
// spells "no value" (borrowed from JSON/YAML), and taking it literally as
// the local model's URL/name would otherwise silently point this client
// at a nonsensical endpoint instead of actually disabling the tier.
func getenvDefault(key, fallback string) string {
	v, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	if trimmed := strings.TrimSpace(v); trimmed == "" || strings.EqualFold(trimmed, "null") {
		return ""
	}
	return v
}

func getenvFloat(key string, fallback float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return fallback
	}
	return f
}

// localReachable does a best-effort check so New() can fail fast when
// neither tier is usable, rather than every fallback call discovering it
// independently. A local runtime being briefly unreachable at startup but
// available later is treated as "configured" — this is a startup sanity
// check, not a hard gate re-verified per call.
func (c *Client) localReachable() bool {
	if c.localURL == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.localURL+"/v1/models", nil)
	if err != nil {
		return false
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode < 500
}

// chatMessage/chatRequest/chatResponse are the OpenAI-chat-completions-
// compatible shape both OpenRouter and a local Ollama-style runtime's
// /v1/chat/completions endpoint accept (docs/02-architecture-and-tech-
// stack.md §8) — one request/response shape for both tiers.
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
}

type chatResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

// tier identifies which endpoint a call went to, purely for cost accounting
// — local calls are free (self-hosted, no metered API), OpenRouter calls
// are priced per the configured per-1M-token rates.
type tier int

const (
	tierLocal tier = iota
	tierFrontier
)

// complete sends one stateless chat-completion call and returns the raw
// text response plus its real cost in USD (0 for the local tier). system
// should instruct the model to respond with JSON matching the caller's
// target shape and nothing else; complete does not itself enforce a JSON
// schema (neither tier is guaranteed to support one uniformly) — callers
// parse the response themselves via decodeJSONResponse.
func (c *Client) complete(ctx context.Context, t tier, system, user string) (text string, costUSD float64, err error) {
	var url, model, authHeader string
	switch t {
	case tierLocal:
		if !c.localAvailable {
			return "", 0, fmt.Errorf("llmfallback: local tier not available")
		}
		url = c.localURL + "/v1/chat/completions"
		model = c.localModel
	case tierFrontier:
		if c.openRouterKey == "" {
			return "", 0, fmt.Errorf("llmfallback: OpenRouter tier not configured")
		}
		if globalSpendExceeded() {
			return "", 0, errGlobalSpendCeilingExceeded()
		}
		url = defaultOpenRouterBaseURL + "/chat/completions"
		model = c.openRouterModel
		authHeader = "Bearer " + c.openRouterKey
	default:
		return "", 0, fmt.Errorf("llmfallback: unknown tier %d", t)
	}

	body, err := json.Marshal(chatRequest{
		Model: model,
		Messages: []chatMessage{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
		Temperature: 0,
	})
	if err != nil {
		return "", 0, fmt.Errorf("llmfallback: encoding request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", 0, fmt.Errorf("llmfallback: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("llmfallback: request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, fmt.Errorf("llmfallback: reading response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("llmfallback: %s returned %d: %s", url, resp.StatusCode, string(raw))
	}

	var cr chatResponse
	if err := json.Unmarshal(raw, &cr); err != nil {
		return "", 0, fmt.Errorf("llmfallback: decoding response: %w", err)
	}
	if len(cr.Choices) == 0 {
		return "", 0, fmt.Errorf("llmfallback: response had no choices")
	}

	if t == tierFrontier {
		costUSD = float64(cr.Usage.PromptTokens)/1_000_000*c.openRouterInputUSD +
			float64(cr.Usage.CompletionTokens)/1_000_000*c.openRouterOutputUSD
		addGlobalSpend(costUSD) // process-lifetime total, independent of any one Client/plan-call
	}
	return cr.Choices[0].Message.Content, costUSD, nil
}

// completeLabeled wraps complete with LT-146's reliability behavior for one
// logical call: a per-call context deadline (timeout — distinct from
// httpClient's own fixed, longer ceiling, which exists only as an outer
// backstop), a periodic "still waiting" heartbeat via logCB once the call
// has been outstanding past heartbeatInterval, and exactly one retry when
// the failure was specifically this per-call deadline firing — not the
// caller's own ctx already being canceled/expired (the whole operation is
// stopping regardless, a retry would just hang again), and not a real
// API/decode error (retrying an auth failure or a malformed response wastes
// a second call for nothing). label identifies the call in every heartbeat/
// retry line logCB sees — e.g. "ResolveLeaf leaf-10", "PlanFromRecon".
func (c *Client) completeLabeled(ctx context.Context, t tier, system, user, label string, timeout time.Duration) (text string, costUSD float64, err error) {
	text, costUSD, err = c.completeOnce(ctx, t, system, user, label, timeout)
	if err != nil && isOwnTimeout(ctx, err) {
		c.logf("warn", "%s: timed out after %s — retrying once", label, timeout)
		var retryText string
		var retryCost float64
		retryText, retryCost, err = c.completeOnce(ctx, t, system, user, label, timeout)
		costUSD += retryCost
		if err == nil {
			text = retryText
		}
	}
	return text, costUSD, err
}

// completeOnce is one attempt within completeLabeled: a fresh per-call
// deadline plus the heartbeat goroutine, wrapping complete's single HTTP
// round trip. The heartbeat goroutine's stop is synchronous (it waits for
// the goroutine to actually exit, not just signals it to) so no goroutine
// outlives this function, mirroring pkg/scanner's startDispatchHeartbeat
// (LT-149) — the two are independent, package-local implementations of the
// same "periodic progress line on a long operation" shape rather than a
// shared dependency, since each logs through its own package's seam.
func (c *Client) completeOnce(ctx context.Context, t tier, system, user, label string, timeout time.Duration) (string, float64, error) {
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(heartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				c.logf("info", "%s: still waiting on the model, %s elapsed", label, time.Since(start).Round(time.Second))
			case <-done:
				return
			}
		}
	}()

	text, cost, err := c.complete(callCtx, t, system, user)
	close(done)
	<-stopped
	return text, cost, err
}

// isOwnTimeout reports whether err is completeOnce's own per-call deadline
// firing (worth completeLabeled's one retry) rather than the caller's outer
// callerCtx already being canceled/expired, or a non-timeout error.
func isOwnTimeout(callerCtx context.Context, err error) bool {
	return errors.Is(err, context.DeadlineExceeded) && callerCtx.Err() == nil
}

// completeBestAvailableLabeled tries the local tier first, falling back to
// the frontier tier if local errored or isn't available — the tiered
// fallback order every caller in this package shares (ResolveLeaf's
// classification call, ResolveField, PlanFromRecon, TriageFindings,
// VetPendingLeaves, Suggest), routed through completeLabeled so each gets
// LT-146's heartbeat/timeout/retry behavior with a label/timeout it chooses.
func (c *Client) completeBestAvailableLabeled(ctx context.Context, system, user, label string, timeout time.Duration) (string, float64, error) {
	if c.localAvailable {
		text, cost, err := c.completeLabeled(ctx, tierLocal, system, user, label, timeout)
		if err == nil {
			return text, cost, nil
		}
		if c.openRouterKey == "" {
			return "", 0, err
		}
	}
	return c.completeLabeled(ctx, tierFrontier, system, user, label, timeout)
}

// ModelLabel names the model a call would actually use right now: the
// OpenRouter model when the frontier tier is configured (that's the one
// that costs money and the one an accidental HACKERFIVE_OPENROUTER_MODEL
// switch would change), otherwise the local model name. For log lines only
// — LT-37's spend-warning line.
func (c *Client) ModelLabel() string {
	if c.openRouterKey != "" {
		return "openrouter:" + c.openRouterModel
	}
	return "local:" + c.localModel
}

// decodeJSONResponse parses text as JSON into v, tolerating a model
// wrapping its answer in a markdown code fence despite being asked not to
// — the single most common real-world deviation from "respond with JSON
// only" across both local and hosted models.
func decodeJSONResponse(text string, v any) error {
	trimmed := strings.TrimSpace(text)
	trimmed = strings.TrimPrefix(trimmed, "```json")
	trimmed = strings.TrimPrefix(trimmed, "```")
	trimmed = strings.TrimSuffix(trimmed, "```")
	trimmed = strings.TrimSpace(trimmed)
	if err := json.Unmarshal([]byte(trimmed), v); err != nil {
		return fmt.Errorf("llmfallback: model response was not valid JSON: %w (raw: %s)", err, text)
	}
	return nil
}
