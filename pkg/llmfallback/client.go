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

	// requestTimeout must cover the slowest real call this client makes:
	// ResolveLeaf's draft-template authoring call generates a full YAML
	// template plus (for reasoning-capable models) hidden reasoning tokens,
	// and was observed live to exceed 60s and time out mid-response-body-
	// read against a real OpenRouter model — classification/triage/field
	// calls finish in a few seconds, so this ceiling is sized for the
	// outlier, not the common case.
	requestTimeout = 180 * time.Second
)

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
}

// New builds a Client from environment variables. It does not error when a
// tier is unconfigured — a Client with only one tier available is valid
// (e.g. local-only in an offline lab environment); it only errors when
// neither tier is usable, since every fallback call would otherwise fail
// anyway.
func New() (*Client, error) {
	c := &Client{
		httpClient: &http.Client{Timeout: requestTimeout},

		localURL:   strings.TrimSuffix(getenvDefault(envLocalModelURL, defaultLocalModelURL), "/"),
		localModel: getenvDefault(envLocalModelName, defaultLocalModelName),

		openRouterKey:   os.Getenv(envOpenRouterKey),
		openRouterModel: getenvDefault(envOpenRouterModel, defaultOpenRouterModel),
	}
	c.openRouterInputUSD = getenvFloat(envOpenRouterInputPrice, 3.0)
	c.openRouterOutputUSD = getenvFloat(envOpenRouterOutPrice, 15.0)
	c.localAvailable = c.localReachable()

	if c.openRouterKey == "" && !c.localAvailable {
		return nil, ErrNoTierAvailable
	}
	return c, nil
}

// getenvDefault falls back to fallback only when key is entirely unset —
// an operator who explicitly sets key to an empty value (e.g.
// HACKERFIVE_LOCAL_MODEL_URL= in a .env, to say "I have no local model
// runtime, don't try") gets that empty value honored, not silently
// replaced with the built-in default (found live, 2026-09-04: the old
// os.Getenv-based check couldn't tell "explicitly cleared" apart from
// "never set" — clearing HACKERFIVE_LOCAL_MODEL_URL still fell back to
// http://localhost:11434, so New() kept probing and failing against a
// runtime that was never installed).
func getenvDefault(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
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
