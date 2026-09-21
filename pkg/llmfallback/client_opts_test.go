package llmfallback

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureTransport answers every request with one canned chat-completion body
// and keeps the request bodies it saw, so a test can inspect exactly what the
// client put on the wire for the (URL-hardcoded) OpenRouter tier.
type captureTransport struct {
	reply  string
	bodies [][]byte
}

func (ct *captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	b, _ := io.ReadAll(req.Body)
	ct.bodies = append(ct.bodies, b)
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(ct.reply))),
		Request:    req,
	}, nil
}

func decodeBody(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	return m
}

const okReply = `{"choices":[{"message":{"role":"assistant","content":"{\"kind\":\"stop\"}"},"finish_reason":"stop"}],"usage":{"prompt_tokens":100,"completion_tokens":20}}`

// LT-173: a decision call asks the frontier tier for a capped, low-effort
// response, and a call that did not opt in is byte-for-byte what it was.
func TestCompleteWith_FrontierSendsCapAndReasoningOnlyWhenAsked(t *testing.T) {
	resetGlobalSpendForTest()
	ct := &captureTransport{reply: okReply}
	c := &Client{httpClient: &http.Client{Transport: ct}, openRouterKey: "k", openRouterModel: "m"}

	_, _, err := c.completeWith(context.Background(), tierFrontier, "sys", "user", callOpts{maxTokens: 2048, reasoningEffort: "low"})
	require.NoError(t, err)
	_, _, err = c.complete(context.Background(), tierFrontier, "sys", "user")
	require.NoError(t, err)

	require.Len(t, ct.bodies, 2)
	capped := decodeBody(t, ct.bodies[0])
	assert.EqualValues(t, 2048, capped["max_tokens"])
	assert.Equal(t, map[string]any{"effort": "low"}, capped["reasoning"])

	plain := decodeBody(t, ct.bodies[1])
	assert.NotContains(t, plain, "max_tokens", "a call that did not opt in must not carry a cap")
	assert.NotContains(t, plain, "reasoning", "a call that did not opt in must not carry a reasoning field")
}

// The local runtime has no `reasoning` field; the cap is standard and goes to it.
func TestCompleteWith_LocalTierGetsTheCapButNeverReasoning(t *testing.T) {
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			w.WriteHeader(http.StatusOK)
			return
		}
		got, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(okReply))
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	_, _, err := c.completeWith(context.Background(), tierLocal, "sys", "user", callOpts{maxTokens: 2048, reasoningEffort: "low"})
	require.NoError(t, err)

	body := decodeBody(t, got)
	assert.EqualValues(t, 2048, body["max_tokens"])
	assert.NotContains(t, body, "reasoning")
}

// A model that spends its whole cap on hidden reasoning returns empty content
// with finish_reason "length". That must surface as an error (and still report
// the cost the tokens incurred), never as an empty "answer" a caller parses.
func TestCompleteWith_EmptyLengthResponseIsAnErrorNotAnAnswer(t *testing.T) {
	resetGlobalSpendForTest()
	const truncated = `{"choices":[{"message":{"role":"assistant","content":""},"finish_reason":"length"}],"usage":{"prompt_tokens":100000,"completion_tokens":100000}}`
	ct := &captureTransport{reply: truncated}
	c := &Client{httpClient: &http.Client{Transport: ct}, openRouterKey: "k", openRouterModel: "m", openRouterInputUSD: 1, openRouterOutputUSD: 1}

	text, cost, err := c.completeWith(context.Background(), tierFrontier, "sys", "user", callOpts{maxTokens: 64})
	require.Error(t, err)
	assert.True(t, errors.Is(err, errTruncatedResponse))
	assert.Empty(t, text)
	assert.InDelta(t, 0.2, cost, 0.0001, "the spent tokens are real cost even though nothing usable came back")

	// Without an opt-in cap the same empty body is unchanged behaviour: no error.
	text, _, err = c.complete(context.Background(), tierFrontier, "sys", "user")
	require.NoError(t, err)
	assert.Empty(t, text)
}

func TestDecisionCallOpts_DefaultAndEnvOverride(t *testing.T) {
	// t.Setenv registers the restore; Unsetenv then makes it genuinely "unset".
	t.Setenv(envDecisionReasoningEffort, "")
	require.NoError(t, os.Unsetenv(envDecisionReasoningEffort))
	got := decisionCallOpts()
	assert.Equal(t, decisionMaxTokens, got.maxTokens)
	assert.Equal(t, decisionReasoningEffort, got.reasoningEffort)

	t.Setenv(envDecisionReasoningEffort, "minimal")
	assert.Equal(t, "minimal", decisionCallOpts().reasoningEffort)

	// Explicitly empty = send no reasoning field (the per-model escape hatch),
	// but the cap still applies.
	t.Setenv(envDecisionReasoningEffort, "")
	got = decisionCallOpts()
	assert.Empty(t, got.reasoningEffort)
	assert.Equal(t, decisionMaxTokens, got.maxTokens)
}

func TestDecisionTimeout_IsShorterThanTheGeneralRequestTimeout(t *testing.T) {
	// The client retries once on the deadline, so a stalled decision call costs
	// 2*decisionTimeout (4m) instead of the 2*requestTimeout (8m) it cost before.
	assert.Less(t, decisionTimeout, requestTimeout, "the point of LT-173's deadline is to fail faster than requestTimeout")
}
