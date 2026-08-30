// Package hackerone is a first-party client for HackerOne's Hacker API
// (https://api.hackerone.com/v1/hackers/...) — the API a hacker uses to
// submit a report to a third-party program, distinct from HackerOne's
// Customer/Program API for organizations importing their own findings.
//
// This client only ever creates a private, unsubmitted report_intent
// (state "pending"/"ready_to_submit") from CreateReportIntent. Nothing
// reaches the program until SubmitReportIntent is called separately — and
// in HackerFive, that only happens from cmd/hackerfive/report.go's
// `report submit` command, which requires an explicit --yes flag from a
// human. See CLAUDE.md's HackerOne report-drafting-only invariant and
// docs/13-implementation-plan-ph4.md Step 4.
//
// The exact report_intent create request/response field names below were
// built from HackerOne's documented direct-report-creation schema
// (team_handle/title/vulnerability_information/severity_rating/weakness_id/
// structured_scope_id) applied to the newer report_intents draft endpoint —
// confirm against a real trial call (a deliberately incomplete request's
// 422 field-validation-error body is the fastest way) before relying on
// this against a real account, per doc13 Step 4's verification note.
package hackerone

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const defaultBaseURL = "https://api.hackerone.com/v1/hackers"

// Client authenticates every request with HTTP Basic auth — HackerOne's API
// token identifier as username, token value as password (not OAuth) — per
// https://docs.hackerone.com/en/articles/8544782-api-tokens. Construct
// username/token from HACKERONE_API_USERNAME/HACKERONE_API_TOKEN env vars
// only; never hardcode or accept the token value via a CLI flag (CLAUDE.md's
// credential rule).
type Client struct {
	http               *http.Client
	baseURL            string
	username, apiToken string
}

// Option configures a Client at construction time.
type Option func(*Client)

// WithBaseURL overrides the default HackerOne API base URL — used by tests
// to point at an httptest.Server.
func WithBaseURL(u string) Option {
	return func(c *Client) { c.baseURL = u }
}

// WithHTTPClient overrides the underlying *http.Client.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.http = hc }
}

// New builds a Client. username/apiToken are the API token identifier and
// value respectively — callers are expected to have already sourced them
// from HACKERONE_API_USERNAME/HACKERONE_API_TOKEN.
func New(username, apiToken string, opts ...Option) *Client {
	c := &Client{
		http:     &http.Client{Timeout: 30 * time.Second},
		baseURL:  defaultBaseURL,
		username: username,
		apiToken: apiToken,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// do sends a JSON:API-shaped request (HackerOne's Hacker API follows the
// JSON:API convention — resource ids are strings, payloads nest under
// "data"/"attributes") and decodes a successful response into out (nil to
// discard the body, as SubmitReportIntent does).
func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("hackerone: encoding request body: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return fmt.Errorf("hackerone: building request: %w", err)
	}
	req.SetBasicAuth(c.username, c.apiToken)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("hackerone: %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("hackerone: reading response body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("hackerone: %s %s: unexpected status %d: %s", method, path, resp.StatusCode, respBody)
	}
	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("hackerone: decoding response: %w", err)
		}
	}
	return nil
}

type jsonAPIResource struct {
	ID         string          `json:"id"`
	Type       string          `json:"type"`
	Attributes json.RawMessage `json:"attributes"`
}

type jsonAPIListResponse struct {
	Data []jsonAPIResource `json:"data"`
}

type jsonAPISingleResponse struct {
	Data jsonAPIResource `json:"data"`
}

// Weakness is one entry from a program's CWE-mapped weakness list — its ID
// is what ReportIntentInput.WeaknessID needs.
type Weakness struct {
	ID          string
	Name        string
	ExternalID  string // CWE identifier, e.g. "79"
}

type weaknessAttributes struct {
	Name       string `json:"name"`
	ExternalID string `json:"external_id"`
}

// ListWeaknesses fetches programHandle's CWE-mapped weakness list —
// GET /programs/{handle}/weaknesses.
func (c *Client) ListWeaknesses(ctx context.Context, programHandle string) ([]Weakness, error) {
	if programHandle == "" {
		return nil, fmt.Errorf("hackerone: program handle required")
	}
	var resp jsonAPIListResponse
	path := fmt.Sprintf("/programs/%s/weaknesses", url.PathEscape(programHandle))
	if err := c.do(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	weaknesses := make([]Weakness, 0, len(resp.Data))
	for _, r := range resp.Data {
		var attrs weaknessAttributes
		if err := json.Unmarshal(r.Attributes, &attrs); err != nil {
			return nil, fmt.Errorf("hackerone: decoding weakness %s: %w", r.ID, err)
		}
		weaknesses = append(weaknesses, Weakness{ID: r.ID, Name: attrs.Name, ExternalID: attrs.ExternalID})
	}
	return weaknesses, nil
}

// Scope is one entry from a program's structured-scope (in-scope asset)
// list — its ID is what ReportIntentInput.StructuredScopeID needs.
// EligibleForSubmission/Instruction matter beyond report-drafting: a false
// EligibleForSubmission means the asset is explicitly out of scope for
// testing at all (e.g. a catch-all "Other Asset" entry), and Instruction
// routinely carries real testing constraints (reachability notes, "don't
// test X here") a caller needs to read before scanning, not just before
// reporting.
type Scope struct {
	ID                    string
	AssetIdentifier       string
	AssetType             string
	EligibleForSubmission bool
	EligibleForBounty     bool
	Instruction           string
	MaxSeverity           string
}

type scopeAttributes struct {
	AssetIdentifier       string `json:"asset_identifier"`
	AssetType             string `json:"asset_type"`
	EligibleForSubmission bool   `json:"eligible_for_submission"`
	EligibleForBounty     bool   `json:"eligible_for_bounty"`
	Instruction           string `json:"instruction"`
	MaxSeverity           string `json:"max_severity"`
}

// ListStructuredScopes fetches programHandle's in-scope structured assets —
// GET /programs/{handle}/structured_scopes.
func (c *Client) ListStructuredScopes(ctx context.Context, programHandle string) ([]Scope, error) {
	if programHandle == "" {
		return nil, fmt.Errorf("hackerone: program handle required")
	}
	var resp jsonAPIListResponse
	path := fmt.Sprintf("/programs/%s/structured_scopes", url.PathEscape(programHandle))
	if err := c.do(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	scopes := make([]Scope, 0, len(resp.Data))
	for _, r := range resp.Data {
		var attrs scopeAttributes
		if err := json.Unmarshal(r.Attributes, &attrs); err != nil {
			return nil, fmt.Errorf("hackerone: decoding structured scope %s: %w", r.ID, err)
		}
		scopes = append(scopes, Scope{
			ID:                    r.ID,
			AssetIdentifier:       attrs.AssetIdentifier,
			AssetType:             attrs.AssetType,
			EligibleForSubmission: attrs.EligibleForSubmission,
			EligibleForBounty:     attrs.EligibleForBounty,
			Instruction:           attrs.Instruction,
			MaxSeverity:           attrs.MaxSeverity,
		})
	}
	return scopes, nil
}

// ReportIntentInput is everything needed to create a draft report_intent.
// SeverityRating must be one of "none"/"low"/"medium"/"high"/"critical" —
// reporter.hackerOneSeverityRating already maps Finding.Severity onto this
// enum for the offline hackerone-json export format.
type ReportIntentInput struct {
	TeamHandle              string
	Title                   string
	VulnerabilityInformation string
	SeverityRating          string
	WeaknessID              string
	StructuredScopeID       string
	Impact                  string // optional
}

func (in ReportIntentInput) validate() error {
	missing := []string{}
	if in.TeamHandle == "" {
		missing = append(missing, "team handle")
	}
	if in.Title == "" {
		missing = append(missing, "title")
	}
	if in.VulnerabilityInformation == "" {
		missing = append(missing, "vulnerability information")
	}
	if in.SeverityRating == "" {
		missing = append(missing, "severity rating")
	}
	if in.WeaknessID == "" {
		missing = append(missing, "weakness id")
	}
	if in.StructuredScopeID == "" {
		missing = append(missing, "structured scope id")
	}
	if len(missing) > 0 {
		return fmt.Errorf("hackerone: missing required field(s): %v", missing)
	}
	return nil
}

type reportIntentAttributes struct {
	TeamHandle              string `json:"team_handle"`
	Title                   string `json:"title"`
	VulnerabilityInformation string `json:"vulnerability_information"`
	SeverityRating          string `json:"severity_rating"`
	WeaknessID              string `json:"weakness_id"`
	StructuredScopeID       string `json:"structured_scope_id"`
	Impact                  string `json:"impact,omitempty"`
}

type reportIntentCreateRequest struct {
	Data struct {
		Type       string                 `json:"type"`
		Attributes reportIntentAttributes `json:"attributes"`
	} `json:"data"`
}

type reportIntentResponseAttributes struct {
	State string `json:"state"`
}

// CreateReportIntent creates a private, unsubmitted draft report —
// POST /report_intents. Returns the intent's id and its state
// ("pending"/"ready_to_submit"). Never calls submit itself.
func (c *Client) CreateReportIntent(ctx context.Context, in ReportIntentInput) (id, state string, err error) {
	if err := in.validate(); err != nil {
		return "", "", err
	}

	var req reportIntentCreateRequest
	req.Data.Type = "report-intent"
	req.Data.Attributes = reportIntentAttributes(in)

	var resp jsonAPISingleResponse
	if err := c.do(ctx, http.MethodPost, "/report_intents", req, &resp); err != nil {
		return "", "", err
	}
	var attrs reportIntentResponseAttributes
	if err := json.Unmarshal(resp.Data.Attributes, &attrs); err != nil {
		return "", "", fmt.Errorf("hackerone: decoding report_intent response: %w", err)
	}
	return resp.Data.ID, attrs.State, nil
}

// SubmitReportIntent submits an existing draft to its program —
// POST /report_intents/{id}/submit. This is the one call in this package
// that makes a report visible outside the caller's own account; callers
// must gate it behind their own explicit human confirmation (see
// cmd/hackerfive/report.go's `report submit --yes`).
func (c *Client) SubmitReportIntent(ctx context.Context, intentID string) error {
	if intentID == "" {
		return fmt.Errorf("hackerone: intent id required")
	}
	path := fmt.Sprintf("/report_intents/%s/submit", url.PathEscape(intentID))
	return c.do(ctx, http.MethodPost, path, nil, nil)
}
