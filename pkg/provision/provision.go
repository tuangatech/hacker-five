// Package provision implements --auto-provision-account: registering a
// throwaway account against a target's own signup endpoint so idor's
// baseline mode and authbypass's token-reuse/BFLA checks get a second,
// unrelated account's token without an operator having to find/create one
// by hand and pass it via --other-auth-token.
//
// Deliberately its own package, not pkg/detectors (this produces a token,
// not a detectors.Finding) and not pkg/recon (this mutates target state —
// recon's own invariant is read/enumerate-only). Gated behind a dedicated
// --auto-provision-account flag, never --allow-writes: CLAUDE.md scopes that
// flag to pkg/detectors/businesslogic's mutating checks only, and creating a
// persistent account on a real program is its own distinct class of side
// effect.
//
// No cleanup/deprovisioning is attempted — an accepted limitation, the same
// category of residual side effect --allow-writes' coupon-mint checks
// already accept. The created email is returned so the caller can log it for
// the operator to manually close the account later if a program's ToS
// requires it.
package provision

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
)

// maxResponseBodyBytes bounds how much of a signup/login response
// extractToken reads — a real registration/login response is a few hundred
// bytes to a few KiB of JSON; generous headroom without reading unboundedly.
const maxResponseBodyBytes = 1 << 20

// tokenFieldNames are the common JSON key names a signup/login response
// carries a usable auth token under — the same key-name set
// tests/integration/scripts/crapi_setup.sh's proven jq -r '.token' shape
// confirms works for crAPI, widened with the other common castings real
// frameworks use.
var tokenFieldNames = []string{"token", "access_token", "accessToken", "jwt", "auth_token"}

// Result carries what ProvisionAccount created — logged by the caller so the
// operator can manually close the account later if a program's ToS requires
// it (no automated cleanup — see package doc). Only ever returned alongside
// a usable Token; a run that can't extract one returns an error instead.
type Result struct {
	Email string
	Token string
}

// ProvisionAccount registers a throwaway account against signupURL/method (a
// recon-observed candidate, recon.ReconResult.SignupEndpoint) and returns a
// usable auth token for it. emailTemplate is the operator-supplied
// --provision-email value (e.g. "you+{{rand}}@yourdomain.com"); "{{rand}}"
// is substituted with a short random token per call so repeated runs don't
// collide on a unique-email constraint.
//
// Fails closed rather than guessing: if no token can be extracted from
// either the signup response or a login-fallback (the same signup-then-login
// shape crapi_setup.sh already proves works against a real target), it
// returns a clear error naming the likely cause — most commonly an
// email-verification gate this package can't clear — instead of retrying
// forever or fabricating a token. The scan then proceeds without a second
// account exactly as it does today when --other-auth-token is never passed.
func ProvisionAccount(ctx context.Context, client *httpclient.Client, signupURL, method, emailTemplate string) (Result, error) {
	if emailTemplate == "" {
		return Result{}, fmt.Errorf("provision: emailTemplate is required")
	}
	if method == "" {
		method = http.MethodPost
	}
	email := renderEmailTemplate(emailTemplate)
	username := "hackerfive" + randomHex(6)
	password := "Hf!" + randomHex(12)

	signupBody := fmt.Sprintf(
		`{"email":%q,"username":%q,"name":%q,"password":%q,"password_confirmation":%q,"confirm_password":%q}`,
		email, username, username, password, password, password,
	)
	respBody, status, err := doJSON(ctx, client, method, signupURL, signupBody)
	if err != nil {
		return Result{}, fmt.Errorf("provision: signup request to %s: %w", signupURL, err)
	}
	if status < 200 || status >= 300 {
		return Result{}, fmt.Errorf("provision: signup at %s returned status %d", signupURL, status)
	}
	if token := extractToken(respBody); token != "" {
		return Result{Email: email, Token: token}, nil
	}

	// Signup succeeded but carried no token — fall back to a login with the
	// credentials just created, same dual-path shape
	// tests/integration/scripts/crapi_setup.sh already proves works live.
	loginURL := siblingLoginURL(signupURL)
	loginBody := fmt.Sprintf(`{"email":%q,"password":%q}`, email, password)
	if loginRespBody, loginStatus, err := doJSON(ctx, client, http.MethodPost, loginURL, loginBody); err == nil && loginStatus >= 200 && loginStatus < 300 {
		if token := extractToken(loginRespBody); token != "" {
			return Result{Email: email, Token: token}, nil
		}
	}

	return Result{}, fmt.Errorf("provision: registration for %s succeeded but no token was found (tried signup response and a login fallback) — target likely requires email verification before the account is usable; supply --other-auth-token manually instead", email)
}

// renderEmailTemplate substitutes "{{rand}}" in tmpl with a short random
// token — the only placeholder this supports, matching the "names only, no
// values invented beyond what the operator explicitly asked for" discipline
// the rest of this codebase already uses for recon-derived candidates.
func renderEmailTemplate(tmpl string) string {
	return strings.ReplaceAll(tmpl, "{{rand}}", randomHex(6))
}

// siblingLoginURL swaps a signup-shaped path segment for "login" — the
// login-fallback URL when a signup response carries no token itself. Best
// effort: if none of the known signup-shaped substrings are present, the
// original URL is returned unchanged and the caller's login attempt simply
// fails closed like any other unreachable endpoint.
func siblingLoginURL(signupURL string) string {
	u, err := url.Parse(signupURL)
	if err != nil {
		return signupURL
	}
	replacer := strings.NewReplacer(
		"signup", "login", "Signup", "Login", "SignUp", "Login",
		"sign-up", "login", "sign_up", "login",
		"register", "login", "Register", "Login", "registration", "login",
	)
	u.Path = replacer.Replace(u.Path)
	return u.String()
}

// doJSON fires one JSON-body request, mirroring the same
// fmt.Sprintf+%q-into-hand-written-JSON + Content-Type idiom
// pkg/detectors/businesslogic and pkg/detectors/authbypass already use for
// their own mutating/probing requests.
func doJSON(ctx context.Context, client *httpclient.Client, method, rawURL, body string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, bytes.NewReader([]byte(body)))
	if err != nil {
		return nil, 0, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return respBody, resp.StatusCode, nil
}

// extractToken scans body's top-level fields, and one level of nesting (a
// common "{"data": {"token": "..."}}" / "{"user": {"token": "..."}}" API
// response shape), for tokenFieldNames — "" if none match or body isn't a
// JSON object.
func extractToken(body []byte) string {
	var top map[string]json.RawMessage
	if json.Unmarshal(body, &top) != nil {
		return ""
	}
	if t := findTokenField(top); t != "" {
		return t
	}
	for _, raw := range top {
		var nested map[string]json.RawMessage
		if json.Unmarshal(raw, &nested) == nil {
			if t := findTokenField(nested); t != "" {
				return t
			}
		}
	}
	return ""
}

// findTokenField returns the first non-empty string value found under any
// of tokenFieldNames (case-insensitive key match) in m.
func findTokenField(m map[string]json.RawMessage) string {
	for _, name := range tokenFieldNames {
		for k, v := range m {
			if !strings.EqualFold(k, name) {
				continue
			}
			var s string
			if json.Unmarshal(v, &s) == nil && s != "" {
				return s
			}
		}
	}
	return ""
}

// randomHex returns n hex characters of crypto/rand-sourced randomness —
// mirrors pkg/detectors/businesslogic's randomHex helper exactly (kept as a
// local copy rather than an exported dependency: neither package has any
// other reason to depend on the other).
func randomHex(n int) string {
	b := make([]byte, (n+1)/2)
	_, _ = rand.Read(b)
	s := hex.EncodeToString(b)
	if len(s) > n {
		s = s[:n]
	}
	return s
}
