package recon

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
)

// Credential is the owner token an operator chose to let recon use (LT-187),
// with the one origin it may be sent to. Every recon entry point (the agent CLI,
// the web UI, the MCP server) builds it the same way so they cannot drift on
// where the token goes.
//
// It reaches recon through two channels, both scoped to Origin (see
// httpclient.WithHostHeadersUnless and WithCrawlHeaders): recon's own HTTP
// client, and the katana crawl. httpx, which probes many hosts, never gets it.
// A URL that looks state-changing (StateChangingURL) is requested without it.
type Credential struct {
	Origin string
	Header map[string]string
}

// NewCredential builds the credential header from token, using the same
// defaults the detectors use ("Authorization: Bearer {token}") so recon and the
// leaf dispatches present one identity. target is the scan target; a scheme-less
// one gets https, as recon itself does.
func NewCredential(target, token, headerName, headerFormat string) (*Credential, error) {
	if token == "" {
		return nil, errors.New("recon authentication needs an owner token")
	}
	if headerName == "" {
		headerName = "Authorization"
	}
	if headerFormat == "" {
		headerFormat = "Bearer {token}"
	}
	if !strings.Contains(headerFormat, "{token}") {
		return nil, fmt.Errorf("auth header format must contain a {token} placeholder, got %q", headerFormat)
	}
	origin := target
	if !strings.Contains(origin, "://") {
		origin = "https://" + origin
	}
	return &Credential{Origin: origin, Header: map[string]string{headerName: strings.Replace(headerFormat, "{token}", token, 1)}}, nil
}

// Middleware is the HTTP client half: add it to the client recon is built with.
func (c *Credential) Middleware() httpclient.Middleware {
	return httpclient.WithHostHeadersUnless(c.Origin, c.Header, StateChangingURL)
}

// Option is the recon half: pass it to New. It carries the crawl and the direct
// probes; the shared client's half is Middleware.
func (c *Credential) Option() Option { return WithCredential(c) }

// HeaderNames lists the header names it sets, for a note to the operator (never the values).
func (c *Credential) HeaderNames() []string {
	names := make([]string, 0, len(c.Header))
	for k := range c.Header {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// Note is the one line an entry point shows the operator when recon is authenticated.
func (c *Credential) Note() string {
	return fmt.Sprintf("recon-auth: recon requests to %s carry the %s header (read-only requests; URLs that look state-changing are sent without it); no other host receives it",
		c.Origin, strings.Join(c.HeaderNames(), ", "))
}
