// Package oob is a first-party, stdlib-only client for the Interactsh HTTP
// polling protocol — reverse-engineered directly from
// github.com/projectdiscovery/interactsh@v1.3.1/pkg/client's real source
// (registration/poll/deregister JSON shapes, RSA-OAEP+AES-256-CTR
// interaction encryption), not guessed or approximated. Written first-party
// instead of importing that package because its client subpackage
// transitively pulls in interactsh's own server/storage internals (~130
// new go.mod entries: an embedded DB, host-introspection libraries, an FTP
// server) for a small slice of functionality — see
// docs/13-implementation-plan-ph4.md Step 2's Dependencies note.
//
// Non-negotiable per that doc: preserve Interactsh's real per-client-keypair
// encryption, not just its polling mechanism — a plaintext-polling fallback
// would silently drop the confidentiality property self-hosting exists for
// in the first place. This does: every interaction payload is still
// RSA-OAEP+AES-256-CTR encrypted exactly as the real client/server pair
// does, so a compromised or merely curious operator of the self-hosted OOB
// box still can't read intercepted data in cleartext.
//
// Promoted here from pkg/detectors/ssrf/oob_client.go
// (docs/14-implementation-plan-ph5.md Step 3's R1b) once a second consumer
// (pkg/recon's future blind-check infrastructure, and later blind XSS/SQLi
// detectors) needed the same correlation-URL/callback-channel mechanism —
// same "promote once a second consumer needs it" discipline as every other
// shared type in this project. No behavior change from the original.
package oob

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// retryAttempts/retryBackoff exist because public Interactsh servers
// individually drop or tarpit a meaningful fraction of requests — confirmed
// live (docs/discussions.md, 2026-09-02): a single well-formed register
// request via curl and via this package's own single-attempt client both
// hung for the server's full connection lifetime with zero bytes back on
// oast.pro/oast.live/oast.fun, while the official interactsh-client (which
// retries up to 5x via retryablehttp-go) succeeded from the same network
// moments later. This isn't a protocol bug — it's the normal operating
// reality of free, heavily-used public OOB infrastructure, and a
// single-attempt client is simply the wrong shape for talking to it.
const retryAttempts = 3

var retryBackoff = []time.Duration{1 * time.Second, 2 * time.Second}

// withRetry runs do up to retryAttempts times, waiting the matching
// retryBackoff entry (the last entry repeats for any further attempt)
// between tries, and returns the final attempt's error if none succeed.
func withRetry(ctx context.Context, do func() error) error {
	var lastErr error
	for attempt := 0; attempt < retryAttempts; attempt++ {
		if attempt > 0 {
			wait := retryBackoff[len(retryBackoff)-1]
			if attempt-1 < len(retryBackoff) {
				wait = retryBackoff[attempt-1]
			}
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if err := do(); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	return lastErr
}

// Client is a registered Interactsh-protocol session against one self-hosted
// server.
type Client struct {
	serverURL     string
	correlationID string
	secretKey     string
	privKey       *rsa.PrivateKey
	pubKeyB64     string
	httpClient    *http.Client
}

// CorrelationIDLen/NonceLen match Interactsh's own real defaults
// (settings.CorrelationIdLengthDefault/CorrelationIdNonceLengthDefault) —
// not required to match for the protocol to work (the server just stores
// whatever the client claims), but matching keeps generated hostnames a
// familiar, expected shape.
const (
	CorrelationIDLen = 20
	NonceLen         = 13
)

// Interaction mirrors the subset of Interactsh's real Interaction JSON
// shape callers actually use.
type Interaction struct {
	Protocol      string `json:"protocol"`
	UniqueID      string `json:"unique-id"`
	FullID        string `json:"full-id"`
	RawRequest    string `json:"raw-request"`
	RemoteAddress string `json:"remote-address"`
}

type registerRequest struct {
	PublicKey     string `json:"public-key"`
	SecretKey     string `json:"secret-key"`
	CorrelationID string `json:"correlation-id"`
}

type deregisterRequest struct {
	CorrelationID string `json:"correlation-id"`
	SecretKey     string `json:"secret-key"`
}

type pollResponse struct {
	Data   []string `json:"data"`
	Extra  []string `json:"extra"`
	AESKey string   `json:"aes_key"`
}

// NewClientWithFallback tries servers in order, returning the first one
// that accepts registration — the ordered-fallback behavior a repeatable
// --oob-server flag enables (e.g. expanding "public" to a known public
// server pool, so one server being down doesn't stall the whole check).
// Returns an error only if every server in the list fails.
func NewClientWithFallback(ctx context.Context, httpClient *http.Client, servers []string) (*Client, error) {
	if len(servers) == 0 {
		return nil, fmt.Errorf("oob: no server configured")
	}
	var errs []error
	for _, serverURL := range servers {
		c, err := NewClient(ctx, httpClient, serverURL)
		if err == nil {
			return c, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", serverURL, err))
	}
	return nil, fmt.Errorf("oob: every server failed registration: %w", errors.Join(errs...))
}

// NewClient generates a fresh RSA keypair and correlation ID, then registers
// with serverURL — a self-hosted server the caller runs themselves, never a
// silent public default. serverURL must already include a scheme.
func NewClient(ctx context.Context, httpClient *http.Client, serverURL string) (*Client, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("oob: generating rsa key: %w", err)
	}
	pubKeyB64, err := encodePublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("oob: encoding public key: %w", err)
	}

	c := &Client{
		serverURL:     strings.TrimRight(serverURL, "/"),
		correlationID: randomHexID(CorrelationIDLen),
		secretKey:     randomHexID(32),
		privKey:       priv,
		pubKeyB64:     pubKeyB64,
		httpClient:    httpClient,
	}
	if err := c.register(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Client) register(ctx context.Context) error {
	body, err := json.Marshal(registerRequest{PublicKey: c.pubKeyB64, SecretKey: c.secretKey, CorrelationID: c.correlationID})
	if err != nil {
		return fmt.Errorf("oob: marshaling register request: %w", err)
	}
	return withRetry(ctx, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.serverURL+"/register", bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("oob: building register request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("oob: registering with server %s: %w", c.serverURL, err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			data, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("oob: server rejected registration: %s", string(data))
		}
		return nil
	})
}

// NewPayloadHost returns a fresh, unique hostname (a correlationID+nonce
// subdomain of the OOB server's own host) to embed in one probe's URL —
// call once per probe, not once per Client: nonce is what lets Poll
// attribute a returned interaction back to the specific probe that
// triggered it.
func (c *Client) NewPayloadHost() (host, nonce string) {
	nonce = randomHexID(NonceLen)
	bareHost := strings.TrimPrefix(strings.TrimPrefix(c.serverURL, "https://"), "http://")
	return c.correlationID + nonce + "." + bareHost, nonce
}

// Poll fetches and decrypts every interaction recorded since the last poll
// (or since registration).
func (c *Client) Poll(ctx context.Context) ([]Interaction, error) {
	pollURL := fmt.Sprintf("%s/poll?id=%s&secret=%s", c.serverURL, c.correlationID, c.secretKey)

	var pr pollResponse
	err := withRetry(ctx, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, pollURL, nil)
		if err != nil {
			return fmt.Errorf("oob: building poll request: %w", err)
		}
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("oob: polling server: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			data, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("oob: server rejected poll: %s", string(data))
		}
		if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
			return fmt.Errorf("oob: decoding poll response: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	var out []Interaction
	for _, encrypted := range pr.Data {
		plaintext, err := c.decrypt(pr.AESKey, encrypted)
		if err != nil {
			continue // one undecryptable interaction shouldn't drop the rest
		}
		var it Interaction
		if err := json.Unmarshal(bytes.TrimSpace(plaintext), &it); err != nil {
			continue
		}
		out = append(out, it)
	}
	for _, plaintext := range pr.Extra {
		var it Interaction
		if err := json.Unmarshal([]byte(plaintext), &it); err != nil {
			continue
		}
		out = append(out, it)
	}
	return out, nil
}

// decrypt reverses the real Interactsh server's encryption exactly:
// aesKeyB64 is RSA-OAEP(SHA-256)-encrypted to our public key; the message
// itself is AES-256-CTR-encrypted with a 16-byte IV prepended to the
// ciphertext.
func (c *Client) decrypt(aesKeyB64, messageB64 string) ([]byte, error) {
	encryptedKey, err := base64.StdEncoding.DecodeString(aesKeyB64)
	if err != nil {
		return nil, err
	}
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, c.privKey, encryptedKey, nil)
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(messageB64)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("oob: ciphertext shorter than one AES block")
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	iv, body := ciphertext[:aes.BlockSize], ciphertext[aes.BlockSize:]
	plaintext := make([]byte, len(body))
	cipher.NewCTR(block, iv).XORKeyStream(plaintext, body)
	return plaintext, nil
}

// Deregister best-effort releases the correlation ID — a failure here
// doesn't matter enough to surface as an error (the server evicts idle
// sessions on its own).
func (c *Client) Deregister(ctx context.Context) {
	body, err := json.Marshal(deregisterRequest{CorrelationID: c.correlationID, SecretKey: c.secretKey})
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.serverURL+"/deregister", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

func encodePublicKey(pub *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: der})
	return base64.StdEncoding.EncodeToString(pemBytes), nil
}

// randomHexID returns n hex characters of crypto/rand-sourced randomness —
// DNS-label-safe (lowercase hex only), unlike Interactsh's own zbase32
// encoding, which this package avoids pulling in as a dependency just for
// this.
func randomHexID(n int) string {
	b := make([]byte, (n+1)/2)
	_, _ = rand.Read(b)
	s := hex.EncodeToString(b)
	if len(s) > n {
		s = s[:n]
	}
	return s
}
