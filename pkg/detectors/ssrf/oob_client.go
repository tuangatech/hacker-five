package ssrf

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
)

// oobClient is a first-party, stdlib-only client for the Interactsh HTTP
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
type oobClient struct {
	serverURL     string
	correlationID string
	secretKey     string
	privKey       *rsa.PrivateKey
	pubKeyB64     string
	httpClient    *http.Client
}

// correlationIDLen/nonceLen match Interactsh's own real defaults
// (settings.CorrelationIdLengthDefault/CorrelationIdNonceLengthDefault) —
// not required to match for the protocol to work (the server just stores
// whatever the client claims), but matching keeps generated hostnames a
// familiar, expected shape.
const (
	correlationIDLen = 20
	nonceLen         = 13
)

// oobInteraction mirrors the subset of Interactsh's real Interaction JSON
// shape this detector actually uses.
type oobInteraction struct {
	Protocol      string `json:"protocol"`
	UniqueID      string `json:"unique-id"`
	FullID        string `json:"full-id"`
	RawRequest    string `json:"raw-request"`
	RemoteAddress string `json:"remote-address"`
}

type oobRegisterRequest struct {
	PublicKey     string `json:"public-key"`
	SecretKey     string `json:"secret-key"`
	CorrelationID string `json:"correlation-id"`
}

type oobDeregisterRequest struct {
	CorrelationID string `json:"correlation-id"`
	SecretKey     string `json:"secret-key"`
}

type oobPollResponse struct {
	Data   []string `json:"data"`
	Extra  []string `json:"extra"`
	AESKey string   `json:"aes_key"`
}

// newOOBClient generates a fresh RSA keypair and correlation ID, then
// registers with serverURL — a self-hosted server the user runs
// themselves via --oob-server, never a public default (see doc13's design
// tension 1). serverURL must already include a scheme.
func newOOBClient(ctx context.Context, httpClient *http.Client, serverURL string) (*oobClient, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("ssrf: generating oob rsa key: %w", err)
	}
	pubKeyB64, err := encodeOOBPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("ssrf: encoding oob public key: %w", err)
	}

	c := &oobClient{
		serverURL:     strings.TrimRight(serverURL, "/"),
		correlationID: randomHexID(correlationIDLen),
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

func (c *oobClient) register(ctx context.Context) error {
	body, err := json.Marshal(oobRegisterRequest{PublicKey: c.pubKeyB64, SecretKey: c.secretKey, CorrelationID: c.correlationID})
	if err != nil {
		return fmt.Errorf("ssrf: marshaling oob register request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.serverURL+"/register", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("ssrf: building oob register request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("ssrf: registering with oob server %s: %w", c.serverURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("ssrf: oob server rejected registration: %s", string(data))
	}
	return nil
}

// NewPayloadHost returns a fresh, unique hostname (a correlationID+nonce
// subdomain of the OOB server's own host) to embed in one SSRF probe's URL
// — call once per probe, not once per Client: nonce is what lets Poll
// attribute a returned interaction back to the specific probe that
// triggered it.
func (c *oobClient) NewPayloadHost() (host, nonce string) {
	nonce = randomHexID(nonceLen)
	bareHost := strings.TrimPrefix(strings.TrimPrefix(c.serverURL, "https://"), "http://")
	return c.correlationID + nonce + "." + bareHost, nonce
}

// Poll fetches and decrypts every interaction recorded since the last poll
// (or since registration).
func (c *oobClient) Poll(ctx context.Context) ([]oobInteraction, error) {
	pollURL := fmt.Sprintf("%s/poll?id=%s&secret=%s", c.serverURL, c.correlationID, c.secretKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pollURL, nil)
	if err != nil {
		return nil, fmt.Errorf("ssrf: building oob poll request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ssrf: polling oob server: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ssrf: oob server rejected poll: %s", string(data))
	}

	var pr oobPollResponse
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return nil, fmt.Errorf("ssrf: decoding oob poll response: %w", err)
	}

	var out []oobInteraction
	for _, encrypted := range pr.Data {
		plaintext, err := c.decrypt(pr.AESKey, encrypted)
		if err != nil {
			continue // one undecryptable interaction shouldn't drop the rest
		}
		var it oobInteraction
		if err := json.Unmarshal(bytes.TrimSpace(plaintext), &it); err != nil {
			continue
		}
		out = append(out, it)
	}
	for _, plaintext := range pr.Extra {
		var it oobInteraction
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
func (c *oobClient) decrypt(aesKeyB64, messageB64 string) ([]byte, error) {
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
		return nil, errors.New("ssrf: oob ciphertext shorter than one AES block")
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
// doesn't matter enough to surface as a Run error (the server evicts idle
// sessions on its own).
func (c *oobClient) Deregister(ctx context.Context) {
	body, err := json.Marshal(oobDeregisterRequest{CorrelationID: c.correlationID, SecretKey: c.secretKey})
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

func encodeOOBPublicKey(pub *rsa.PublicKey) (string, error) {
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
