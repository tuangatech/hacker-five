package unit

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/detectors/ssrf"
	"github.com/tuangatech/hacker-five/pkg/oob"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
)

func newSSRFClient() *httpclient.Client {
	return httpclient.New(httpclient.Config{
		Timeout:             5 * time.Second,
		MaxRedirects:        5,
		MaxIdleConnsPerHost: 10,
	})
}

// TestSSRFInternalTarget_Hit mirrors vAPI's real serversurfer response
// shape ({"data": "<base64>"}) — confirmed live against the actual
// endpoint, see docs/13-implementation-plan-ph4.md Step 2.
func TestSSRFInternalTarget_Hit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		url := r.URL.Query().Get("url")
		if url == "http://127.0.0.1/" {
			data := base64.StdEncoding.EncodeToString([]byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin"))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":"` + data + `"}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	detector := ssrf.New(newSSRFClient())
	findings, err := detector.Run(context.Background(), srv.URL, "", []string{"url"}, nil, nil)
	require.NoError(t, err)

	got := withPrefix(findings, "ssrf-internal-target-url-127-0-0-1")
	require.Len(t, got, 1)
	assert.Equal(t, "ssrf", got[0].Type)
	assert.Equal(t, "high", got[0].Severity)
	assert.Equal(t, "high", got[0].Confidence, "decoded payload contains a recognizable /etc/passwd marker")
}

// TestSSRFInternalTarget_EncodedBypass_Hit proves the decimal-encoded
// loopback variant is probed as its own explicit entry, not folded into
// the canonical "127.0.0.1" form — the blocklist-bypass case doc13 calls
// out as where the real findings live.
func TestSSRFInternalTarget_EncodedBypass_Hit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		url := r.URL.Query().Get("url")
		if url == "http://2130706433/" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":"` + base64.StdEncoding.EncodeToString([]byte("root:x:0:0")) + `"}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	detector := ssrf.New(newSSRFClient())
	findings, err := detector.Run(context.Background(), srv.URL, "", []string{"url"}, nil, nil)
	require.NoError(t, err)

	got := withPrefix(findings, "ssrf-internal-target-url-2130706433")
	require.Len(t, got, 1)
}

func TestSSRFInternalTarget_Blocked_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	detector := ssrf.New(newSSRFClient())
	findings, err := detector.Run(context.Background(), srv.URL, "", []string{"url"}, nil, nil)
	require.NoError(t, err)

	assert.Empty(t, withPrefix(findings, "ssrf-internal-target-"))
	assert.Empty(t, withPrefix(findings, "ssrf-cloud-metadata-"))
}

// TestSSRFBodyParamTarget_Hit covers LT-96 (docs/follow-up.md): a target
// that takes the attacker-controlled URL in a JSON request-body field (e.g.
// crAPI's contact_mechanic's repair_url), not a query param.
func TestSSRFBodyParamTarget_Hit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["repair_url"] == "http://127.0.0.1/" {
			data := base64.StdEncoding.EncodeToString([]byte("root:x:0:0:root:/root:/bin/bash"))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":"` + data + `"}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	detector := ssrf.New(newSSRFClient())
	findings, err := detector.Run(context.Background(), srv.URL, "", nil, []string{"repair_url"}, nil)
	require.NoError(t, err)

	got := withPrefix(findings, "ssrf-body-internal-target-repair_url-127-0-0-1")
	require.Len(t, got, 1)
	assert.Equal(t, "ssrf", got[0].Type)
	assert.Equal(t, "high", got[0].Severity)
	assert.Equal(t, "high", got[0].Confidence, "decoded payload contains a recognizable /etc/passwd marker")
	assert.Equal(t, "repair_url", got[0].Evidence["body_field"])
}

// TestSSRFBodyParamTarget_OtherFieldRequired_FillDisabled_NoFinding is
// LT-188 (a)'s root cause, reproduced: a target that validates its other
// required body fields before ever attempting the URL fetch answers the
// same generic error whether the payload is reachable or not (verified live
// against crAPI's contact_mechanic), so the default single-field body can
// never see a fetch happen — with or without a real SSRF underneath.
func TestSSRFBodyParamTarget_OtherFieldRequired_FillDisabled_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["other_field"] == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"message":"other_field is required"}`))
			return
		}
		data := base64.StdEncoding.EncodeToString([]byte("root:x:0:0:root:/root:/bin/bash"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":"` + data + `"}`))
	}))
	defer srv.Close()

	detector := ssrf.New(newSSRFClient())
	findings, err := detector.Run(context.Background(), srv.URL, "", nil, []string{"repair_url"}, nil)
	require.NoError(t, err)

	assert.Empty(t, withPrefix(findings, "ssrf-body-"), "the single-field body never satisfies other_field, so the fetch is never attempted")
}

// TestSSRFBodyParamTarget_WithBodyFill_PastRequiredFieldValidation_Hit is
// the fix: WithBodyFill fills the target's other recovered field names, so
// the same endpoint above now gets past its own validation and the fetch is
// actually attempted and seen.
func TestSSRFBodyParamTarget_WithBodyFill_PastRequiredFieldValidation_Hit(t *testing.T) {
	var postCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		postCount++
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["other_field"] == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"message":"other_field is required"}`))
			return
		}
		if body["repair_url"] == "http://"+r.Host+"/" {
			// WithBodyFill's one internal-network payload is the target's own
			// origin (bodyFillSelfOriginHost), not a fixed 127.0.0.1 — reachable
			// for any target, unlike a container-specific loopback (LT-188 a,
			// found live against crAPI's own multi-container topology).
			data := base64.StdEncoding.EncodeToString([]byte("root:x:0:0:root:/root:/bin/bash"))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":"` + data + `"}`))
			return
		}
		// Validation passes (other_field present) for every other payload too,
		// including the baseline's own unreachable URL — same generic "ok" body,
		// short enough that the baseline comparison never mistakes it for a
		// real fetch of its own accord.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"message":"ok"}`))
	}))
	defer srv.Close()

	detector := ssrf.New(newSSRFClient(), ssrf.WithBodyFill([]string{"repair_url", "other_field"}, nil))
	findings, err := detector.Run(context.Background(), srv.URL, "", nil, []string{"repair_url"}, nil)
	require.NoError(t, err)

	got := withPrefix(findings, "ssrf-body-")
	require.NotEmpty(t, got, "filling other_field gets past validation, so the fetch is now attempted and seen")

	// LT-188 (a)'s own capped payload set: 1 internal address + 1 cloud path +
	// 1 scheme payload, plus the baseline, per body field under test — far
	// fewer requests than the full sweep, since every one may be a live write.
	assert.LessOrEqual(t, postCount, 4, "WithBodyFill sends a capped payload set, not the full sweep")
}

func TestSSRFBodyParamTarget_Blocked_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	detector := ssrf.New(newSSRFClient())
	findings, err := detector.Run(context.Background(), srv.URL, "", nil, []string{"repair_url"}, nil)
	require.NoError(t, err)

	assert.Empty(t, withPrefix(findings, "ssrf-body-"))
}

// TestSSRFBodyParamTarget_NoBodyParams_NoRequests confirms an empty
// bodyParams list makes zero requests — a bare-params ssrf run (query mode
// only) must not silently also probe an empty body-field set.
// TestSSRFBodyParamTarget_WithBodyFill_OmittedForFieldUnderTest confirms
// buildProbeBody never overwrites the field under test with the placeholder
// even when that field's own name is also listed in the fill set (recon's
// recovered key list includes the SSRF candidate itself).
func TestSSRFBodyParamTarget_WithBodyFill_OmittedForFieldUnderTest(t *testing.T) {
	var lastBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&lastBody)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	detector := ssrf.New(newSSRFClient(), ssrf.WithBodyFill([]string{"repair_url", "vin"}, nil))
	_, err := detector.Run(context.Background(), srv.URL, "", nil, []string{"repair_url"}, nil)
	require.NoError(t, err)

	require.NotNil(t, lastBody)
	assert.Equal(t, "hackerfive-probe-value", lastBody["vin"], "the other recovered field gets the placeholder")
	assert.NotEqual(t, "hackerfive-probe-value", lastBody["repair_url"], "the field under test always carries the real payload, never the placeholder")
}

// TestSSRFBodyParamTarget_WithBodyFill_RecoveredLiteralSentVerbatim is
// LT-188 (a)'s live-measured fix: crAPI's contact_mechanic rejects the
// generic placeholder string on its boolean/integer fields just as it
// rejects an absent field, so WithBodyFill's values map (the literal the
// bundle itself declared for that field) has to reach the wire as real JSON
// true/false/a number, never a quoted string.
func TestSSRFBodyParamTarget_WithBodyFill_RecoveredLiteralSentVerbatim(t *testing.T) {
	var lastBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&lastBody)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	detector := ssrf.New(newSSRFClient(), ssrf.WithBodyFill(
		[]string{"repair_url", "repeat_request_if_failed", "number_of_repeats", "unrecovered_field"},
		map[string]string{"repeat_request_if_failed": "false", "number_of_repeats": "1"},
	))
	_, err := detector.Run(context.Background(), srv.URL, "", nil, []string{"repair_url"}, nil)
	require.NoError(t, err)

	require.NotNil(t, lastBody)
	assert.Equal(t, false, lastBody["repeat_request_if_failed"], "a recovered boolean literal is sent as real JSON false, not the placeholder string")
	assert.Equal(t, float64(1), lastBody["number_of_repeats"], "a recovered integer literal is sent as a real JSON number")
	assert.Equal(t, "hackerfive-probe-value", lastBody["unrecovered_field"], "a field with no recovered literal still falls back to the placeholder")
}

func TestSSRFBodyParamTarget_NoBodyParams_NoRequests(t *testing.T) {
	var postCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			postCount++
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	detector := ssrf.New(newSSRFClient())
	_, err := detector.Run(context.Background(), srv.URL, "", []string{"url"}, nil, nil)
	require.NoError(t, err)

	assert.Equal(t, 0, postCount, "no bodyParams means checkBodyParamTargets must not fire at all")
}

func TestSSRFSchemeBased_FileURI_Hit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		url := r.URL.Query().Get("url")
		if url == "file:///etc/passwd" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":"` + base64.StdEncoding.EncodeToString([]byte("root:x:0:0:root:/root:/bin/bash")) + `"}`))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	detector := ssrf.New(newSSRFClient())
	findings, err := detector.Run(context.Background(), srv.URL, "", []string{"url"}, nil, nil)
	require.NoError(t, err)

	got := withPrefix(findings, "ssrf-scheme-based-url-file")
	require.Len(t, got, 1)
	assert.Equal(t, "high", got[0].Confidence)
}

func TestSSRFSchemeBased_Rejected_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	detector := ssrf.New(newSSRFClient())
	findings, err := detector.Run(context.Background(), srv.URL, "", []string{"url"}, nil, nil)
	require.NoError(t, err)

	assert.Empty(t, withPrefix(findings, "ssrf-scheme-based-"))
}

// TestSSRFInternalTarget_ResponseIndistinguishableFromBaseline_Suppressed
// guards a real false-positive class found live, 2026-09-04: a target
// whose url parameter is simply unused returns its own normal homepage
// for every payload tried, regardless of payload — previously every one
// of them (file://, gopher://, dict://, every loopback encoding, every
// RFC1918 sample, every cloud-metadata path) was misread as "the server
// fetched it." One inert baseline probe per param now establishes what
// "nothing was fetched" looks like, and a payload's response
// indistinguishable from it is never turned into a finding.
func TestSSRFInternalTarget_ResponseIndistinguishableFromBaseline_Suppressed(t *testing.T) {
	homepage := strings.Repeat("<html>same homepage regardless of payload</html>", 5)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(homepage))
	}))
	defer srv.Close()

	detector := ssrf.New(newSSRFClient())
	findings, err := detector.Run(context.Background(), srv.URL, "", []string{"url"}, nil, nil)
	require.NoError(t, err)

	assert.Empty(t, withPrefix(findings, "ssrf-internal-target-"), "every payload's response matches the baseline — none should be treated as evidence of a real fetch")
	assert.Empty(t, withPrefix(findings, "ssrf-cloud-metadata-"))
	assert.Empty(t, withPrefix(findings, "ssrf-scheme-based-"))
}

// TestSSRFInternalTarget_DistinctFromBaseline_StillFires is the previous
// test's counterpart: a payload whose response is genuinely different from
// the baseline must still fire, and baseline suppression must not swallow
// it just because other, unrelated payloads share the app's own normal
// page.
func TestSSRFInternalTarget_DistinctFromBaseline_StillFires(t *testing.T) {
	homepage := strings.Repeat("<html>normal homepage</html>", 10) // deliberately far from the fetched-content body's length below
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		url := r.URL.Query().Get("url")
		if url == "http://127.0.0.1/" {
			data := base64.StdEncoding.EncodeToString([]byte("root:x:0:0"))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":"` + data + `"}`))
			return
		}
		// baseline and every other payload get the app's own normal page
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(homepage))
	}))
	defer srv.Close()

	detector := ssrf.New(newSSRFClient())
	findings, err := detector.Run(context.Background(), srv.URL, "", []string{"url"}, nil, nil)
	require.NoError(t, err)

	got := withPrefix(findings, "ssrf-internal-target-url-127-0-0-1")
	require.Len(t, got, 1, "a response genuinely distinct from the baseline must still fire")

	assert.Empty(t, withPrefix(findings, "ssrf-internal-target-url-10-0-0-1"), "a payload matching the baseline must be suppressed even though a different payload fired")
}

// TestSSRFAuthHeader_Override proves WithAuthHeader actually changes the
// header carrying authToken on every probe — same convention as
// authbypass's equivalent test.
func TestSSRFAuthHeader_Override(t *testing.T) {
	var sawCustomHeader bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization-Token") == "sekret" {
			sawCustomHeader = true
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	detector := ssrf.New(newSSRFClient(), ssrf.WithAuthHeader("Authorization-Token", "{token}"))
	_, err := detector.Run(context.Background(), srv.URL, "sekret", []string{"url"}, nil, nil)
	require.NoError(t, err)

	assert.True(t, sawCustomHeader, "override header must be sent on probe requests")
}

// --- OOB callback: a minimal fake Interactsh-protocol server, real
// RSA-OAEP+AES-256-CTR encryption round trip against the client's own
// hand-rolled decrypt path (pkg/detectors/ssrf/oob_client.go), not a
// simplified stand-in — proves the crypto is actually correct, not just
// that some bytes flow through.

type fakeOOBServer struct {
	mu     chan struct{} // 1-buffered mutex substitute, avoids importing sync just for this
	pubKey *rsa.PublicKey
	nonce  string // set once a probe request embeds our correlation host in its URL — simulated by the test firing it directly
}

func newFakeOOBServer(t *testing.T) (*httptest.Server, *fakeOOBServer) {
	f := &fakeOOBServer{mu: make(chan struct{}, 1)}
	f.mu <- struct{}{}

	mux := http.NewServeMux()
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			PublicKey     string `json:"public-key"`
			SecretKey     string `json:"secret-key"`
			CorrelationID string `json:"correlation-id"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))

		pemBytes, err := base64.StdEncoding.DecodeString(req.PublicKey)
		require.NoError(t, err)
		block, _ := pem.Decode(pemBytes)
		require.NotNil(t, block)
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		require.NoError(t, err)
		rsaPub, ok := pub.(*rsa.PublicKey)
		require.True(t, ok)

		<-f.mu
		f.pubKey = rsaPub
		f.mu <- struct{}{}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "registration successful"})
	})
	mux.HandleFunc("/poll", func(w http.ResponseWriter, r *http.Request) {
		<-f.mu
		pub := f.pubKey
		f.mu <- struct{}{}
		if pub == nil {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []string{}, "extra": []string{}})
			return
		}

		interaction := map[string]string{
			"protocol":       "http",
			"unique-id":      f.nonce,
			"full-id":        f.nonce + "abcdefghijklm.oob.test",
			"raw-request":    "GET /ssrf-probe HTTP/1.1",
			"remote-address": "203.0.113.1",
		}
		plaintext, err := json.Marshal(interaction)
		require.NoError(t, err)

		aesKey := make([]byte, 32)
		_, _ = rand.Read(aesKey)
		iv := make([]byte, aes.BlockSize)
		_, _ = rand.Read(iv)
		block, err := aes.NewCipher(aesKey)
		require.NoError(t, err)
		ciphertext := make([]byte, len(plaintext))
		cipher.NewCTR(block, iv).XORKeyStream(ciphertext, plaintext)
		fullCipher := append(iv, ciphertext...)

		encryptedAESKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, aesKey, nil)
		require.NoError(t, err)

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data":    []string{base64.StdEncoding.EncodeToString(fullCipher)},
			"extra":   []string{},
			"aes_key": base64.StdEncoding.EncodeToString(encryptedAESKey),
		})
	})
	mux.HandleFunc("/deregister", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "deregistration successful"})
	})

	srv := httptest.NewServer(mux)
	return srv, f
}

func TestSSRFOOBCallback_RealEncryptedRoundTrip_Hit(t *testing.T) {
	oobSrv, fake := newFakeOOBServer(t)
	defer oobSrv.Close()

	// Buffered generously: Run also fires checkInternalTargets/
	// checkSchemeBasedTargets against this same targetSrv before the OOB
	// check's own probe (~15 requests) — every one of them hits this
	// handler too, so the channel must never block a send regardless of
	// how many land before the one OOB probe we actually care about.
	probedURLCh := make(chan string, 64)
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probedURLCh <- r.URL.Query().Get("url")
		w.WriteHeader(http.StatusOK)
	}))
	defer targetSrv.Close()
	oobBareHost := oobSrv.URL[len("http://"):]

	// The detector generates its own nonce internally; since the fake
	// server can't know it in advance, it scans every probed URL for the
	// one embedding the OOB server's own host — the other ~15 probes
	// (internal-target/scheme-based) never do — and extracts the nonce
	// from it. checkOOBCallback waits oobPollDelay before polling, so this
	// always lands well before the poll request arrives.
	go func() {
		var probedURL string
		for u := range probedURLCh {
			if strings.Contains(u, oobBareHost) {
				probedURL = u
				break
			}
		}
		// probedURL is like "http://<corrid><nonce>.127.0.0.1:PORT/ssrf-probe"
		host := probedURL[len("http://"):]
		if i := strings.IndexByte(host, '.'); i > oob.CorrelationIDLen {
			label := host[:i]
			<-fake.mu
			fake.nonce = label[oob.CorrelationIDLen:]
			fake.mu <- struct{}{}
		}
	}()

	detector := ssrf.New(newSSRFClient())
	findings, err := detector.Run(context.Background(), targetSrv.URL, "", []string{"url"}, nil, []string{oobSrv.URL})
	require.NoError(t, err)

	got := withPrefix(findings, "ssrf-oob-callback-url")
	require.Len(t, got, 1, "a real RSA-OAEP+AES-256-CTR-encrypted interaction must decrypt and correlate back to the probe")
	assert.Equal(t, "critical", got[0].Severity)
	assert.Equal(t, "203.0.113.1", got[0].Evidence["oob_remote_addr"])
}
