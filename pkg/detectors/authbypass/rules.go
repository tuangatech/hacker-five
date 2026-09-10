package authbypass

import "regexp"

// bflaPathHints mark a protectedPaths entry as list/admin-shaped — the kind
// of endpoint that should return exactly one account's own data, never every
// account's. checkBFLA only evaluates paths containing one of these; a
// narrow, named list (same discipline as WeakJWTSecrets/DefaultCreds) rather
// than a broad heuristic, to keep the false-positive rate low. See
// docs/follow-up.md LT-92 (live-observed on crAPI's
// /workshop/api/management/users/all).
var bflaPathHints = []string{"/all", "/admin/", "management"}

// emailRe / idKeyRe are the two per-account-identifier shapes
// distinctAccountIdentifiers looks for: a bare email address, and a JSON
// "id"/"user_id"/"userId"/"phone" key's value. checkBFLA counts distinct
// matches to tell "this list endpoint returned N different accounts' data"
// from "one account's own record, shown once"; checkTokenReuse reuses the
// same pair to require an identical two-account response actually carry a
// per-account field before flagging, rather than an empty or shared/
// non-personalized page that would otherwise still look "identical" (LT-92,
// docs/follow-up.md).
var (
	emailRe = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	idKeyRe = regexp.MustCompile(`"(?:id|user_id|userId|phone)"\s*:\s*"?([0-9A-Za-z\-]+)"?`)
)

// WeakJWTSecrets are well-known, publicly-documented HS256 JWT signing
// secrets — real defaults/examples left in place by frameworks and
// tutorials, not a general password dictionary. Checked entirely offline
// (see jwt.go's verifiesWithSecret) — never sent to the target server, per
// docs/follow-up.md's explicit note that this check must not become online
// brute force. Small and fixed, same shape as misconfig.DefaultCreds.
var WeakJWTSecrets = []string{
	"secret",
	"changeme",
	"your-256-bit-secret",
	"jwt_secret",
	"jwtsecret",
	"supersecret",
	"secretkey",
	"my-secret-key",
	"password",
	"12345678",
}

// DefaultAuthHeaderName/DefaultAuthHeaderFormat are the header name/value
// shape used unless overridden via WithAuthHeader — same values as
// idor.DefaultAuthHeaderName/Format, duplicated rather than imported so this
// package still doesn't depend on idor (see checkTokenReuse's doc comment
// for why that import was deliberately removed).
const (
	DefaultAuthHeaderName   = "Authorization"
	DefaultAuthHeaderFormat = "Bearer {token}"
)

// LoginPaths are candidate login endpoints for checkRateLimitSignal —
// tried in order; the first one that responds (not a connection failure) is
// used. Same fixed-list precedent as misconfig.DefaultCreds' LoginPath.
// These are generic guesses and won't match every real target's actual
// routes (live-verified against neither crAPI's nor vAPI's real login paths,
// see docs/11-implementation-plan-ph2.md Step 5) — override per-target via
// WithLoginPaths (--login-paths).
var LoginPaths = []string{"/login", "/api/login", "/auth/login"}

// rateLimitProbeUsername/Password are a single, deliberately-invalid
// credential pair used only to observe whether the target throttles repeated
// login attempts — never a real credential-guessing sequence. See
// checkRateLimitSignal's doc comment and docs/11-implementation-plan-ph2.md
// Step 1 for why this replaces the roadmap's literal "rate limiting bypass"
// (brute force) description.
const (
	rateLimitProbeUsername = "hackerfive-rate-limit-probe"
	rateLimitProbePassword = "hackerfive-rate-limit-probe-not-a-real-credential"
)

// LogoutPaths are candidate logout endpoints for checkBrokenSession — same
// try-in-order convention as LoginPaths, same "generic guess, override via
// WithLogoutPaths (--logout-paths)" caveat.
var LogoutPaths = []string{"/logout", "/api/logout", "/auth/logout"}
