package authbypass

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
