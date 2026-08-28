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

// LoginPaths are candidate login endpoints for checkRateLimitSignal —
// tried in order; the first one that responds (not a connection failure) is
// used. Same fixed-list precedent as misconfig.DefaultCreds' LoginPath.
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
// try-in-order convention as LoginPaths.
var LogoutPaths = []string{"/logout", "/api/logout", "/auth/logout"}
