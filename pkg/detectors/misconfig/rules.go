package misconfig

// PathRule checks whether Path exposes sensitive content. A finding requires
// both a non-404 response and at least one Keywords match in the body —
// status alone is too weak a signal, since many apps return 200 for a custom
// 404 page.
type PathRule struct {
	Path     string
	Keywords []string
	Severity string
}

// HeaderRule flags Name when it's absent from the response.
type HeaderRule struct {
	Name     string
	Severity string
}

// MethodRule checks whether Method is accepted (i.e. not rejected with
// 405/501/403) against Path ("" = target root).
type MethodRule struct {
	Method string
	Path   string
}

// DefaultCredRule is one username/password pair tried once, at LoginPath.
// The default-cred table is capped at 5 pairs, each tried exactly once —
// never retried or expanded into a dictionary. This is a fixed-size,
// single-pass check, not credential brute force, which CLAUDE.md's
// read/enumerate-only rule and most bug-bounty program policies explicitly
// prohibit.
type DefaultCredRule struct {
	LoginPath string
	Username  string
	Password  string
}

// ExposedPaths are common sensitive paths worth a single GET each.
var ExposedPaths = []PathRule{
	{Path: "/.env", Keywords: []string{"DB_PASSWORD", "APP_KEY", "SECRET"}, Severity: "high"},
	{Path: "/.git/config", Keywords: []string{"[core]", "repositoryformatversion"}, Severity: "high"},
	{Path: "/.git/HEAD", Keywords: []string{"ref:"}, Severity: "high"},
	{Path: "/.aws/credentials", Keywords: []string{"aws_access_key_id", "aws_secret_access_key"}, Severity: "critical"},
	{Path: "/debug", Keywords: []string{"debug", "trace"}, Severity: "medium"},
	{Path: "/debug/pprof/", Keywords: []string{"profile", "goroutine"}, Severity: "medium"},
	{Path: "/.well-known/security.txt", Keywords: []string{"Contact:"}, Severity: "low"},
	{Path: "/swagger", Keywords: []string{"swagger", "openapi"}, Severity: "medium"},
	{Path: "/swagger.json", Keywords: []string{"swagger", "openapi"}, Severity: "medium"},
	{Path: "/swagger-ui.html", Keywords: []string{"swagger"}, Severity: "medium"},
	{Path: "/graphql", Keywords: []string{"errors", "__schema"}, Severity: "medium"},
	{Path: "/admin", Keywords: []string{"admin", "login", "dashboard"}, Severity: "medium"},
	{Path: "/admin123", Keywords: []string{"admin", "login"}, Severity: "low"},
	{Path: "/actuator", Keywords: []string{"_links"}, Severity: "medium"},
	{Path: "/actuator/env", Keywords: []string{"propertySources"}, Severity: "high"},
	{Path: "/actuator/health", Keywords: []string{"status"}, Severity: "low"},
	{Path: "/config.json", Keywords: []string{"apiKey", "secret", "password"}, Severity: "high"},
	{Path: "/wp-config.php.bak", Keywords: []string{"DB_PASSWORD", "define("}, Severity: "high"},
	{Path: "/server-status", Keywords: []string{"Apache Server Status"}, Severity: "medium"},
	// Keywords are real htpasswd hash-format markers (Apache MD5, bcrypt,
	// SHA1-base64 — see `man htpasswd`), not a bare ":" — a real .htpasswd
	// line is "user:hash", but ":" alone false-positived against any target
	// that returns HTTP 200 for unmatched paths (e.g. an SPA's catch-all
	// index.html, which trivially contains a colon somewhere in its own
	// markup) — found live against Juice Shop, see
	// docs/20-setup-testing-targets.md's Juice Shop caveat.
	{Path: "/.htpasswd", Keywords: []string{"$apr1$", "{SHA}", "$2y$", "$2a$", "$2b$"}, Severity: "high"},
}

// WPUserEnumPath is WordPress's REST route that lists every user who has
// authored a post of a publicly-visible type. WordPress >= 4.7.1 limits the
// listing to post types that opted into the REST API, but a default install
// still serves the full author list unauthenticated — and each entry's
// "slug" is that account's wp-login.php username, i.e. a ready-made target
// list for credential stuffing / password spraying (CWE-200). checkWPUserEnum
// probes it directly rather than leaving it to the nuclei wp-user-enum
// template, which a tag-scoped corpus run can skip under the per-target time
// budget (docs/follow-up.md).
const WPUserEnumPath = "/wp-json/wp/v2/users/"

// wpUserObjectMarkers are the JSON keys every element of a real
// /wp-json/wp/v2/users/ array carries. All must be present (AND) — the
// hardened response WordPress returns when the endpoint is locked down
// ({"code":"rest_user_cannot_view",...,"data":{"status":401}}) is still a
// 200 JSON body on some setups but has no "slug", so requiring "slug" keeps
// that secure response from matching.
var wpUserObjectMarkers = []string{`"id":`, `"slug":`, `"name":`}

// DolibarrAuthorMeta is the exact <meta> tag Dolibarr's top_htmlhead() emits
// on every rendered page (htdocs/main.inc.php) — including the
// unauthenticated login page. checkDolibarrOutdated uses it as the hard "this
// really is Dolibarr" gate before trusting any version string parsed out of
// the same response.
const DolibarrAuthorMeta = `<meta name="author" content="Dolibarr Development Team">`

// DolibarrLatestStable is the newest stable Dolibarr release, quoted only in
// checkDolibarrOutdated's human-readable description (the CVE match itself is
// driven by DolibarrCVEs, not by this). Refresh when the upstream stable
// line advances — checked against github.com/Dolibarr/dolibarr/releases on
// 2026-09-08: 24.0.1 (2026-09-07), with 23.0.4 the last of the 23.x line.
const DolibarrLatestStable = "24.0.1"

// VersionCVERule maps "any release of a product earlier than FixedIn" to one
// published CVE. checkDolibarrOutdated walks a table of these against the
// version it parses from the app's own output. Every entry's affected range
// is verified against NVD — no guessed CVEs (CLAUDE.md's <5% false-positive
// bar); Severity/CVSS are the NVD CVSS v4 base values.
type VersionCVERule struct {
	CVE           string
	FixedIn       string // first release NOT affected; the rule fires when detected < FixedIn
	Severity      string // NVD CVSS v4 base severity, lowercased
	CVSS          float64
	ExploitPublic bool
	Summary       string
}

// DolibarrCVEs is the curated affected-version table for Dolibarr ERP/CRM.
// Ordered newest-fix-first for readable evidence only; matching is
// order-independent. FixedIn uses the single first-unaffected release per
// CVE — for the two entries phrased upstream as "up to 21.0.4/22.0.5/23.0.3"
// this means an old-major install (21.x/22.x) also matches the 23.0.4 fix
// line, which is correct: it needs the upgrade regardless.
var DolibarrCVEs = []VersionCVERule{
	{CVE: "CVE-2026-81728", FixedIn: "24.0.0", Severity: "high", CVSS: 8.6,
		Summary: "SQL injection in the CSV/XLSX import wizard (authenticated, low-privilege)"},
	{CVE: "CVE-2026-85401", FixedIn: "23.0.4", Severity: "low", CVSS: 2.1, ExploitPublic: true,
		Summary: "Legacy File Manager improper access control (public exploit available)"},
	{CVE: "CVE-2026-22666", FixedIn: "23.0.2", Severity: "high", CVSS: 8.6,
		Summary: "authenticated RCE via dol_eval_standard() PHP dynamic-callable bypass"},
	{CVE: "CVE-2026-23500", FixedIn: "23.0.0", Severity: "critical", CVSS: 9.4,
		Summary: "OS command injection via ODT-to-PDF conversion (authenticated admin RCE)"},
}

// DirListingPaths are common subpaths worth a directory-listing probe,
// beyond just target root ("" is included so misconfig.Detector finds a
// root listing on its own, without depending on
// templates/nuclei-samples/dvwa-php/dir-listing.yaml also being loaded via
// --templates). Found via a real gap: dir-listing.yaml only checks root,
// but DVWA's actual directory listing lives at /docs/, so this specific,
// genuine misconfiguration was invisible to a default scan — see
// docs/10-implementation-plan-ph1b.md's Future Enhancement #4.
var DirListingPaths = []string{
	"",
	"/docs/",
	"/uploads/",
	"/backup/",
	"/backups/",
	"/files/",
	"/images/",
	"/assets/",
	"/logs/",
	"/tmp/",
	"/old/",
}

// DirListingMarkers are the same directory-listing banner strings
// templates/nuclei-samples/dvwa-php/dir-listing.yaml already matches on
// (Apache/nginx "Index of /", Apache-mod_autoindex "Directory listing
// for ", IIS "[To Parent Directory]", generic "Directory: /") — reused
// rather than reinvented so the built-in check and the sample template
// agree on what "looks like a directory listing" means. Matched
// case-insensitively (see checkDirListing), same as the YAML template's own
// case-insensitive: true.
var DirListingMarkers = []string{
	"Directory listing for ",
	"Index of /",
	"[To Parent Directory]",
	"Directory: /",
}

// MissingHeaders are common security headers whose absence is worth flagging.
var MissingHeaders = []HeaderRule{
	{Name: "Content-Security-Policy", Severity: "medium"},
	{Name: "X-Frame-Options", Severity: "medium"},
	{Name: "Strict-Transport-Security", Severity: "medium"},
	{Name: "X-Content-Type-Options", Severity: "low"},
}

// DisallowedMethods are state-mutating HTTP verbs that shouldn't be accepted
// on endpoints that don't explicitly need them.
var DisallowedMethods = []MethodRule{
	{Method: "PUT", Path: ""},
	{Method: "DELETE", Path: ""},
	{Method: "PATCH", Path: ""},
}

// DefaultCreds is capped at 5 well-known pairs, each tried once — see
// DefaultCredRule's doc comment.
var DefaultCreds = []DefaultCredRule{
	{LoginPath: "/login", Username: "admin", Password: "admin"},
	{LoginPath: "/login", Username: "test", Password: "test"},
	{LoginPath: "/login", Username: "admin", Password: "password"},
	{LoginPath: "/admin/login", Username: "admin", Password: "admin"},
	{LoginPath: "/admin/login", Username: "admin", Password: "admin123"},
}

// VerboseErrorPatterns match common stack-trace / internal-error signatures
// in response bodies (compiled once in detector.go via regexp.MustCompile).
var VerboseErrorPatterns = []string{
	`at java\.`,
	`Traceback \(most recent call last\)`,
	`ORA-\d+`,
	`Microsoft OLE DB Provider for SQL Server`,
	`Warning: mysql_`,
	`Unhandled Exception`,
	`System\.Exception`,
	`\b10\.\d+\.\d+\.\d+\b`,
	`\b172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+\b`,
	`\b192\.168\.\d+\.\d+\b`,
}

// CommentLeakPatterns match common debug/development leftovers inside HTML
// comments — information disclosure (Phase 2 Step 4,
// docs/11-implementation-plan-ph2.md), checked case-insensitively (see
// checkCommentLeaks) since real markup capitalizes these inconsistently.
// Deliberately narrower than doc11's original example list: every pattern
// here is anchored to actually being inside an HTML comment (`<!--...`), not
// a bare substring match anywhere in the body — doc11's own example
// included a bare `console.log(` check, but that matches so much real,
// intentional production JS (any bundled library that logs anything) that
// it would be a real false-positive generator rather than a genuine "debug
// leftover" signal; dropped here rather than guessed into the list.
var CommentLeakPatterns = []string{
	`<!--[^>]*\bTODO\b`,
	`<!--[^>]*\bFIXME\b`,
	`<!--[^>]*\bDEBUG\b`,
	`<!--[^>]*<script`,                       // a whole commented-out <script> block left in the page
	`<!--[^>]*(password|secret|api[_-]?key)`, // a credential-shaped word inside a comment
}
