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
	// NB: /.well-known/ paths are deliberately NOT probed here (LT-119). RFC
	// 9116's security.txt, MTA-STS's mta-sts.txt and OIDC's
	// openid-configuration are all *required* to be publicly served — recon's
	// own pkg/preflight fetches security.txt as a positive policy signal — so
	// flagging one as an "exposed sensitive path" is a structural false
	// positive, not a finding.
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
// driven by KnownVulnerableVersions, not by this). Refresh when the upstream
// stable line advances — checked against github.com/Dolibarr/dolibarr/releases
// on 2026-09-08: 24.0.1 (2026-09-07), with 23.0.4 the last of the 23.x line.
const DolibarrLatestStable = "24.0.1"

// Product* are the canonical product names the native version checks pass to
// matchKnownCVEs — the discriminator column of the KnownVulnerableVersions
// table. They are not derived from anything the target says about itself
// (e.g. Nextcloud's status.php "productname" can read "ownCloud"); each check
// hard-codes which one it owns.
const (
	ProductDolibarr   = "Dolibarr"
	ProductNextcloud  = "Nextcloud"
	ProductPhpMyAdmin = "phpMyAdmin"
	ProductWebmin     = "Webmin"
)

// VersionCVERule maps "any release of Product earlier than FixedIn" to one
// published CVE. It is the row type of the single cross-product
// KnownVulnerableVersions table that every native version→CVE check
// (checkDolibarrOutdated, checkNextcloudStatus, checkPhpMyAdmin, checkWebmin)
// walks via matchKnownCVEs against the version it parsed from the app's own
// output. Every entry's affected range is verified against NVD — no guessed
// CVEs (CLAUDE.md's <5% false-positive bar); Severity/CVSS are the NVD base
// values (CVSS v4 where NVD publishes one, otherwise v3.1).
type VersionCVERule struct {
	Product       string // one of the Product* constants
	CVE           string
	FixedIn       string // first release NOT affected; the rule fires when detected < FixedIn
	Severity      string // NVD base severity, lowercased
	CVSS          float64
	ExploitPublic bool
	Summary       string
}

// KnownVulnerableVersions is the curated cross-product affected-version table.
// Grouped by product and ordered newest-fix-first for readable evidence only;
// matchKnownCVEs is order-independent and filters by Product. FixedIn is the
// single first-unaffected release per CVE — an install on an even older major
// still matches (correctly: it needs the upgrade regardless).
//
// Refresh discipline: every row cites a real NVD entry; the *Latest* consts
// alongside carry the date each product's release line was last checked.
var KnownVulnerableVersions = []VersionCVERule{
	// Dolibarr ERP/CRM — fingerprinted by the author <meta> (checkDolibarrOutdated).
	{Product: ProductDolibarr, CVE: "CVE-2026-81728", FixedIn: "24.0.0", Severity: "high", CVSS: 8.6,
		Summary: "SQL injection in the CSV/XLSX import wizard (authenticated, low-privilege)"},
	{Product: ProductDolibarr, CVE: "CVE-2026-85401", FixedIn: "23.0.4", Severity: "low", CVSS: 2.1, ExploitPublic: true,
		Summary: "Legacy File Manager improper access control (public exploit available)"},
	{Product: ProductDolibarr, CVE: "CVE-2026-22666", FixedIn: "23.0.2", Severity: "high", CVSS: 8.6,
		Summary: "authenticated RCE via dol_eval_standard() PHP dynamic-callable bypass"},
	{Product: ProductDolibarr, CVE: "CVE-2026-23500", FixedIn: "23.0.0", Severity: "critical", CVSS: 9.4,
		Summary: "OS command injection via ODT-to-PDF conversion (authenticated admin RCE)"},

	// Nextcloud community server — fingerprinted by status.php (checkNextcloudStatus).
	// NVD-verified 2026-09-08; every fix lands in the 28.x line, so "detected <
	// FixedIn" correctly covers the 28.0.5 seen live on cloud01/cloud02.
	{Product: ProductNextcloud, CVE: "CVE-2025-47791", FixedIn: "28.0.13", Severity: "medium", CVSS: 4.3,
		Summary: "an unprotected share-recipient verify endpoint could proxy requests to another server"},
	{Product: ProductNextcloud, CVE: "CVE-2024-52523", FixedIn: "28.0.12", Severity: "medium", CVSS: 4.6,
		Summary: "external-storage credentials returned to the frontend in plain text to any session holder"},
	{Product: ProductNextcloud, CVE: "CVE-2024-52518", FixedIn: "28.0.12", Severity: "medium", CVSS: 4.4,
		Summary: "external storages could be created/changed/deleted without password confirmation"},
	{Product: ProductNextcloud, CVE: "CVE-2024-52517", FixedIn: "28.0.11", Severity: "medium", CVSS: 4.6,
		Summary: "stored Global credentials returned by the API in plain text"},

	// phpMyAdmin — fingerprinted by the login-form field pair (checkPhpMyAdmin).
	// NVD-verified 2026-09-08; both fixed in 5.2.2 (PMASA-2025-1 / -2), so a
	// pre-5.2.2 login page (e.g. the 5.2.1 seen live on chasqui03) matches.
	{Product: ProductPhpMyAdmin, CVE: "CVE-2025-24530", FixedIn: "5.2.2", Severity: "medium", CVSS: 6.4,
		Summary: "stored XSS via a crafted database/table name in the Check Tables feature (PMASA-2025-1)"},
	{Product: ProductPhpMyAdmin, CVE: "CVE-2025-24529", FixedIn: "5.2.2", Severity: "medium", CVSS: 6.4,
		Summary: "reflected XSS in the Insert tab (PMASA-2025-2)"},

	// Webmin / MiniServ family — fingerprinted by the Server header (checkWebmin).
	// NVD-verified 2026-09-08. Only the one unambiguous entry: NVD's own
	// description states "Fixed in 2.202". Two 2026 XSS/file-disclosure issues
	// were left out — secondary sources disagree on their fix version, and
	// CLAUDE.md says flag doubt rather than guess a matcher.
	{Product: ProductWebmin, CVE: "CVE-2026-56020", FixedIn: "2.202", Severity: "critical", CVSS: 9.2,
		Summary: "miniserv.pl trusts a client-supplied header for the SSL-client-certificate DN, letting an unauthenticated attacker authenticate as any certificate-mapped user"},
}

// NextcloudStatusPath is Nextcloud/ownCloud's unauthenticated monitoring
// endpoint. status.php in nextcloud/server builds a JSON object with
// installed/version/versionstring/productname — meant for uptime checks, but
// it hands any unauthenticated caller the exact build. Nextcloud's own
// hardening guide recommends restricting it.
const NextcloudStatusPath = "/status.php"

// nextcloudStatusMarkers are the JSON keys status.php always emits (the array
// is built literally with these in every supported release). All required
// (AND) so an unrelated 200 JSON body cannot match.
var nextcloudStatusMarkers = []string{`"installed":`, `"version":`, `"versionstring":`, `"productname":`}

// NextcloudLatestStable and nextcloudOldestMaintainedMajor bound the
// "outdated" judgement — Nextcloud maintains three majors (N, N-1, N-2).
// Checked against github.com/nextcloud/server/releases on 2026-09-08: latest
// 34.0.3, maintained majors 32/33/34. Refresh when the release line advances.
// The affected-version CVE rows live in KnownVulnerableVersions.
const NextcloudLatestStable = "34.0.3"
const nextcloudOldestMaintainedMajor = 32

// PhpMyAdminProbePaths are where an internet-facing phpMyAdmin login most
// often sits — the site root (a dedicated DB-admin vhost) first, then the two
// conventional sub-mounts. checkPhpMyAdmin stops at the first that serves the
// login form.
var PhpMyAdminProbePaths = []string{"/", "/phpmyadmin/", "/pma/"}

// phpMyAdminLoginMarkers are the two login-form field names phpMyAdmin has
// used unchanged for its whole 5.x line (templates/login/form.twig). Both
// required (AND) — together they are specific enough that no non-phpMyAdmin
// page realistically carries them.
var phpMyAdminLoginMarkers = []string{"pma_username", "pma_password"}

// PhpMyAdminLatestStable is the newest stable phpMyAdmin release, quoted only
// in checkPhpMyAdmin's description. Checked against phpmyadmin.net/downloads
// on 2026-09-08: 5.2.3 (2025-10-08, a bugfix release — the last security
// content was 5.2.2 / PMASA-2025-1..3). The CVE rows are in
// KnownVulnerableVersions.
const PhpMyAdminLatestStable = "5.2.3"

// WebminServerToken is the Server-header substring MiniServ (the bespoke HTTP
// server behind Webmin, Usermin and Virtualmin) always sends, e.g.
// "MiniServ/2.111". checkWebmin uses its presence as the hard product gate
// and webminServerVersionRe pulls the version out of the same value. Matched
// case-insensitively.
const WebminServerToken = "MiniServ"

// webminLoginMarker confirms the response is the unauthenticated login page
// specifically (both the legacy and authentic-theme templates post the form
// to this path) rather than an already-authenticated page or a bare 401 —
// checked in addition to the Server header, never instead of it.
const webminLoginMarker = "session_login.cgi"

// WebminLatestStable is the newest stable Webmin release, quoted only in
// checkWebmin's description. Checked against webmin.com / github.com/webmin
// on 2026-09-08: 2.202. The CVE rows are in KnownVulnerableVersions.
const WebminLatestStable = "2.202"

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
