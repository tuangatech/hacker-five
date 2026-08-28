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
