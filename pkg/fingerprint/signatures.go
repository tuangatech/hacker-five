package fingerprint

import "regexp"

// Signature is one static tech-signature rule: every non-empty field is an
// AND'able condition (a signature setting only one field, the common case,
// degenerates to a single check). Modeled directly on HexStrike AI's
// TechnologyDetector (docs/14-implementation-plan-ph5.md Step 3's R7,
// docs/90-research-hackerbot.md's Decision 6/I2) — a static table, not a
// model call, reimplemented first-party rather than pulled in as a
// dependency. Authored fresh: no signature table is transcribed anywhere in
// this project's docs, so these are hand-picked to cover both this
// project's own lab targets (crAPI/DVWA/Juice Shop/vAPI) and common,
// widely-deployed stacks a real bug-bounty target is likely to run.
type Signature struct {
	Product        string
	HeaderName     string // header key to check, case-insensitive; "" = skip this condition
	HeaderContains string // substring HeaderName's value must contain, case-insensitive
	BodyContains   string // substring the response body must contain, case-insensitive
	FaviconHash    string // exact match against httpx's own mmh3 favicon hash string
	Port           int    // well-known port; 0 = skip this condition
	// VersionRegex, when set, is applied to the same signal the signature
	// matched on (the header's value for a header signature, the body for a
	// body signature); its first capture group becomes Match.Version.
	// Best-effort: no capture (a product that hides its version pre-login)
	// still yields the unversioned Match. Ignored for favicon/port signatures,
	// which carry no text to capture from.
	VersionRegex string
}

// versionRegexes holds each signature's compiled VersionRegex, keyed by the
// pattern string, built once at package init so Detect never recompiles. A
// malformed pattern panics at startup (and in TestSignatures_VersionRegexesCompile)
// rather than silently disabling version capture.
var versionRegexes = func() map[string]*regexp.Regexp {
	m := make(map[string]*regexp.Regexp)
	for _, s := range signatures {
		if s.VersionRegex != "" {
			m[s.VersionRegex] = regexp.MustCompile(s.VersionRegex)
		}
	}
	return m
}()

// signatures is intentionally small and reviewable, not exhaustive — a
// TechFact with no match here is meant to surface as an explicit
// unresolved leaf (pkg/registry's decision engine), not silently guessed.
var signatures = []Signature{
	{Product: "Nginx", HeaderName: "server", HeaderContains: "nginx"},
	{Product: "OpenResty", HeaderName: "server", HeaderContains: "openresty"},
	{Product: "Apache HTTP Server", HeaderName: "server", HeaderContains: "apache"},
	{Product: "Microsoft IIS", HeaderName: "server", HeaderContains: "iis"},
	{Product: "Cloudflare", HeaderName: "server", HeaderContains: "cloudflare"},
	{Product: "Express", HeaderName: "x-powered-by", HeaderContains: "express"},
	{Product: "PHP", HeaderName: "x-powered-by", HeaderContains: "php"},
	{Product: "ASP.NET", HeaderName: "x-powered-by", HeaderContains: "asp.net"},
	{Product: "Django", HeaderName: "set-cookie", HeaderContains: "csrftoken"},
	{Product: "PHP", BodyContains: "<?php"},
	{Product: "WordPress", BodyContains: "wp-content"},
	{Product: "WordPress", BodyContains: "wp-includes"},
	{Product: "phpMyAdmin", BodyContains: "phpmyadmin"},
	{Product: "Swagger UI", BodyContains: "swagger-ui"},
	{Product: "GraphQL", BodyContains: "graphiql"},
	{Product: "jQuery", BodyContains: "jquery"},
	{Product: "MySQL", Port: 3306},
	{Product: "PostgreSQL", Port: 5432},
	{Product: "Redis", Port: 6379},
	{Product: "MongoDB", Port: 27017},
	// crAPI's own favicon mmh3 hash, confirmed live against the real
	// running lab container (httpx -favicon against http://localhost:8888,
	// 2026-08-31) — not a guessed/fabricated value.
	{Product: "crAPI", FaviconHash: "-254193850"},

	// Cloud-provider infrastructure signals (Phase 8 Step 3, P1-5,
	// docs/follow-up.md): closes the gap where the decision engine could
	// dispatch the corpus's aws/s3/gcp-tagged exposure templates but
	// nothing ever produced a fact more specific than the denylisted
	// "Google Cloud" / "Amazon S3" hosting-brand facts (see
	// pkg/registry's nonActionableTech). Each header name below is
	// specific to that one provider's own edge/API/storage layer, not a
	// generic "cloud" hint, so the false-positive risk is low — these
	// fire only against a target genuinely fronted by that provider.
	// HeaderContains left blank on a header-presence-only signature is
	// intentional: evaluate() treats an empty HeaderContains as "header
	// exists", which is exactly what these headers signal.
	{Product: "aws", HeaderName: "x-amzn-requestid"},                  // API Gateway / Lambda
	{Product: "aws", HeaderName: "x-amzn-trace-id"},                   // ALB / API Gateway
	{Product: "aws", HeaderName: "x-amz-cf-id"},                       // CloudFront edge
	{Product: "aws", HeaderName: "server", HeaderContains: "awselb"},  // Elastic Load Balancer
	{Product: "s3", HeaderName: "x-amz-bucket-region"},                // a direct S3 bucket response
	{Product: "s3", HeaderName: "server", HeaderContains: "amazons3"}, // S3 static-website hosting
	{Product: "gcp", HeaderName: "x-goog-generation"},                 // GCS object metadata
	{Product: "gcp", HeaderName: "x-guploader-uploadid"},              // GCS upload/session header

	// Self-hosted CMS / admin-panel products (LT-129, docs/follow-up.md). Each
	// marker below was confirmed against a live instance (the four products
	// all run on the owned *.nettix.com.pe scope, 2026-09-30) and cross-checked
	// against the synced nuclei corpus's own detect templates, not recalled.
	// Session-cookie names are used as the header signal because they are
	// product-fixed and, unlike a Server header, survive an nginx/Apache front:
	// erp.* sets DOLSESSID_<hash>, cloud01.* sets oc_sessionPassphrase plus
	// __Host-nc_sameSiteCookie*, wiki.* sets DokuWiki=<sid>.
	//
	// Webmin/MiniServ: the Server header is the hard signal, but MiniServ omits
	// its version pre-login by default (cloud02.*:10000 answered a bare
	// "Server: MiniServ"), so VersionRegex is best-effort. The port-only entry
	// is deliberately weak (ConfidenceLow via SourcePort, same as MySQL/Redis)
	// — 10000 alone doesn't prove Webmin — but it is what lets recon's naabu
	// port fact dispatch the Webmin checks for a host whose :10000 httpx never
	// probed (its default probe set is 80/443).
	{Product: "Webmin", HeaderName: "server", HeaderContains: "miniserv", VersionRegex: `(?i)miniserv/(\d+\.\d+(?:\.\d+)?)`},
	{Product: "Webmin", Port: 10000},
	// Dolibarr: the login page's author <meta> is the same hard product gate
	// misconfig.checkDolibarrOutdated uses; every themed CSS/JS URL in its
	// <head> carries "&version=<DOL_VERSION>" (live: erp.* read 23.0.3).
	{Product: "Dolibarr", HeaderName: "set-cookie", HeaderContains: "DOLSESSID_"},
	{Product: "Dolibarr", BodyContains: `<meta name="author" content="Dolibarr Development Team">`, VersionRegex: `[?&](?:amp;)?version=(\d+\.\d+\.\d+)`},
	// Nextcloud: its login page exposes no version (that lives only on
	// /status.php, which misconfig.checkNextcloudStatus reads), so no
	// VersionRegex here.
	{Product: "Nextcloud", HeaderName: "set-cookie", HeaderContains: "oc_sessionPassphrase"},
	{Product: "Nextcloud", HeaderName: "set-cookie", HeaderContains: "__Host-nc_sameSiteCookie"},
	// DokuWiki: the generator <meta> names the product but not the release, so
	// no VersionRegex.
	{Product: "DokuWiki", HeaderName: "set-cookie", HeaderContains: "DokuWiki="},
	{Product: "DokuWiki", BodyContains: `<meta name="generator" content="DokuWiki`},
}
