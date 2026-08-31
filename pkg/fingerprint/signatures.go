package fingerprint

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
}

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
}
