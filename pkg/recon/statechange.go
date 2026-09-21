package recon

import (
	"net/url"
	"regexp"
)

// stateChangingRE matches a URL whose path or query names an action that changes
// state or ends a session. Recon only issues read-only requests, but a GET is not
// always read-only in practice (a logout link, a delete-by-id link), and an
// authenticated crawl (--recon-auth, LT-187) could trigger it as the signed-in
// user. A match costs little: the credential is withheld from that one request
// (StateChangingURL) and the crawl skips the URL, so the route is still
// discovered, just not exercised.
//
// The words are matched as whole path/query tokens (delimited by / _ - . = & ?),
// so "delete_video" and "/logout" match and "deleted-items" does not.
var stateChangingRE = regexp.MustCompile(`(?i)(^|[/_.=&?-])(log[-_]?out|sign[-_]?out|log[-_]?off|delete|remove|revoke|destroy|deactivate|unsubscribe|terminate|cancel|purge|wipe|reset)([/_.=&?-]|$)`)

// StateChangingURL reports whether u looks like a state-changing or
// session-ending action.
func StateChangingURL(u *url.URL) bool {
	if u == nil {
		return false
	}
	return stateChangingRE.MatchString(u.Path + "?" + u.RawQuery)
}

// StateChangingCrawlExclusion is stateChangingRE's source, for katana's
// -crawl-out-scope, which takes a Go regular expression matched against the URL.
func StateChangingCrawlExclusion() string { return stateChangingRE.String() }
