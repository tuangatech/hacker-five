package recon

import (
	"regexp"
	"strings"
)

// Request-body fields from a JS bundle (LT-186 item d).
//
// An SSRF hypothesis needs to know which JSON body field takes a URL, and the
// only place a single-page app states it is its own request code. crAPI's bundle,
// for one route:
//
//	const e = ig + sg.CONTACT_MECHANIC, ... fetch(e, {method:"POST",
//	  body: JSON.stringify({mechanic_code: r, vin: i,
//	    mechanic_api: s + "/" + ig + sg.RECEIVE_REPORT, number_of_repeats: 1})})
//
// From that this file recovers the route ("api/merchant/contact_mechanic"), the
// body's field names, and which of them is built from a URL (its value uses a
// route constant or the page origin). Names only: no value expression is kept.
//
// It is a pattern match over minified code, so it is deliberately narrow: a
// fetch()/axios call whose URL resolves to a known route constant and whose body
// is an inline object literal. Anything else yields nothing, never a guess.

type jsBodyFields struct {
	Route   string   // the route literal the call requests, e.g. "api/merchant/contact_mechanic"
	Keys    []string // every field name of the body object literal, in order
	URLKeys []string // the fields whose value is built from an origin or a route constant
}

const (
	maxJSBodyCalls   = 200
	maxJSBodyLookup  = 1200 // how far back a call's URL variable is searched for
	maxJSBodyLiteral = 4000 // a body literal longer than this is not read
)

var (
	// jsRouteConstRe finds route constants: NAME:"api/some/route".
	jsRouteConstRe = regexp.MustCompile(`\b([A-Z][A-Z0-9_]{2,}):"([A-Za-z0-9_\-./{}<>]*/[A-Za-z0-9_\-./{}<>]*)"`)
	jsMemberRefRe  = regexp.MustCompile(`\.([A-Z][A-Z0-9_]{2,})\b`)
	jsBodyKeyRe    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.\-]{0,63}$`)
	jsIdentRe      = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*$`)
	jsCallStartRe  = regexp.MustCompile(`\bfetch\(|\.(?:post|put|patch)\(`)
)

// extractJSBodyFields returns the body fields of every fetch()/axios call in body
// whose URL resolves to a route constant and whose body is an inline object
// literal, one entry per route (the first seen wins).
func extractJSBodyFields(body string) []jsBodyFields {
	consts := map[string]string{}
	for _, m := range jsRouteConstRe.FindAllStringSubmatch(body, -1) {
		consts[m[1]] = m[2]
	}
	if len(consts) == 0 {
		return nil
	}

	var out []jsBodyFields
	seen := map[string]bool{}
	for _, loc := range jsCallStartRe.FindAllStringIndex(body, maxJSBodyCalls) {
		open := loc[1] // just after "("
		isFetch := strings.HasPrefix(body[loc[0]:], "fetch(")
		args := splitTopLevel(callArgs(body, open), ',')
		if len(args) < 2 {
			continue
		}
		route := jsCallRoute(body, loc[0], strings.TrimSpace(args[0]), consts)
		if route == "" || seen[route] {
			continue
		}
		obj := strings.TrimSpace(args[1])
		if isFetch {
			// fetch(url, {method, headers, body: JSON.stringify({...})})
			if !strings.HasPrefix(obj, "{") {
				continue
			}
			i := strings.Index(obj, "JSON.stringify(")
			if i < 0 {
				continue
			}
			obj = strings.TrimSpace(obj[i+len("JSON.stringify("):])
		}
		if !strings.HasPrefix(obj, "{") {
			continue
		}
		end := matchClosing(obj, 0)
		if end < 0 || end > maxJSBodyLiteral {
			continue
		}
		keys, urlKeys := jsObjectFields(obj[1:end], consts)
		if len(keys) == 0 {
			continue
		}
		seen[route] = true
		out = append(out, jsBodyFields{Route: route, Keys: keys, URLKeys: urlKeys})
	}
	return out
}

// callArgs returns the text of a call's argument list starting just after "(",
// up to its matching ")". Empty when unbalanced or implausibly long.
func callArgs(s string, open int) string {
	limit := open - 1 + maxJSBodyLiteral
	if limit > len(s) {
		limit = len(s)
	}
	end := matchClosing(s[open-1:limit], 0)
	if end < 0 {
		return ""
	}
	return s[open : open-1+end]
}

// jsCallRoute resolves a call's URL argument to a route literal: directly (an
// expression using a route constant, "ig+sg.CONTACT_MECHANIC"), or through a
// variable assigned such an expression shortly before the call ("const e=...").
func jsCallRoute(s string, callAt int, arg string, consts map[string]string) string {
	expr := arg
	if jsIdentRe.MatchString(arg) {
		from := callAt - maxJSBodyLookup
		if from < 0 {
			from = 0
		}
		re, err := regexp.Compile(`(?:^|[,;{(\s])` + regexp.QuoteMeta(arg) + `\s*=\s*([^,;{}]{1,200})`)
		if err != nil {
			return ""
		}
		matches := re.FindAllStringSubmatch(s[from:callAt], -1)
		if len(matches) == 0 {
			return ""
		}
		expr = matches[len(matches)-1][1]
	}
	for _, m := range jsMemberRefRe.FindAllStringSubmatch(expr, -1) {
		if route, ok := consts[m[1]]; ok {
			return route
		}
	}
	return ""
}

// jsObjectFields lists the keys of an object literal's body ("a:1,b:x") and which
// of them have a value built from a route constant, the page origin or an absolute
// URL literal. A spread or a computed key is skipped.
func jsObjectFields(objBody string, consts map[string]string) (keys, urlKeys []string) {
	for _, entry := range splitTopLevel(objBody, ',') {
		entry = strings.TrimSpace(entry)
		if entry == "" || strings.HasPrefix(entry, "...") || strings.HasPrefix(entry, "[") {
			continue
		}
		key, value, hasValue := strings.Cut(entry, ":")
		key = strings.Trim(strings.TrimSpace(key), `"'`+"`")
		if !jsBodyKeyRe.MatchString(key) {
			continue
		}
		keys = append(keys, key)
		if hasValue && jsValueBuildsURL(value, consts) {
			urlKeys = append(urlKeys, key)
		}
	}
	return keys, urlKeys
}

func jsValueBuildsURL(value string, consts map[string]string) bool {
	if strings.Contains(value, ".origin") || strings.Contains(value, "location.") ||
		strings.Contains(value, `"http://`) || strings.Contains(value, `"https://`) {
		return true
	}
	for _, m := range jsMemberRefRe.FindAllStringSubmatch(value, -1) {
		if _, ok := consts[m[1]]; ok {
			return true
		}
	}
	return false
}

// matchClosing returns the index of the bracket that closes the one at s[open]
// ((), [] or {}), skipping string and template literals; -1 if unbalanced.
func matchClosing(s string, open int) int {
	depth := 0
	for i := open; i < len(s); i++ {
		switch c := s[i]; c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth == 0 {
				return i
			}
		case '"', '\'', '`':
			i = skipJSString(s, i)
			if i < 0 {
				return -1
			}
		}
	}
	return -1
}

// skipJSString returns the index of the closing quote of the literal opened at
// s[i], or -1 if it is unterminated. A "${" template expression is not parsed,
// only stepped over as text; the literals this reads do not nest them.
func skipJSString(s string, i int) int {
	q := s[i]
	for j := i + 1; j < len(s); j++ {
		switch s[j] {
		case '\\':
			j++
		case q:
			return j
		}
	}
	return -1
}

// splitTopLevel splits s on sep where it is not inside brackets or a string.
func splitTopLevel(s string, sep byte) []string {
	var parts []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '"', '\'', '`':
			j := skipJSString(s, i)
			if j < 0 {
				return append(parts, s[start:])
			}
			i = j
		default:
			if c == sep && depth == 0 {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}
	return append(parts, s[start:])
}
