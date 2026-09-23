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
// is an inline object literal, a bare variable this file can trace back to one,
// or a passthrough of the call's own enclosing function's single parameter
// (LT-186 d follow-on, docs/follow-up.md — see resolveIndirectBody's doc
// comment). Anything else yields nothing, never a guess.

type jsBodyFields struct {
	Route    string            // the route literal the call requests, e.g. "api/merchant/contact_mechanic"
	Keys     []string          // every field name of the body object literal, in order
	URLKeys  []string          // the fields whose value is built from an origin or a route constant
	Literals map[string]string // fields whose value is a simple true/false/integer literal (LT-188 a)
}

const (
	maxJSBodyCalls   = 200
	maxJSBodyLookup  = 1200 // how far back a call's URL variable is searched for
	maxJSBodyLiteral = 4000 // a body literal longer than this is not read

	// enclosingFuncLookback bounds how far back a call is searched for its
	// own enclosing method's "name(param){" signature (resolveIndirectBody's
	// passthrough shape) — short on purpose: a minified service method that
	// just forwards its argument to fetch/http.post is typically a few dozen
	// characters long, and searching far back risks matching an unrelated,
	// outer function's own signature instead of the call's real one.
	enclosingFuncLookback = 400

	// minPassthroughFuncNameLen guards resolvePassthroughCallSites against a
	// minifier-mangled one/two-character local recurring so often across an
	// entire bundle that scanning its call sites is both slow and
	// meaningless — same threshold and reasoning LT-184 already applied to
	// mangled property names elsewhere in recon.
	minPassthroughFuncNameLen = 3

	// maxPassthroughCallSites caps how many ".funcName(" occurrences
	// resolvePassthroughCallSites will examine across the whole bundle
	// before giving up — bounded work per call, not a full scan's cost
	// multiplied by every unresolved passthrough found.
	maxPassthroughCallSites = 30
)

var (
	// jsRouteConstRe finds route constants: NAME:"api/some/route".
	jsRouteConstRe = regexp.MustCompile(`\b([A-Z][A-Z0-9_]{2,}):"([A-Za-z0-9_\-./{}<>]*/[A-Za-z0-9_\-./{}<>]*)"`)
	jsMemberRefRe  = regexp.MustCompile(`\.([A-Z][A-Z0-9_]{2,})\b`)
	jsBodyKeyRe    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.\-]{0,63}$`)
	jsIdentRe      = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*$`)
	jsCallStartRe  = regexp.MustCompile(`\bfetch\(|\.(?:post|put|patch)\(`)
	jsIntLiteralRe = regexp.MustCompile(`^-?[0-9]{1,9}$`)

	// jsIdentOrThisPropRe matches a bare identifier ("e") or a simple
	// this-property reference ("this.user") — the two shapes a resolvable
	// bare body argument takes in real bundles (LT-186 d follow-on). Not
	// generalized to an arbitrary dotted path ("a.b.c"): no live evidence
	// justifies it, and CLAUDE.md's "a doubtful pattern is left out, not
	// guessed" applies here as much as anywhere else in this file.
	jsIdentOrThisPropRe = regexp.MustCompile(`^(?:this\.)?[A-Za-z_$][A-Za-z0-9_$]*$`)

	// jsFuncDefRe matches a short method definition's own opening,
	// "name(param){" — one parameter only, matching the passthrough shape
	// resolveIndirectBody looks for. jsReservedWords below excludes the
	// control-flow keywords that share this same textual shape ("if(e){").
	jsFuncDefRe = regexp.MustCompile(`\b([A-Za-z_$][A-Za-z0-9_$]*)\(([A-Za-z_$][A-Za-z0-9_$]*)\)\{`)

	// jsReservedWords excludes JS control-flow keywords from being
	// mistaken for a method name by jsFuncDefRe — "if(e){"/"while(e){" is
	// syntactically identical to a one-param method definition.
	jsReservedWords = map[string]bool{
		"if": true, "for": true, "while": true, "switch": true,
		"catch": true, "function": true, "with": true,
	}
)

// extractJSBodyFields returns the body fields of every fetch()/axios call in body
// whose URL resolves to a route (a named constant, or a literal path —
// jsCallRoute) and whose body resolves to field names (an inline object
// literal, or a bare variable/passthrough this file can trace back to one —
// resolveIndirectBody), one entry per route (the first seen wins). consts
// being empty is no longer a reason to give up entirely (LT-186 d
// follow-on, found live): Juice Shop's bundle declares zero route constants
// of the "NAME:\"api/route\"" shape jsRouteConstRe looks for at all — every
// route in it is an inline literal — so an early exit here would have made
// this function permanently dead code against a real, common bundle shape.
func extractJSBodyFields(body string) []jsBodyFields {
	consts := map[string]string{}
	for _, m := range jsRouteConstRe.FindAllStringSubmatch(body, -1) {
		consts[m[1]] = m[2]
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
		var keys, urlKeys []string
		var literals map[string]string
		if strings.HasPrefix(obj, "{") {
			end := matchClosing(obj, 0)
			if end < 0 || end > maxJSBodyLiteral {
				continue
			}
			keys, urlKeys, literals = jsObjectFields(obj[1:end], consts)
		} else if !isFetch {
			// fetch's own body is always the inline JSON.stringify(...)
			// literal already unwrapped above; a bare-variable body only
			// happens for the .post/.put/.patch shape, so resolution is
			// skipped entirely for fetch (nothing to resolve there).
			keys, urlKeys, literals = resolveIndirectBody(body, loc[0], obj, consts)
		}
		if len(keys) == 0 {
			continue
		}
		seen[route] = true
		out = append(out, jsBodyFields{Route: route, Keys: keys, URLKeys: urlKeys, Literals: literals})
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
// Falls back to jsCallRouteFromLiteral when the expression uses no named route
// constant at all (LT-186 d follow-on — found live: Juice Shop's bundle never
// declares one, every route is built from an inline literal instead, e.g.
// `this.hostServer+\`/rest/user/login\``).
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
	return jsCallRouteFromLiteral(expr)
}

// jsCallRouteFromLiteral resolves a call's URL expression to a route when it
// contains an absolute-path literal directly rather than a named route
// constant — a plain quoted string, or a backtick template literal (read and
// normalized the exact same way jsstatic.go's own jsCandidateLiterals reads
// one, so a route this resolves to is guaranteed to match the same literal's
// route key wherever jsstatic.go derives one for the identical endpoint —
// never a route this file invents independently of it). Reused between
// jsCallRoute's own two forms (a direct expression, or one resolved from a
// variable assignment above).
func jsCallRouteFromLiteral(expr string) string {
	for _, m := range jsQuotedStringRe.FindAllStringSubmatch(expr, -1) {
		s := m[1]
		if s == "" {
			s = m[2]
		}
		if strings.HasPrefix(s, "/") && len(s) > 1 {
			return s
		}
	}
	for _, lit := range extractBacktickLiterals(expr) {
		if s, ok := normalizeJSTemplateLiteral(lit); ok && strings.HasPrefix(s, "/") && len(s) > 1 {
			return s
		}
	}
	return ""
}

// resolveIndirectBody resolves a call's body argument to field names when it
// is not an inline object literal — LT-186 (d)'s original scope stopped
// there ("a body that is a variable is not guessed at"). Found live, Juice
// Shop's real bundle: its request code never builds a body inline at the
// fetch/http.post call site at all, in either of two ways ordinary web-app
// TypeScript compiles down to:
//
//  1. A locally built variable, either an inline literal ("let x = {...}")
//     or built by sequential property assignment onto an existing reference
//     ("this.user={}, this.user.email=e, this.user.password=p") — the
//     latter is the more common real shape (an Angular component building
//     up a bound form model field by field) and was not readable at all
//     before this. See resolveBareObjectArg.
//  2. A bare passthrough of the enclosing method's own single parameter —
//     the method itself never builds the body, it only forwards whatever
//     its caller already built one layer up. Juice Shop's UserService.login
//     is exactly this shape: `login(e){...this.http.post(url,e)...}`, and
//     `e` is nothing but that method's own parameter. Resolved by finding
//     the enclosing method's own name (enclosingFuncParam), then searching
//     the bundle for where that method is itself called (".login(") and
//     resolving THAT call's own argument the same way — exactly one hop,
//     never recursive, so this can never chase an arbitrarily long or
//     cyclic call chain regardless of how the bundle is shaped.
//
// Returns no keys, never a guess, when neither shape resolves — a bundle's
// own true `payload`/`data`-named parameter with no discoverable origin at
// all stays unread, same as before this.
func resolveIndirectBody(body string, callAt int, obj string, consts map[string]string) (keys, urlKeys []string, literals map[string]string) {
	if jsIdentOrThisPropRe.MatchString(obj) {
		if k, u, l, ok := resolveBareObjectArg(body, callAt, obj, consts); ok {
			return k, u, l
		}
	}
	if !jsIdentRe.MatchString(obj) {
		return nil, nil, nil // only a function's own simple (never dotted) parameter can be a passthrough
	}
	funcName := enclosingFuncParam(body, callAt, obj)
	if len(funcName) < minPassthroughFuncNameLen || jsReservedWords[funcName] {
		return nil, nil, nil
	}
	return resolvePassthroughCallSites(body, funcName, consts)
}

// resolveBareObjectArg resolves ident (a bare identifier like "e", or a
// simple this-property reference like "this.user") back to the field names
// of the object it holds by callAt, searching backward within
// maxJSBodyLookup. Two shapes, tried in this order; ok is false when
// neither is found:
//
//  1. "ident = {...}" — an inline literal assigned to a plain local. An
//     empty literal ("ident = {}", Juice Shop's own first statement before
//     building the object field by field) correctly yields zero keys here,
//     falling through to shape 2 rather than stopping early.
//  2. "ident.field = value" (repeated) — sequential property assignment
//     onto an existing reference. Every distinct field assigned to ident in
//     the window becomes a key, read the same way jsObjectFields already
//     reads any other field's value (URL/literal detection included).
func resolveBareObjectArg(s string, callAt int, ident string, consts map[string]string) (keys, urlKeys []string, literals map[string]string, ok bool) {
	from := callAt - maxJSBodyLookup
	if from < 0 {
		from = 0
	}
	window := s[from:callAt]
	safeIdent := regexp.QuoteMeta(ident)

	if lit := findAssignedObjectLiteral(s, from, window, ident); lit != "" {
		if k, u, l := jsObjectFields(lit[1:len(lit)-1], consts); len(k) > 0 {
			return k, u, l, true
		}
	}

	re, err := regexp.Compile(`(?:^|[,;{(\s])` + safeIdent + `\.([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*([^,;]{1,200})`)
	if err != nil {
		return nil, nil, nil, false
	}
	seenKey := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(window, -1) {
		key := m[1]
		if !jsBodyKeyRe.MatchString(key) || seenKey[key] {
			continue
		}
		seenKey[key] = true
		keys = append(keys, key)
		value := m[2]
		if jsValueBuildsURL(value, consts) {
			urlKeys = append(urlKeys, key)
		}
		if lit, litOK := jsValueLiteral(value); litOK {
			if literals == nil {
				literals = map[string]string{}
			}
			literals[key] = lit
		}
	}
	return keys, urlKeys, literals, len(keys) > 0
}

// findAssignedObjectLiteral returns the full "{...}" text (braces included)
// of the last "ident = {" assignment in window before callAt, or "" if none
// exists or it doesn't balance — window is s[from:callAt], passed in rather
// than resliced again since every caller already has it.
func findAssignedObjectLiteral(s string, from int, window, ident string) string {
	re, err := regexp.Compile(`(?:^|[,;{(\s])` + regexp.QuoteMeta(ident) + `\s*=\s*\{`)
	if err != nil {
		return ""
	}
	matches := re.FindAllStringIndex(window, -1)
	if len(matches) == 0 {
		return ""
	}
	last := matches[len(matches)-1]
	open := from + last[1] - 1 // index of "{" itself, in s's coordinates
	end := matchClosing(s, open)
	if end < 0 || end-open > maxJSBodyLiteral {
		return ""
	}
	return s[open : end+1]
}

// enclosingFuncParam finds the name of the method whose body lexically
// contains callAt, when that method's own single declared parameter is
// paramIdent — i.e., when paramIdent is that method's own argument, not a
// locally declared variable. Searches backward within
// enclosingFuncLookback for "name(paramIdent){", closest to the call first,
// skipping a JS control-flow keyword's identically-shaped "if(paramIdent){"
// and any candidate whose body closes (an unmatched "}") before reaching
// callAt — i.e., one that isn't actually the call's own enclosing scope.
// Returns "" when nothing qualifies.
func enclosingFuncParam(s string, callAt int, paramIdent string) string {
	from := callAt - enclosingFuncLookback
	if from < 0 {
		from = 0
	}
	window := s[from:callAt]
	matches := jsFuncDefRe.FindAllStringSubmatchIndex(window, -1)
	for i := len(matches) - 1; i >= 0; i-- {
		m := matches[i]
		name := window[m[2]:m[3]]
		param := window[m[4]:m[5]]
		if param != paramIdent || jsReservedWords[name] {
			continue
		}
		openBrace := from + m[1] - 1 // index of "{" in s
		if stillInsideBody(s, openBrace, callAt) {
			return name
		}
	}
	return ""
}

// stillInsideBody reports whether callAt is still lexically inside the
// function body opened at s[openBrace] ("{") — i.e. its matching "}" comes
// after callAt. A simple net-brace-depth count over [openBrace, callAt],
// not a full parser, but enclosingFuncLookback keeps that window short
// enough for the approximation to be safe.
func stillInsideBody(s string, openBrace, callAt int) bool {
	depth := 0
	for i := openBrace; i < callAt && i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return false // closed before reaching the call
			}
		case '"', '\'', '`':
			j := skipJSString(s, i)
			if j < 0 {
				return false
			}
			i = j
		}
	}
	return true
}

// resolvePassthroughCallSites searches the whole bundle for a call to
// funcName as a member ("."+funcName+"(") and resolves the first one whose
// own argument yields field names — an inline literal, or resolvable via
// resolveBareObjectArg. Bounded to maxPassthroughCallSites call sites; an
// unrelated same-named method elsewhere in the bundle is harmless unless it
// too happens to fit one of those two shapes, in which case the first
// resolvable call site wins, same "first seen wins" convention
// extractJSBodyFields' own doc comment already states for routes.
func resolvePassthroughCallSites(body, funcName string, consts map[string]string) (keys, urlKeys []string, literals map[string]string) {
	re, err := regexp.Compile(`\.` + regexp.QuoteMeta(funcName) + `\(`)
	if err != nil {
		return nil, nil, nil
	}
	for i, loc := range re.FindAllStringIndex(body, -1) {
		if i >= maxPassthroughCallSites {
			break
		}
		args := splitTopLevel(callArgs(body, loc[1]), ',')
		if len(args) == 0 {
			continue
		}
		arg := strings.TrimSpace(args[0])
		if strings.HasPrefix(arg, "{") {
			end := matchClosing(arg, 0)
			if end < 0 || end > maxJSBodyLiteral {
				continue
			}
			if k, u, l := jsObjectFields(arg[1:end], consts); len(k) > 0 {
				return k, u, l
			}
			continue
		}
		if jsIdentOrThisPropRe.MatchString(arg) {
			if k, u, l, ok := resolveBareObjectArg(body, loc[0], arg, consts); ok {
				return k, u, l
			}
		}
	}
	return nil, nil, nil
}

// jsObjectFields lists the keys of an object literal's body ("a:1,b:x") and which
// of them have a value built from a route constant, the page origin or an absolute
// URL literal. A spread or a computed key is skipped. literals carries, for a field
// whose value is a simple true/false/integer literal in the source (LT-188 a: e.g.
// "number_of_repeats:1"), that literal's canonical JSON text — the app's own
// declared default, not an invented value, useful for a body-fill probe
// (--allow-ssrf-body-fill) that would otherwise send a placeholder string a
// strictly-typed field rejects.
func jsObjectFields(objBody string, consts map[string]string) (keys, urlKeys []string, literals map[string]string) {
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
		if !hasValue {
			continue
		}
		if jsValueBuildsURL(value, consts) {
			urlKeys = append(urlKeys, key)
		}
		if lit, ok := jsValueLiteral(value); ok {
			if literals == nil {
				literals = map[string]string{}
			}
			literals[key] = lit
		}
	}
	return keys, urlKeys, literals
}

// jsValueLiteral recognizes a value expression as a simple true/false/integer
// literal and returns its canonical JSON text. "!0"/"!1" are a common minifier
// idiom for true/false (double-negation coerces to boolean); anything else —
// a variable, a string, an expression — is not a literal this can read, and
// ok is false rather than a guess.
func jsValueLiteral(value string) (string, bool) {
	switch v := strings.TrimSpace(value); v {
	case "!0":
		return "true", true
	case "!1":
		return "false", true
	case "true", "false":
		return v, true
	default:
		if jsIntLiteralRe.MatchString(v) {
			return v, true
		}
		return "", false
	}
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
