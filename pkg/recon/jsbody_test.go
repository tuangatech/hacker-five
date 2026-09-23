package recon

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A trimmed copy of the request code in crAPI's served bundle (2026-09-21): a saga
// that posts a JSON body whose "mechanic_api" field is built from the page origin
// and a route constant. Only the template literal for the header is changed.
const crapiContactMechanicJS = `sg={GET_MECHANICS:"api/mechanic",CONTACT_MECHANIC:"api/merchant/contact_mechanic",RECEIVE_REPORT:"api/mechanic/receive_report"},ig="workshop/";` +
	`function*hv(e){const{accessToken:t,callback:n,mechanicCode:r,problemDetails:o,vin:i}=e.payload;let a={};try{yield br({type:fo.FETCHING_DATA});` +
	`const e=ig+sg.CONTACT_MECHANIC,l={"Content-Type":"application/json",Authorization:"Bearer "+t},s=new URL(window.location.href).origin,` +
	`c=yield fetch(e,{headers:l,method:"POST",body:JSON.stringify({mechanic_code:r,problem_details:o,vin:i,` +
	`mechanic_api:s+"/"+ig+sg.RECEIVE_REPORT,repeat_request_if_failed:!1,number_of_repeats:1})}).then((e=>(a=e,e.json())));yield br({type:fo.FETCHED_DATA,payload:a})}catch($v){}}` +
	`function*Av(e){const e2=ig+sg.GET_MECHANICS,i=yield fetch(e2,{headers:{},method:"GET"}).then((e=>e.json()))}`

func TestExtractJSBodyFields_CrapiContactMechanic(t *testing.T) {
	got := extractJSBodyFields(crapiContactMechanicJS)
	require.Len(t, got, 1, "only the call with an inline JSON body is read; the GET has none")
	assert.Equal(t, "api/merchant/contact_mechanic", got[0].Route)
	assert.Equal(t, []string{"mechanic_code", "problem_details", "vin", "mechanic_api", "repeat_request_if_failed", "number_of_repeats"}, got[0].Keys)
	assert.Equal(t, []string{"mechanic_api"}, got[0].URLKeys, "the field the bundle fills with origin + a route constant carries a URL")
	assert.Equal(t, map[string]string{"repeat_request_if_failed": "false", "number_of_repeats": "1"}, got[0].Literals,
		"LT-188 (a): the bundle's own !1/!0 minifier idiom and integer literal are recovered as the app's declared defaults")
}

func TestExtractJSBodyFields_Variants(t *testing.T) {
	consts := `R={SAVE:"api/profile/save",HOOK:"api/hooks/register"};`
	cases := map[string]struct {
		js   string
		want []jsBodyFields
	}{
		"axios post, url expression inline": {consts + `a.post(base+R.SAVE,{name:n,avatar_url:"https://x/"+R.HOOK,age:3})`,
			[]jsBodyFields{{Route: "api/profile/save", Keys: []string{"name", "avatar_url", "age"}, URLKeys: []string{"avatar_url"}, Literals: map[string]string{"age": "3"}}}},
		"quoted keys and a spread": {consts + `fetch(u+R.SAVE,{method:"PUT",body:JSON.stringify({"a-b":1,...rest,c:2})})`,
			[]jsBodyFields{{Route: "api/profile/save", Keys: []string{"a-b", "c"}, Literals: map[string]string{"a-b": "1", "c": "2"}}}},
		"a body that is a variable is not guessed at": {consts + `fetch(u+R.SAVE,{method:"POST",body:JSON.stringify(payload)})`, nil},
		// LT-186 (d) follow-on: a plain absolute-path literal URL, no named
		// route constant involved at all, now resolves via the literal
		// itself (jsCallRouteFromLiteral) — this used to return nil.
		"a plain literal URL with no route constant now resolves via the literal": {consts + `fetch("/other",{method:"POST",body:JSON.stringify({a:1})})`,
			[]jsBodyFields{{Route: "/other", Keys: []string{"a"}, Literals: map[string]string{"a": "1"}}}},
		"a url built from a truly unresolved variable stays unresolved": {consts + `fetch(unknownVar,{method:"POST",body:JSON.stringify({a:1})})`, nil},
		"no route constants in the bundle":                              {`fetch(e,{method:"POST",body:JSON.stringify({a:1})})`, nil},
		"unbalanced call is skipped, not fatal":                         {consts + `fetch(u+R.SAVE,{method:"POST",body:JSON.stringify({a:1`, nil},
	}
	for name, c := range cases {
		assert.Equal(t, c.want, extractJSBodyFields(c.js), name)
	}
}

// juiceShopLoginJS is a trimmed copy of the real shape found live in Juice
// Shop's served bundle (2026-09-23): no named route constant anywhere (every
// route is an inline template literal), and the service method that actually
// posts never builds the body itself — it just forwards its own single
// parameter, which the *caller* built one call frame up by mutating an
// initially empty object field by field. The route constant declaration
// below only exists so extractJSBodyFields' own len(consts)==0 early-exit
// doesn't apply; it plays no other part in this shape.
const juiceShopLoginJS = `X={UNUSED:"api/unused"};` +
	`class UserService{login(e){return this.isLoggedIn.next(!0),this.http.post(this.hostServer+` + "`" + `/rest/user/login` + "`" + `,e).pipe(Q$2(t=>t.authentication))}}` +
	`class LoginComponent{login(){this.user={},this.user.email=this.emailControl.value,this.user.password=this.passwordControl.value,this.userService.login(this.user).subscribe({next:e=>{}})}}`

func TestExtractJSBodyFields_JuiceShopLoginPassthrough(t *testing.T) {
	got := extractJSBodyFields(juiceShopLoginJS)
	require.Len(t, got, 1)
	assert.Equal(t, "/rest/user/login", got[0].Route)
	assert.Equal(t, []string{"email", "password"}, got[0].Keys)
	assert.Empty(t, got[0].URLKeys)
}

// TestExtractJSBodyFields_InlineLiteralAssignedToBareVariable covers the
// simpler of the two new LT-186 (d) follow-on shapes: a local variable
// assigned an inline object literal, then passed by reference — no
// passthrough hop needed, resolved entirely within resolveBareObjectArg's
// first branch.
func TestExtractJSBodyFields_InlineLiteralAssignedToBareVariable(t *testing.T) {
	consts := `R={SAVE:"api/profile/save"};`
	js := consts + `let x={name:n,age:3};a.post(base+R.SAVE,x)`
	got := extractJSBodyFields(js)
	require.Len(t, got, 1)
	assert.Equal(t, "api/profile/save", got[0].Route)
	assert.Equal(t, []string{"name", "age"}, got[0].Keys)
	assert.Equal(t, map[string]string{"age": "3"}, got[0].Literals)
}

// TestExtractJSBodyFields_UnresolvablePassthrough proves the passthrough
// hop stays exactly one level: a method that forwards its own parameter,
// called from somewhere that itself only forwards *its* parameter too (two
// hops), is not chased — never a guess past the one hop live evidence
// justified.
func TestExtractJSBodyFields_UnresolvablePassthrough(t *testing.T) {
	consts := `R={SAVE:"api/profile/save"};`
	js := consts + `function inner(e){return a.post(base+R.SAVE,e)}` +
		`function outer(p){return svc.inner(p)}` // outer's own arg to inner is itself just a passthrough — never resolved
	assert.Empty(t, extractJSBodyFields(js))
}

// TestExtractJSBodyFields_ReservedWordNotMistakenForMethodName guards
// enclosingFuncParam against "if(e){"'s identical textual shape to a
// one-param method definition: the real enclosing method, handler(e){, sits
// one level further back than the if-block wrapping the call, and must
// still be found — if "if" were mistaken for the method name instead, the
// passthrough search below would look for ".if(" call sites (none exist)
// and this would resolve to nothing at all.
func TestExtractJSBodyFields_ReservedWordNotMistakenForMethodName(t *testing.T) {
	consts := `R={SAVE:"api/profile/save"};`
	js := consts + `function handler(e){if(e){return a.post(base+R.SAVE,e)}}` +
		`svc.handler({name:n,age:3})`
	got := extractJSBodyFields(js)
	require.Len(t, got, 1)
	assert.Equal(t, "api/profile/save", got[0].Route)
	assert.Equal(t, []string{"name", "age"}, got[0].Keys)
}

// TestRunWave3_JSStatic_BodyFieldsReachAbsolutePathEndpoint is
// TestRunWave3_JSJoin_BodyFieldsReachTheSSRFSuggestion's counterpart for the
// *other* endpoint-building loop in runJSStaticAnalysis (LT-186 d follow-on):
// a bundle whose routes are plain absolute-path literals, never "api/..."
// bases the join mechanism's own isJSAPIPathBaseCandidate would ever accept
// (it requires the first segment to literally be "api"), reaches
// EndpointFact.BodyParamKeys through the js-static source instead — this
// used to be entirely unwired, so bodyByRoute was built but never consulted
// for any endpoint extractJSEndpoints (as opposed to the join mechanism)
// produced.
func TestRunWave3_JSStatic_BodyFieldsReachAbsolutePathEndpoint(t *testing.T) {
	f := newJoinFixture(t, nil, nil)
	result := f.recon(t, juiceShopLoginJS)

	var fact *EndpointFact
	for i := range result.Endpoints {
		if strings.HasSuffix(result.Endpoints[i].URL, "/rest/user/login") {
			fact = &result.Endpoints[i]
		}
	}
	require.NotNil(t, fact)
	assert.Equal(t, "js-static", fact.Source)
	assert.Equal(t, []string{"email", "password"}, fact.BodyParamKeys)
}

// LT-188 (a): jsValueLiteral only ever recognizes the true/false/integer shapes
// it documents — a variable, a string or an expression is never guessed at.
func TestJSValueLiteral(t *testing.T) {
	cases := map[string]struct {
		val    string
		want   string
		wantOK bool
	}{
		"minifier true":     {"!0", "true", true},
		"minifier false":    {"!1", "false", true},
		"literal true":      {"true", "true", true},
		"literal false":     {"false", "false", true},
		"positive integer":  {"42", "42", true},
		"negative integer":  {"-1", "-1", true},
		"padded":            {"  7  ", "7", true},
		"a variable":        {"n", "", false},
		"a string literal":  {`"1"`, "", false},
		"a decimal":         {"1.5", "", false},
		"an expression":     {"a+1", "", false},
		"an overlong digit": {"1234567890123", "", false},
	}
	for name, c := range cases {
		got, ok := jsValueLiteral(c.val)
		assert.Equal(t, c.wantOK, ok, name)
		assert.Equal(t, c.want, got, name)
	}
}

// LT-186 (d) end to end: the bundle's request code puts the URL-carrying body field
// on the joined route, and the SSRF suggestion picks it up although "mechanic_api"
// matches no URL keyword.
func TestRunWave3_JSJoin_BodyFieldsReachTheSSRFSuggestion(t *testing.T) {
	f := newJoinFixture(t, map[string]int{
		"/workshop/api/merchant/contact_mechanic": http.StatusMethodNotAllowed,
	}, nil)
	result := f.recon(t, crapiContactMechanicJS)

	var fact *EndpointFact
	for i := range result.Endpoints {
		if strings.HasSuffix(result.Endpoints[i].URL, "/workshop/api/merchant/contact_mechanic") {
			fact = &result.Endpoints[i]
		}
	}
	require.NotNil(t, fact)
	assert.Contains(t, fact.BodyParamKeys, "mechanic_code")
	assert.Equal(t, []string{"mechanic_api"}, fact.URLBodyParamKeys)
	assert.Equal(t, []string{"mechanic_api"}, SuggestSSRFBodyParamsFromRecon(result))
	assert.Equal(t, map[string]string{"repeat_request_if_failed": "false", "number_of_repeats": "1"}, fact.BodyParamLiterals,
		"LT-188 (a) end to end: the recovered literals reach the endpoint fact")

	targets := SuggestSSRFTargets(result)
	require.Len(t, targets, 1)
	assert.Equal(t, map[string]string{"repeat_request_if_failed": "false", "number_of_repeats": "1"}, targets[0].FillValues,
		"and from there into the SSRFTarget a --allow-ssrf-body-fill probe reads")
}
