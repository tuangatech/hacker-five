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
}

func TestExtractJSBodyFields_Variants(t *testing.T) {
	consts := `R={SAVE:"api/profile/save",HOOK:"api/hooks/register"};`
	cases := map[string]struct {
		js   string
		want []jsBodyFields
	}{
		"axios post, url expression inline": {consts + `a.post(base+R.SAVE,{name:n,avatar_url:"https://x/"+R.HOOK,age:3})`,
			[]jsBodyFields{{Route: "api/profile/save", Keys: []string{"name", "avatar_url", "age"}, URLKeys: []string{"avatar_url"}}}},
		"quoted keys and a spread": {consts + `fetch(u+R.SAVE,{method:"PUT",body:JSON.stringify({"a-b":1,...rest,c:2})})`,
			[]jsBodyFields{{Route: "api/profile/save", Keys: []string{"a-b", "c"}}}},
		"a body that is a variable is not guessed at": {consts + `fetch(u+R.SAVE,{method:"POST",body:JSON.stringify(payload)})`, nil},
		"a url that resolves to no route constant":    {consts + `fetch("/other",{method:"POST",body:JSON.stringify({a:1})})`, nil},
		"no route constants in the bundle":            {`fetch(e,{method:"POST",body:JSON.stringify({a:1})})`, nil},
		"unbalanced call is skipped, not fatal":       {consts + `fetch(u+R.SAVE,{method:"POST",body:JSON.stringify({a:1`, nil},
	}
	for name, c := range cases {
		assert.Equal(t, c.want, extractJSBodyFields(c.js), name)
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
}
