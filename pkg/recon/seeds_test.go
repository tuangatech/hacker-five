package recon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
)

const seedTestUUID = "3f2b8c1e-5d4a-4e7b-9a10-2c6d8e0f1a23"

func TestHarvestUUIDSeed(t *testing.T) {
	cases := map[string]struct{ body, want string }{
		"array of objects, uuid key": {`[{"uuid":"` + seedTestUUID + `","vin":"X"}]`, seedTestUUID},
		"id key":                     {`[{"id":"` + seedTestUUID + `"}]`, seedTestUUID},
		"wrapped list":               {`{"vehicles":[{"uuid":"` + seedTestUUID + `"}],"total":1}`, seedTestUUID},
		"single object":              {`{"id":"` + seedTestUUID + `","name":"n"}`, seedTestUUID},
		"uuid on a later element":    {`[{"vin":"a"},{"uuid":"` + seedTestUUID + `"}]`, seedTestUUID},
		"a foreign key is not the object's own id": {`[{"owner_id":"` + seedTestUUID + `","user_uuid":"` + seedTestUUID + `"}]`, ""},
		"integer id is not a uuid seed":            {`[{"id":7}]`, ""},
		"not json":                                 {`<html>`, ""},
		"scalar":                                   {`"` + seedTestUUID + `"`, ""},
	}
	for name, c := range cases {
		assert.Equal(t, c.want, harvestUUIDSeed([]byte(c.body)), name)
	}
}

func TestResourceStem(t *testing.T) {
	for in, want := range map[string]string{"vehicles": "vehicle", "vehicle": "vehicle", "Vehicle_s": "vehicle",
		"orders": "order", "categories": "category", "user-profiles": "userprofile", "me": "me"} {
		assert.Equal(t, want, resourceStem(in), in)
	}
}

func TestAttachHarvestedSeeds(t *testing.T) {
	agg := &aggregator{endpoints: []EndpointFact{
		{URL: "http://h.test/identity/api/v2/vehicle/{carId}/location"},
		{URL: "http://h.test/api/orders/{orderId}"},
		{URL: "http://h.test/api/users/{id}/posts"},
		{URL: "http://other.test/api/orders/{orderId}"},
		{URL: "http://h.test/identity/api/v2/user/dashboard"}, // not templated
	}}
	n := attachHarvestedSeeds(agg, map[string]string{
		"http://h.test/identity/api/v2/vehicle/vehicles": "veh-1",
		"http://h.test/api/orders":                       "ord-1",
		"http://h.test/api/v2/vehicles":                  "wrong-service",
	})
	assert.Equal(t, 2, n)
	assert.Equal(t, "veh-1", agg.endpoints[0].SeedID, "list under the same service, resource named vehicle/vehicles")
	assert.Equal(t, "ord-1", agg.endpoints[1].SeedID, "the collection itself is a list of the resource")
	assert.Empty(t, agg.endpoints[2].SeedID, "no list names the users resource")
	assert.Empty(t, agg.endpoints[3].SeedID, "a list on another host never seeds this host")
	assert.Empty(t, agg.endpoints[4].SeedID)
}

// LT-186 (c): an authenticated recon of a crAPI-shaped service. Identity answers 401
// to every anonymous request and, signed in, serves a vehicle list whose ids key a
// templated location route. Checks the whole chain: status kept on the joined route,
// a credential-free re-probe for "protected", the id harvested into a templated
// route, offered to idor as a harvested seed, and absent from the serialised result.
func TestRun_AuthenticatedRecon_HarvestsSeedAndProtectedPaths(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authed := r.Header.Get("Authorization") == "Bearer tok"
		switch {
		case strings.HasPrefix(r.URL.Path, "/identity/"):
			switch {
			case !authed:
				w.WriteHeader(http.StatusUnauthorized) // blanket, real or not
			case r.URL.Path == "/identity/api/v2/vehicle/vehicles":
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`[{"uuid":"` + seedTestUUID + `","vin":"1HGCM"}]`))
			case r.URL.Path == "/identity/api/v2/user/dashboard":
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"name":"n"}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		case r.URL.Path == "/workshop/api/shop/orders/all":
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	js := `og="identity/",ig="workshop/",sg={VEHICLES:"api/v2/vehicle/vehicles",LOC:"api/v2/vehicle/<carId>/location",` +
		`DASH:"api/v2/user/dashboard",ORDERS:"api/shop/orders/all"};`
	jsJSON, err := json.Marshal(js)
	require.NoError(t, err)
	responses := map[string]string{
		"katana": `{"request":{"endpoint":"` + srv.URL + `/static/app.js","method":"GET"},` +
			`"response":{"status_code":200,"headers":{"content-type":"application/javascript"},"body":` + string(jsJSON) + `}}`,
	}

	run := func(signedIn bool) *ReconResult {
		_, fake := recordingRun(t, responses)
		opts := []Option{withRun(fake)}
		var mws []httpclient.Middleware
		if signedIn {
			cred, err := NewCredential(srv.URL, "tok", "", "")
			require.NoError(t, err)
			mws = append(mws, cred.Middleware())
			opts = append(opts, cred.Option())
		}
		client := httpclient.New(httpclient.Config{Timeout: 2 * time.Second, MaxRedirects: 5, MaxIdleConnsPerHost: 10}, mws...)
		res, err := New(client, opts...).Run(context.Background(), srv.URL, DepthFull)
		require.NoError(t, err)
		return res
	}
	byURL := func(res *ReconResult, suffix string) *EndpointFact {
		for i := range res.Endpoints {
			if strings.HasSuffix(res.Endpoints[i].URL, suffix) {
				return &res.Endpoints[i]
			}
		}
		return nil
	}

	res := run(true)

	vehicles := byURL(res, "/identity/api/v2/vehicle/vehicles")
	require.NotNil(t, vehicles, "the list route is found only when recon is signed in")
	assert.Equal(t, http.StatusOK, vehicles.StatusCode, "the verification status is kept on the joined route")
	assert.True(t, vehicles.AuthRequired, "an anonymous request to it is turned away (401)")

	protected, _, _ := SuggestAuthBypassPathsFromRecon(res)
	assert.Contains(t, protected, "/identity/api/v2/vehicle/vehicles", "a signed-in-only route is a protected-path candidate")
	assert.Contains(t, protected, "/identity/api/v2/user/dashboard")
	assert.Contains(t, protected, "/workshop/api/shop/orders/all", "a route that rejects even the token is protected too")

	seeds := SuggestIDORHarvestedSeeds(res)
	assert.Equal(t, map[string]string{"/identity/api/v2/vehicle/{{id}}/location": seedTestUUID}, seeds)
	assert.Empty(t, SuggestIDORSeedIDs(res), "a harvested id is never offered through the URL-observed path")

	raw, err := json.Marshal(res)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), seedTestUUID, "the harvested id must not appear in any serialised result")
	assert.Contains(t, strings.Join(res.Warnings, "\n"), "held in memory only")

	anon := run(false)
	assert.Nil(t, byURL(anon, "/identity/api/v2/vehicle/vehicles"), "anonymous recon cannot see past identity's blanket 401")
	assert.Empty(t, SuggestIDORHarvestedSeeds(anon))
}
