package recon

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSuggestSSRFTargets(t *testing.T) {
	res := &ReconResult{Endpoints: []EndpointFact{
		{URL: "http://h.test/api/fetch?url=http://x&page=2"},
		{URL: "http://h.test/api/fetch?callback=1"}, // same path: merged
		{URL: "http://h.test/workshop/api/merchant/contact_mechanic", BodyParamKeys: []string{"mechanic_code", "mechanic_api", "vin"}, URLBodyParamKeys: []string{"mechanic_api"}},
		{URL: "http://h.test/api/webhooks", BodyParamKeys: []string{"callback_url", "name"}}, // keyword match, no URL key
		{URL: "http://h.test/api/vehicle/{carId}/location", BodyParamKeys: []string{"url"}},  // templated: no concrete path
		{URL: "http://h.test/static/app.js?url=1"}, // static asset
		{URL: "http://h.test/api/plain?page=2"},    // nothing URL-shaped
	}}
	got := SuggestSSRFTargets(res)
	require.Len(t, got, 3)
	assert.Equal(t, SSRFTarget{Path: "/api/fetch", Params: []string{"url", "callback"}}, got[0])
	assert.Equal(t, SSRFTarget{
		Path: "/workshop/api/merchant/contact_mechanic", BodyParams: []string{"mechanic_api"},
		FillFields: []string{"mechanic_code", "mechanic_api", "vin"},
	}, got[1], "BodyParams stays only the URL-carrying field; FillFields (LT-188 a) carries every recovered body key, for --allow-ssrf-body-fill")
	assert.Equal(t, SSRFTarget{
		Path: "/api/webhooks", BodyParams: []string{"callback_url"},
		FillFields: []string{"callback_url", "name"},
	}, got[2])
	assert.Nil(t, SuggestSSRFTargets(nil))
}
