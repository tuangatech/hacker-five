package recon

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHasBucketMarkerHeaders(t *testing.T) {
	cases := []struct {
		name string
		h    http.Header
		want bool
	}{
		{"GCS marker", http.Header{"X-Goog-Generation": []string{"12345"}}, true},
		{"S3 marker", http.Header{"X-Amz-Request-Id": []string{"abc"}}, true},
		{"guploader marker", http.Header{"X-Guploader-Uploadid": []string{"xyz"}}, true},
		{"no marker", http.Header{"Content-Type": []string{"text/html"}}, false},
		{"empty", http.Header{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, hasBucketMarkerHeaders(c.h))
		})
	}
}

// TestDropCatchallCommonPathEndpoints is LT-66 tail: a bucket host whose
// canary happened not to match a couple of common-path probes on (status,
// bodyLen, contentType) alone must still lose those probes' fabricated
// endpoints once the whole host is classified catchall — keyed on an exact
// body-hash duplicate across ≥2 probed paths, or a bucket marker header on
// even one of them. A probed path with neither signal (a genuinely distinct
// body, no bucket header) survives.
func TestDropCatchallCommonPathEndpoints(t *testing.T) {
	agg := &aggregator{
		endpoints: []EndpointFact{
			{URL: "https://bucket.example.com/api", Source: "wave3-common-path-probe"},
			{URL: "https://bucket.example.com/graphql", Source: "wave3-common-path-probe"},
			{URL: "https://bucket.example.com/swagger.json", Source: "wave3-common-path-probe"},
			{URL: "https://bucket.example.com/real-route", Source: "katana"}, // different source, never touched
		},
	}
	hits := []commonPathHit{
		{url: "https://bucket.example.com/api", bodyHash: 111},          // duplicates /graphql's hash -> drop
		{url: "https://bucket.example.com/graphql", bodyHash: 111},      // duplicates /api's hash -> drop
		{url: "https://bucket.example.com/swagger.json", bodyHash: 222, bucketMarker: true}, // unique hash but bucket marker -> drop
	}

	dropCatchallCommonPathEndpoints(agg, "bucket.example.com", hits)

	var urls []string
	for _, ep := range agg.endpoints {
		urls = append(urls, ep.URL)
	}
	assert.Equal(t, []string{"https://bucket.example.com/real-route"}, urls, "all three wave3-common-path-probe endpoints are dropped; the katana one survives untouched")
}

func TestDropCatchallCommonPathEndpoints_NoDuplicatesOrMarkers_NothingDropped(t *testing.T) {
	agg := &aggregator{
		endpoints: []EndpointFact{
			{URL: "https://example.com/api", Source: "wave3-common-path-probe"},
			{URL: "https://example.com/graphql", Source: "wave3-common-path-probe"},
		},
	}
	hits := []commonPathHit{
		{url: "https://example.com/api", bodyHash: 111},
		{url: "https://example.com/graphql", bodyHash: 222},
	}

	dropCatchallCommonPathEndpoints(agg, "example.com", hits)

	assert.Len(t, agg.endpoints, 2, "distinct bodies, no bucket marker -> both are real, neither is dropped")
}
