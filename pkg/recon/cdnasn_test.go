package recon

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCDNForASNField(t *testing.T) {
	assert.Equal(t, "Cloudflare", cdnForASNField("13335"))
	assert.Equal(t, "Akamai", cdnForASNField("20940"))
	assert.Equal(t, "Fastly", cdnForASNField("AS54113"))
	assert.Equal(t, "Akamai", cdnForASNField("20940 16509"), "the first known CDN AS in a multi-origin field wins")
	assert.Equal(t, "", cdnForASNField("16509"), "a generic cloud AS (AWS) is deliberately not in the table")
	assert.Equal(t, "", cdnForASNField(""))
	assert.Equal(t, "", cdnForASNField("not-a-number"))
}

// TestRunNaabu_SkipsCDNEdgeHost guards LT-61: a host Wave 1 marked as
// resolving into a known CDN AS is dropped from the port scan with a
// warning; a real host alongside it is still scanned.
func TestRunNaabu_SkipsCDNEdgeHost(t *testing.T) {
	var naabuStdin string
	var naabuRan bool
	fake := func(_ context.Context, stdin string, name string, _ ...string) ([]byte, error) {
		if name == "naabu" {
			naabuRan = true
			naabuStdin = stdin
		}
		return nil, nil
	}
	r := New(newTestClient(), withRun(fake))

	// Every host is a CDN edge -> naabu must not run at all.
	agg := &aggregator{target: "https://edge.example"}
	agg.markCDNEdge("edge.example", "Akamai")
	got := r.runNaabu(context.Background(), agg, []string{"edge.example"})
	assert.Nil(t, got)
	assert.False(t, naabuRan, "naabu must not run when every host is a CDN edge")
	joined := strings.Join(agg.warnings, " | ")
	assert.Contains(t, joined, "LT-61")
	assert.Contains(t, joined, "Akamai")

	// Mixed: the CDN host is skipped, the real host is still scanned.
	naabuRan = false
	agg2 := &aggregator{target: "https://edge.example"}
	agg2.markCDNEdge("edge.example", "Akamai")
	input := []string{"edge.example", "origin.example"}
	_ = r.runNaabu(context.Background(), agg2, input)
	assert.True(t, naabuRan)
	assert.Contains(t, naabuStdin, "origin.example")
	assert.NotContains(t, naabuStdin, "edge.example")
	assert.Equal(t, []string{"edge.example", "origin.example"}, input, "the caller's host slice must not be mutated")
}
