package ssrf

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/oob"
)

// oobPollDelay is how long checkOOBCallback waits after firing every probe
// before polling once for interactions — enough time for a same-network
// target to make its outbound request and the OOB server to record it.
// May need lengthening for a real target that processes the fetch
// asynchronously (a background job/queue) rather than inline with the
// probe request — a real, target-dependent tuning question, not guessed
// further here.
const oobPollDelay = 5 * time.Second

// checkOOBCallback fires one request per param embedding a unique per-probe
// payload host, waits, then polls the OOB server once and correlates any
// HTTP interaction back to the probe that triggered it — proof the target
// actually made an outbound request, independent of what its own HTTP
// response says. oobServers is tried in order (oob.NewClientWithFallback) —
// more than one entry only happens via a repeatable --oob-server (e.g. the
// "public" shorthand expanding to PublicInteractshServers), so one server
// being unreachable doesn't stall the whole check.
func (d *Detector) checkOOBCallback(ctx context.Context, target, authToken string, params []string, oobServers []string) ([]detectors.Finding, error) {
	client, err := oob.NewClientWithFallback(ctx, &http.Client{Timeout: 10 * time.Second}, oobServers)
	if err != nil {
		return nil, fmt.Errorf("ssrf: setting up oob client: %w", err)
	}
	defer client.Deregister(context.Background())

	type firedProbe struct {
		param string
		nonce string
		url   string
	}
	var probes []firedProbe
	for _, param := range params {
		payloadHost, nonce := client.NewPayloadHost()
		payloadURL := "http://" + payloadHost + "/ssrf-probe"
		probeURL := buildProbeURL(target, param, payloadURL)
		if _, _, _, err := d.doRequest(ctx, probeURL, authToken); err != nil {
			continue // couldn't even send this probe — nothing to poll for
		}
		probes = append(probes, firedProbe{param: param, nonce: nonce, url: probeURL})
	}
	if len(probes) == 0 {
		return nil, nil
	}

	select {
	case <-time.After(oobPollDelay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	interactions, err := client.Poll(ctx)
	if err != nil {
		return nil, fmt.Errorf("ssrf: polling oob server: %w", err)
	}

	var findings []detectors.Finding
	for _, it := range interactions {
		if !strings.EqualFold(it.Protocol, "http") {
			continue // DNS-only lookups aren't proof of an actual fetch
		}
		for _, p := range probes {
			if !strings.Contains(it.FullID, p.nonce) && !strings.Contains(it.UniqueID, p.nonce) {
				continue
			}
			findings = append(findings, detectors.Finding{
				ID:          fmt.Sprintf("ssrf-oob-callback-%s", sanitizeID(p.param)),
				Type:        "ssrf",
				Severity:    "critical",
				Confidence:  "high",
				Target:      p.url,
				Description: fmt.Sprintf("%s parameter triggered a real outbound HTTP request to a self-hosted OOB server — blind SSRF confirmed independent of the target's own HTTP response", p.param),
				Evidence: map[string]string{
					"param":           p.param,
					"payload_url":     p.url,
					"oob_remote_addr": it.RemoteAddress,
					"oob_raw_request": it.RawRequest,
				},
			})
			break
		}
	}
	return findings, nil
}
