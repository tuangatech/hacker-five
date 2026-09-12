package sqli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
)

// withTestTimePayloads temporarily swaps timePayloads for a fast,
// test-scale sleep (real timePayloads' 5s nominal sleep would make this
// test take tens of seconds) and restores the original on return.
func withTestTimePayloads(t *testing.T, tp []timePayload) {
	t.Helper()
	orig := timePayloads
	timePayloads = tp
	t.Cleanup(func() { timePayloads = orig })
}

func newTestClient() *httpclient.Client {
	return httpclient.New(httpclient.Config{
		Timeout:             5 * time.Second,
		MaxRedirects:        5,
		MaxIdleConnsPerHost: 10,
	})
}

// TestTimeBasedCheck_Hit_RepeatConfirmed mirrors a blind time-based
// endpoint: the sleep payload delays the response, and the delay repeats on
// the confirm request — exactly what timeBasedCheck requires before
// reporting.
func TestTimeBasedCheck_Hit_RepeatConfirmed(t *testing.T) {
	const suffix = "' AND SLEEPTEST-- -"
	withTestTimePayloads(t, []timePayload{{"TestDB", suffix, 0.2}})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("id") != "1" {
			time.Sleep(250 * time.Millisecond)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	d := New(newTestClient())
	findings := d.runParam(context.Background(), srv.URL+"?id=1", "id", "", hostMust(t, srv.URL))

	got := withPrefixLocal(findings, "sqli-time-id")
	if len(got) != 1 {
		t.Fatalf("got %d time-based findings, want 1: %+v", len(got), findings)
	}
	if got[0].Confidence != "medium" {
		t.Fatalf("got confidence %q, want medium", got[0].Confidence)
	}
}

// TestTimeBasedCheck_DelayDoesNotRepeat_NoFinding: the first probe happens
// to be slow (server jitter/GC pause), but the confirm request is fast — no
// finding, since the delay wasn't reproducible.
func TestTimeBasedCheck_DelayDoesNotRepeat_NoFinding(t *testing.T) {
	const suffix = "' AND SLEEPTEST-- -"
	withTestTimePayloads(t, []timePayload{{"TestDB", suffix, 0.2}})

	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("id") != "1" {
			calls++
			if calls == 1 {
				time.Sleep(250 * time.Millisecond) // only the first payload probe is slow
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	d := New(newTestClient())
	findings := d.runParam(context.Background(), srv.URL+"?id=1", "id", "", hostMust(t, srv.URL))

	got := withPrefixLocal(findings, "sqli-time-id")
	if len(got) != 0 {
		t.Fatalf("got %d time-based findings, want 0 (delay didn't repeat): %+v", len(got), findings)
	}
}

// TestTimeBasedCheck_SlowBaseline_Skipped: a baseline already close to the
// ceiling makes any timing comparison meaningless — skipped outright, even
// though every payload probe would also be slow (a uniformly slow backend,
// not a SQL sleep).
func TestTimeBasedCheck_SlowBaseline_Skipped(t *testing.T) {
	const suffix = "' AND SLEEPTEST-- -"
	withTestTimePayloads(t, []timePayload{{"TestDB", suffix, 0.2}})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2100 * time.Millisecond) // every response, baseline included, is slow
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	d := New(newTestClient())
	baseline, ok := d.probeWithToken(context.Background(), srv.URL+"?id=1", "", hostMust(t, srv.URL))
	if !ok {
		t.Fatalf("baseline probe failed")
	}
	findings := d.timeBasedCheck(context.Background(), srv.URL+"?id=1", "id", "", hostMust(t, srv.URL), baseline)
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0 (baseline already slow): %+v", len(findings), findings)
	}
}

func hostMust(t *testing.T, rawURL string) string {
	t.Helper()
	h, err := hostOf(rawURL)
	if err != nil {
		t.Fatalf("hostOf(%q): %v", rawURL, err)
	}
	return h
}

func withPrefixLocal(findings []detectors.Finding, prefix string) []detectors.Finding {
	var out []detectors.Finding
	for _, f := range findings {
		if strings.HasPrefix(f.ID, prefix) {
			out = append(out, f)
		}
	}
	return out
}
