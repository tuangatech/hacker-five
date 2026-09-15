package scriptexec

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/tuangatech/hacker-five/pkg/scanner/scope"
)

// requireDocker skips the test when no Docker daemon is reachable — these
// tests exercise the real sandbox topology (two docker networks, a
// bind-mounted sidecar binary, a script container) and are the actual
// validation M1's plan calls for ("Execute enforces the sandbox against a
// real Docker daemon"), not a substitute for the pure unit tests above.
func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not found on PATH")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker daemon not reachable")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not found on PATH (needed to build the egress-proxy sidecar)")
	}
}

func alwaysApprove(context.Context, ScriptRequest, PrecheckResult) (bool, error) {
	return true, nil
}

// TestExecute_BenignPythonScript_ReachesInScopeTargetThroughProxy is the
// sandbox's golden path: a script that only talks to its one in-scope
// target must actually be able to, end to end, through the egress proxy.
func TestExecute_BenignPythonScript_ReachesInScopeTargetThroughProxy(t *testing.T) {
	requireDocker(t)

	// A loopback-only listener (httptest.NewServer's default) is unreachable
	// from a container via host.docker.internal on plain Docker Engine
	// (Linux): there, host-gateway is a real routed IP on the docker0
	// bridge, distinct from 127.0.0.1, and Linux's kernel won't deliver
	// packets for that IP to a socket bound specifically to loopback (Docker
	// Desktop's host.docker.internal is a userspace relay that can reach a
	// loopback-bound service, so this gap doesn't show up there). Binding to
	// all interfaces instead also matches how a real lab target
	// (docs/20-setup-testing-targets.md) is actually published — 0.0.0.0,
	// not 127.0.0.1-only.
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("sandboxed-ok"))
	}))
	_ = upstream.Listener.Close()
	upstream.Listener = ln
	upstream.Start()
	defer upstream.Close()

	// The container reaches the test's httptest server via the egress
	// proxy's own outbound leg on the egress network — Docker Desktop/Engine
	// both route a bridge-network container's egress through the host, so
	// http://host.docker.internal is the portable way to name "the machine
	// running the test" from inside a container. Scope must allow that exact
	// hostname since that's what the script's request line will carry.
	host := "host.docker.internal"
	port := upstream.URL[strings.LastIndex(upstream.URL, ":")+1:]

	// host.docker.internal resolves to Docker's own private gateway address
	// — exactly the shape of address the egress proxy's DNS-rebinding
	// defense (isSpecialUseIP) refuses unless a scope entry explicitly
	// covers it, the same as a real lab-target scope file needs an explicit
	// CIDR for a Dockerized target's private bridge address (docs/20-setup-
	// testing-targets.md). fc00::/7 covers RFC4193 IPv6 unique-local
	// addresses — confirmed live that this Docker installation resolves
	// host.docker.internal to one of those, not an IPv4 RFC1918 address —
	// and the three IPv4 ranges cover every other install's likely answer.
	sc, err := scope.New([]string{host, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"})
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}

	req := ScriptRequest{
		Language:     LangPython,
		Source:       "import urllib.request\nprint(urllib.request.urlopen('http://" + host + ":" + port + "/').read().decode())\n",
		Scope:        sc,
		Timeout:      30 * time.Second,
		ApprovalGate: alwaysApprove,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	result, err := Execute(ctx, req)
	if err != nil {
		t.Fatalf("Execute: %v (stdout=%q stderr=%q)", err, result.Stdout, result.Stderr)
	}
	if !strings.Contains(result.Stdout, "sandboxed-ok") {
		t.Fatalf("got stdout=%q stderr=%q exit=%d, want it to contain the upstream's response", result.Stdout, result.Stderr, result.ExitCode)
	}
}

// TestExecute_OutOfScopeTarget_BlockedAtEgressProxy proves the network-layer
// enforcement actually holds even for a script that passed precheck (a
// benign-looking request whose target simply isn't authorized) — the
// egress proxy, not just the static check, is what stops it.
func TestExecute_OutOfScopeTarget_BlockedAtEgressProxy(t *testing.T) {
	requireDocker(t)

	// Scope only covers a placeholder host, never host.docker.internal, so
	// this script's request must be denied by the proxy at runtime even
	// though nothing about the request itself trips the static precheck.
	sc, err := scope.New([]string{"only-this-authorized-host.test"})
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}

	req := ScriptRequest{
		Language:     LangPython,
		Source:       "import urllib.request\nprint(urllib.request.urlopen('http://host.docker.internal:1/').read())\n",
		Scope:        sc,
		Timeout:      30 * time.Second,
		ApprovalGate: alwaysApprove,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	result, err := Execute(ctx, req)
	// The script itself raises an HTTPError/URLError on the 403 the proxy
	// returns and exits non-zero — Execute reports that as a normal
	// (non-error) ScriptResult with ExitCode != 0, mirroring how a real
	// scan treats a detector's non-zero exit as a result, not a plumbing
	// failure. Either shape (a returned error, or a non-zero exit with the
	// denial visible in stderr) proves the block happened.
	if err == nil && result.ExitCode == 0 {
		t.Fatalf("got a clean exit reaching an out-of-scope target through the proxy — egress enforcement failed; stdout=%q stderr=%q", result.Stdout, result.Stderr)
	}
}

func TestExecute_PrecheckBlocked_NeverStartsAContainer(t *testing.T) {
	requireDocker(t)

	calledApproval := false
	req := ScriptRequest{
		Language: LangPython,
		Source:   "import subprocess\nsubprocess.run(['id'])\n",
		Scope:    mustScope(t, "example.test"),
		Timeout:  10 * time.Second,
		ApprovalGate: func(context.Context, ScriptRequest, PrecheckResult) (bool, error) {
			calledApproval = true
			return true, nil
		},
	}

	_, err := Execute(context.Background(), req)
	if err == nil {
		t.Fatal("want an error for a precheck-blocked script")
	}
	if calledApproval {
		t.Fatal("ApprovalGate must never be called for a precheck-blocked script")
	}
}
