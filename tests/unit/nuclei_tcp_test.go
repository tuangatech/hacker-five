package unit

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/template/nuclei"
)

// redisDetectTCPTemplate mirrors real upstream's redis-detect.yaml shape
// (simplified): connect, send an unsolicited-nothing read... actually this
// one *sends* an INFO command and word-matches the reply — the common
// "send a fixed probe, read the reply, word-match" tcp: shape Phase 8
// Step 1 targets (docs/17-implementation-plan-ph8.md).
const redisDetectTCPTemplate = `
id: redis-detect-style
info:
  name: Redis Detect
  severity: info
tcp:
  - inputs:
      - data: "INFO\r\n"
    matchers:
      - type: word
        part: data
        words:
          - "redis_version"
`

// ftpBannerTCPTemplate is the simpler "read an unsolicited banner, no send
// at all" shape (real upstream ftp templates commonly just read the 220
// greeting).
const ftpBannerTCPTemplate = `
id: ftp-banner-style
info:
  name: FTP Banner
  severity: info
tcp:
  - inputs:
      - {}
    matchers:
      - type: word
        part: body
        words:
          - "FTP server ready"
`

// dslDataTCPTemplate exercises the bare "data" DSL identifier alias.
const dslDataTCPTemplate = `
id: dsl-data-style
info:
  name: DSL Data Identifier
  severity: info
tcp:
  - inputs:
      - {}
    matchers:
      - type: dsl
        dsl:
          - 'contains(data, "hello")'
`

// httpOnlyTemplateForTCPGate is an ordinary http: template with no tcp:
// block at all — used to confirm it never fires against a tcp:// target.
const httpOnlyTemplateForTCPGate = `
id: http-only-style
info:
  name: HTTP Only
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status:
          - 200
`

func newFakeTCPServerTCP(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(conn)
		}
	}()
	return ln.Addr().String()
}

func TestNucleiLoadDir_TCPTemplate_LoadsSuccessfully(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "redis-detect.yaml", redisDetectTCPTemplate)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)
}

func TestNucleiLoadDir_TCPTemplate_NoInputsRejected(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "bad.yaml", `
id: bad-tcp
info:
  name: Bad
tcp:
  - matchers:
      - type: word
        words:
          - "x"
`)
	_, errs := nuclei.LoadDir(dir)
	require.Len(t, errs, 1)
}

func TestNucleiLoadDir_TCPTemplate_InternalMatcherRejected(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "bad.yaml", `
id: bad-tcp-internal
info:
  name: Bad
tcp:
  - inputs:
      - {}
    matchers:
      - type: word
        words:
          - "x"
        internal: true
`)
	_, errs := nuclei.LoadDir(dir)
	require.Len(t, errs, 1)
}

func TestExecutorRun_TCP_SendThenReadMatches(t *testing.T) {
	addr := newFakeTCPServerTCP(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 64)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		if string(buf[:n]) == "INFO\r\n" {
			_, _ = conn.Write([]byte("redis_version:7.0.0\r\n"))
		}
	})

	dir := t.TempDir()
	writeTemplate(t, dir, "redis-detect.yaml", redisDetectTCPTemplate)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)

	findings, err := nuclei.New(newExecutorClient()).WithTCPTimeout(2*time.Second).
		Run(context.Background(), "tcp://"+addr, templates[0])
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "misconfig", findings[0].Type)
	assert.Contains(t, findings[0].Evidence["response"], "redis_version")
}

func TestExecutorRun_TCP_UnsolicitedBannerMatches(t *testing.T) {
	addr := newFakeTCPServerTCP(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		_, _ = conn.Write([]byte("220 FTP server ready\r\n"))
	})

	dir := t.TempDir()
	writeTemplate(t, dir, "ftp-banner.yaml", ftpBannerTCPTemplate)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)

	findings, err := nuclei.New(newExecutorClient()).WithTCPTimeout(2*time.Second).
		Run(context.Background(), "tcp://"+addr, templates[0])
	require.NoError(t, err)
	require.Len(t, findings, 1)
}

func TestExecutorRun_TCP_NoMatchProducesNoFinding(t *testing.T) {
	addr := newFakeTCPServerTCP(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		_, _ = conn.Write([]byte("220 something else entirely\r\n"))
	})

	dir := t.TempDir()
	writeTemplate(t, dir, "ftp-banner.yaml", ftpBannerTCPTemplate)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)

	findings, err := nuclei.New(newExecutorClient()).WithTCPTimeout(2*time.Second).
		Run(context.Background(), "tcp://"+addr, templates[0])
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestExecutorRun_TCP_DSLDataIdentifierMatches(t *testing.T) {
	addr := newFakeTCPServerTCP(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		_, _ = conn.Write([]byte("hello there\r\n"))
	})

	dir := t.TempDir()
	writeTemplate(t, dir, "dsl-data.yaml", dslDataTCPTemplate)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)

	findings, err := nuclei.New(newExecutorClient()).WithTCPTimeout(2*time.Second).
		Run(context.Background(), "tcp://"+addr, templates[0])
	require.NoError(t, err)
	require.Len(t, findings, 1)
}

// TestExecutorRun_TCP_HTTPOnlyTemplateNeverFiresAgainstTCPTarget confirms
// the protocol gate: an http:-only template loaded against a "tcp://"
// target produces no findings and no error, never attempting to build an
// HTTP request against it.
func TestExecutorRun_TCP_HTTPOnlyTemplateNeverFiresAgainstTCPTarget(t *testing.T) {
	addr := newFakeTCPServerTCP(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		_, _ = conn.Write([]byte("220 ready\r\n"))
	})

	dir := t.TempDir()
	writeTemplate(t, dir, "http-only.yaml", httpOnlyTemplateForTCPGate)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)

	findings, err := nuclei.New(newExecutorClient()).WithTCPTimeout(2*time.Second).
		Run(context.Background(), "tcp://"+addr, templates[0])
	require.NoError(t, err)
	assert.Empty(t, findings)
}

// TestExecutorRun_TCP_TCPOnlyTemplateNeverFiresAgainstHTTPTarget is the
// mirror image: a tcp:-only template loaded against an ordinary http(s)
// target produces no findings and no error either.
func TestExecutorRun_TCP_TCPOnlyTemplateNeverFiresAgainstHTTPTarget(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "redis-detect.yaml", redisDetectTCPTemplate)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)

	findings, err := nuclei.New(newExecutorClient()).
		Run(context.Background(), "https://example.test", templates[0])
	require.NoError(t, err)
	assert.Empty(t, findings)
}

// TestExecutorRun_TCP_HostPlaceholderWithLiteralPortResolves confirms a
// real-corpus-shaped `host: ["{{Hostname}}:<port>"]` entry (a literal
// port, no {{Port}} needed) still dials correctly even though the target
// itself already carries that port.
func TestExecutorRun_TCP_HostPlaceholderWithLiteralPortResolves(t *testing.T) {
	addr := newFakeTCPServerTCP(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		_, _ = conn.Write([]byte("FTP server ready\r\n"))
	})
	_, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)

	tmplText := `
id: ftp-banner-hostfield
info:
  name: FTP Banner
tcp:
  - host:
      - "{{Hostname}}:` + port + `"
    inputs:
      - {}
    matchers:
      - type: word
        words:
          - "FTP server ready"
`
	dir := t.TempDir()
	writeTemplate(t, dir, "ftp-banner-hostfield.yaml", tmplText)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)

	findings, err := nuclei.New(newExecutorClient()).WithTCPTimeout(2*time.Second).
		Run(context.Background(), "tcp://"+addr, templates[0])
	require.NoError(t, err)
	require.Len(t, findings, 1)
}

// TestExecutorRun_TCP_HostPlaceholderNeedingUnsupportedPortVarSkips
// confirms a host: entry needing {{Port}} (a variable this project has no
// source for — see TCPRequest.Host's doc comment) is skipped rather than
// guessed at: no findings, no error.
func TestExecutorRun_TCP_HostPlaceholderNeedingUnsupportedPortVarSkips(t *testing.T) {
	addr := newFakeTCPServerTCP(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		_, _ = conn.Write([]byte("FTP server ready\r\n"))
	})

	tmplText := `
id: ftp-banner-needs-port-var
info:
  name: FTP Banner
tcp:
  - host:
      - "{{Hostname}}:{{Port}}"
    inputs:
      - {}
    matchers:
      - type: word
        words:
          - "FTP server ready"
`
	dir := t.TempDir()
	writeTemplate(t, dir, "ftp-banner-needs-port-var.yaml", tmplText)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)

	findings, err := nuclei.New(newExecutorClient()).WithTCPTimeout(2*time.Second).
		Run(context.Background(), "tcp://"+addr, templates[0])
	require.NoError(t, err)
	assert.Empty(t, findings)
}
