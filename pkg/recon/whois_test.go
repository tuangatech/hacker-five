package recon

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseWHOISRefer(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"no refer line", "domain: example.com\nstatus: active\n", ""},
		{"lowercase refer", "refer:  whois.verisign-grs.com\n", "whois.verisign-grs.com"},
		{"uppercase field name", "REFER: whois.example-registry.net\n", "whois.example-registry.net"},
		{"refer line among others", "domain: com\norganisation: IANA\nrefer: whois.verisign-grs.com\nwhois: whois.verisign-grs.com\n", "whois.verisign-grs.com"},
		{"empty input", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, parseWHOISRefer(tt.raw))
		})
	}
}

// startFakeWHOISServer spins up a local, no-real-network TCP listener that
// speaks just enough of RFC 3912 (read one query line, write a canned
// response, close) for whoisQuery to exercise its real dial/write/read path
// without ever touching whois.iana.org.
func startFakeWHOISServer(t *testing.T, response string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf) // the query line; content unused by this fake server
		_, _ = conn.Write([]byte(response))
	}()
	return ln.Addr().String()
}

func TestWhoisQuery_ReturnsServerResponse(t *testing.T) {
	addr := startFakeWHOISServer(t, "domain: example.com\nstatus: active\n")

	got, err := whoisQuery(context.Background(), addr, "example.com")
	require.NoError(t, err)
	assert.Equal(t, "domain: example.com\nstatus: active\n", got)
}

func TestWhoisQuery_UnreachableAddress_ReturnsError(t *testing.T) {
	// Port 0 on a resolved loopback address is never listening — connection
	// refused immediately, no real network hop.
	_, err := whoisQuery(context.Background(), "127.0.0.1:1", "example.com")
	assert.Error(t, err)
}

func TestLookupWHOIS_CanceledContext_ReturnsError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := lookupWHOIS(ctx, "example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "whois query")
}

func TestLookupASN_InvalidIPv4_ReturnsError(t *testing.T) {
	_, _, _, err := lookupASN(context.Background(), "not-an-ip")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a valid IPv4")
}

func TestLookupASN_IPv6_ReturnsError(t *testing.T) {
	_, _, _, err := lookupASN(context.Background(), "::1")
	require.Error(t, err)
}

func TestLookupASN_CanceledContext_ReturnsError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, _, err := lookupASN(ctx, "8.8.8.8")
	assert.Error(t, err)
}

func TestFirstIPv4_Localhost_ResolvesToLoopback(t *testing.T) {
	ip, err := firstIPv4(context.Background(), "localhost")
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", ip)
}

func TestFirstIPv4_CanceledContext_ReturnsError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := firstIPv4(ctx, "example.com")
	assert.Error(t, err)
}
