package netservice

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// readFakePGStartupMessage consumes (and discards) one client StartupMessage
// on the fake-server side of a test — NOT pgReadMessage, which parses a
// *backend* message's 1-byte-type+4-byte-length framing; the client's
// StartupMessage carries no type byte at all, just its own 4-byte
// big-endian total-length prefix (see buildPGStartupMessage's doc comment).
func readFakePGStartupMessage(conn net.Conn) error {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	length := binary.BigEndian.Uint32(header)
	rest := make([]byte, length-4)
	_, err := io.ReadFull(conn, rest)
	return err
}

// fakePGMessage frames payload the same way a real backend does: 1-byte
// type + 4-byte big-endian length (including the length field itself).
func fakePGMessage(msgType byte, payload []byte) []byte {
	msg := make([]byte, 1+4+len(payload))
	msg[0] = msgType
	binary.BigEndian.PutUint32(msg[1:5], uint32(4+len(payload)))
	copy(msg[5:], payload)
	return msg
}

// fakePGAuthenticationOk builds the exact 4-byte-authType payload
// checkPostgresTrustAuth looks for.
func fakePGAuthenticationOk() []byte {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, 0) // AuthenticationOk
	return fakePGMessage(pgMsgAuthentication, payload)
}

func fakePGAuthenticationCleartextPassword() []byte {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, 3) // AuthenticationCleartextPassword
	return fakePGMessage(pgMsgAuthentication, payload)
}

func TestCheckPostgresTrustAuth_Vulnerable(t *testing.T) {
	addr := newFakeListener(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		if err := readFakePGStartupMessage(conn); err != nil {
			return
		}
		_ = pgWriteRaw(conn, 2*time.Second, fakePGAuthenticationOk())
	})

	d := New(WithTimeout(2 * time.Second))
	findings, err := d.checkPostgresTrustAuth(context.Background(), addr, "tcp://"+addr)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "critical", findings[0].Severity)
	assert.Equal(t, pgProbeUser, findings[0].Evidence["probe_user"])
}

func TestCheckPostgresTrustAuth_NotVulnerable_PasswordRequested(t *testing.T) {
	addr := newFakeListener(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		if err := readFakePGStartupMessage(conn); err != nil {
			return
		}
		_ = pgWriteRaw(conn, 2*time.Second, fakePGAuthenticationCleartextPassword())
	})

	d := New(WithTimeout(2 * time.Second))
	findings, err := d.checkPostgresTrustAuth(context.Background(), addr, "tcp://"+addr)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestCheckPostgresTrustAuth_NotVulnerable_ErrorResponse(t *testing.T) {
	addr := newFakeListener(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		if err := readFakePGStartupMessage(conn); err != nil {
			return
		}
		// e.g. "FATAL: SSL/TLS required" — an ErrorResponse instead of an
		// AuthenticationRequest.
		_ = pgWriteRaw(conn, 2*time.Second, fakePGMessage(pgMsgErrorResponse, []byte("SFATAL\x00")))
	})

	d := New(WithTimeout(2 * time.Second))
	findings, err := d.checkPostgresTrustAuth(context.Background(), addr, "tcp://"+addr)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestCheckPostgresTrustAuth_NotPostgresProtocol(t *testing.T) {
	addr := newFakeListener(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		_, _ = conn.Write([]byte("not postgres at all"))
	})

	d := New(WithTimeout(2 * time.Second))
	findings, err := d.checkPostgresTrustAuth(context.Background(), addr, "tcp://"+addr)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestBuildPGStartupMessage_RoundTrip(t *testing.T) {
	addr := newFakeListener(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		if err := readFakePGStartupMessage(conn); err != nil {
			return
		}
		_ = pgWriteRaw(conn, 2*time.Second, fakePGAuthenticationOk())
	})

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	msg := buildPGStartupMessage("alice", "mydb")
	require.NoError(t, pgWriteRaw(conn, 2*time.Second, msg))
	// buildPGStartupMessage's own length prefix must equal the message's
	// real total length (this is the field the fake server above trusts).
	assert.Equal(t, len(msg), int(binary.BigEndian.Uint32(msg[:4])))
	assert.Contains(t, string(msg), "alice")
	assert.Contains(t, string(msg), "mydb")
}
