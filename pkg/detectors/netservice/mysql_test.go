package netservice

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeMySQLHandshake builds a minimal, well-formed HandshakeV10 payload —
// enough for checkMySQLEmptyPassword to recognize it as MySQL (leading
// 0x0a) and extract a version string; every other field is a fixed
// placeholder, since the check under test never uses the auth-plugin-
// data/capability fields at all (empty-password login needs no
// scrambling — see checkMySQLEmptyPassword's doc comment).
func fakeMySQLHandshake(version string) []byte {
	var b []byte
	b = append(b, 0x0a)
	b = append(b, []byte(version)...)
	b = append(b, 0x00)
	b = append(b, 0, 0, 0, 1)                 // connection id
	b = append(b, []byte("AAAAAAAA")...)      // auth-plugin-data-part-1 (8 bytes)
	b = append(b, 0x00)                       // filler
	b = append(b, 0xff, 0xf7)                 // capability_flags_1
	b = append(b, 0x21)                       // charset
	b = append(b, 0x02, 0x00)                 // status flags
	b = append(b, 0x00, 0x00)                 // capability_flags_2
	b = append(b, 0x00)                       // auth-plugin-data length
	b = append(b, make([]byte, 10)...)        // reserved
	b = append(b, []byte("BBBBBBBBBBBBB")...) // auth-plugin-data-part-2 (13 bytes)
	return b
}

func TestCheckMySQLEmptyPassword_Vulnerable(t *testing.T) {
	addr := newFakeListener(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		if err := mysqlWritePacket(conn, 2*time.Second, 0, fakeMySQLHandshake("8.0.28-fake")); err != nil {
			return
		}
		if _, _, err := mysqlReadPacket(conn, 2*time.Second); err != nil {
			return
		}
		_ = mysqlWritePacket(conn, 2*time.Second, 2, []byte{0x00}) // OK packet
	})

	d := New(WithTimeout(2 * time.Second))
	findings, err := d.checkMySQLEmptyPassword(context.Background(), addr, "tcp://"+addr)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "critical", findings[0].Severity)
	assert.Contains(t, findings[0].Evidence["server_version"], "8.0.28-fake")
}

func TestCheckMySQLEmptyPassword_NotVulnerable(t *testing.T) {
	addr := newFakeListener(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		if err := mysqlWritePacket(conn, 2*time.Second, 0, fakeMySQLHandshake("8.0.28-fake")); err != nil {
			return
		}
		if _, _, err := mysqlReadPacket(conn, 2*time.Second); err != nil {
			return
		}
		_ = mysqlWritePacket(conn, 2*time.Second, 2, []byte{0xff, 0x15, 0x04, '#', '2', '8', '0', '0', '0'}) // ERR packet
	})

	d := New(WithTimeout(2 * time.Second))
	findings, err := d.checkMySQLEmptyPassword(context.Background(), addr, "tcp://"+addr)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestCheckMySQLEmptyPassword_AuthSwitchRequestNotVulnerable(t *testing.T) {
	addr := newFakeListener(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		if err := mysqlWritePacket(conn, 2*time.Second, 0, fakeMySQLHandshake("8.0.28-fake")); err != nil {
			return
		}
		if _, _, err := mysqlReadPacket(conn, 2*time.Second); err != nil {
			return
		}
		_ = mysqlWritePacket(conn, 2*time.Second, 2, []byte{0xfe, 'c', 'a', 'c', 'h', 'i', 'n', 'g'}) // AuthSwitchRequest
	})

	d := New(WithTimeout(2 * time.Second))
	findings, err := d.checkMySQLEmptyPassword(context.Background(), addr, "tcp://"+addr)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestCheckMySQLEmptyPassword_NotMySQLProtocol(t *testing.T) {
	addr := newFakeListener(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		_, _ = conn.Write([]byte("220 not mysql at all\r\n"))
	})

	d := New(WithTimeout(2 * time.Second))
	findings, err := d.checkMySQLEmptyPassword(context.Background(), addr, "tcp://"+addr)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestMySQLPacketRoundTrip(t *testing.T) {
	addr := newFakeListener(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		seq, payload, err := mysqlReadPacket(conn, 2*time.Second)
		if err != nil || seq != 5 || string(payload) != "hello" {
			return
		}
		_ = mysqlWritePacket(conn, 2*time.Second, 6, []byte("world"))
	})

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	require.NoError(t, mysqlWritePacket(conn, 2*time.Second, 5, []byte("hello")))
	seq, payload, err := mysqlReadPacket(conn, 2*time.Second)
	require.NoError(t, err)
	assert.Equal(t, byte(6), seq)
	assert.Equal(t, []byte("world"), payload)
}
