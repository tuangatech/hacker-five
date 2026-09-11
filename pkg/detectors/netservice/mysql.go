package netservice

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/template/tcpproto"
)

// mysqlProbeUser is the single account name this check tries — MySQL's
// universal default administrative account. This is deliberately not a
// credential list or brute-force attempt: with an empty password, MySQL's
// wire protocol needs no guessed/scrambled value at all (see
// checkMySQLEmptyPassword's doc comment) — root-with-no-password is a
// specific, well-known misconfiguration class this checks for once, not a
// dictionary attack against arbitrary accounts.
const mysqlProbeUser = "root"

// mysqlMaxPacketPayload caps how large a single packet payload this check
// will ever allocate for, regardless of what a length header claims — a
// real handshake/OK/ERR packet this check reads is at most a few hundred
// bytes; capped generously at 1 MiB purely as a memory-exhaustion guard
// against a malicious or broken listener claiming an enormous length.
const mysqlMaxPacketPayload = 1 << 20

// MySQL client capability flags this check declares in its
// HandshakeResponse41 — the minimum a virtually universal-support subset:
// CLIENT_LONG_PASSWORD | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION.
// Deliberately does NOT set CLIENT_PLUGIN_AUTH or CLIENT_CONNECT_WITH_DB —
// this check selects no database and lets the server keep using whichever
// auth plugin its own initial handshake already declared, so the response
// packet needs no plugin-name/database fields at all.
const mysqlClientCapabilities = 0x00000001 | 0x00000200 | 0x00008000

// checkMySQLEmptyPassword dials addr, reads the server's initial
// HandshakeV10 packet, and sends a HandshakeResponse41 for mysqlProbeUser
// with a zero-length auth response — MySQL's wire protocol represents "the
// client is attempting to log in with an empty password" as literally an
// empty auth-response field, needing no scrambling/hashing of any kind
// (scrambling only ever applies to a non-empty password). A server whose
// reply to that is an OK packet has just let this check log in with no
// password at all; an ERR (or AuthSwitchRequest this check doesn't chase
// further — see the inline comment below) means it didn't.
func (d *Detector) checkMySQLEmptyPassword(ctx context.Context, addr, target string) ([]detectors.Finding, error) {
	timeout := timeoutOrDefault(d.timeout)
	conn, err := tcpproto.Dial(ctx, addr, timeout)
	if err != nil {
		return nil, nil
	}
	defer func() { _ = conn.Close() }()

	_, handshake, err := mysqlReadPacket(conn, timeout)
	if err != nil || len(handshake) == 0 || handshake[0] != 0x0a {
		return nil, nil // not a MySQL protocol-10 handshake — wrong service, or one this check doesn't understand
	}
	serverVersion := mysqlServerVersion(handshake)

	response := buildMySQLHandshakeResponse(mysqlProbeUser)
	if err := mysqlWritePacket(conn, timeout, 1, response); err != nil {
		return nil, nil
	}

	_, reply, err := mysqlReadPacket(conn, timeout)
	if err != nil || len(reply) == 0 {
		return nil, nil
	}
	switch reply[0] {
	case 0x00:
		// OK packet — login succeeded with no password.
	default:
		// 0xff (ERR — access denied) or 0xfe (AuthSwitchRequest — server
		// insists on a different plugin exchange this minimal check
		// doesn't implement) or anything else: not a confirmed
		// no-password login. Deliberately not treated as vulnerable —
		// this check only reports what it directly confirmed.
		return nil, nil
	}

	return []detectors.Finding{{
		ID:          fmt.Sprintf("netservice-mysql-empty-password-%s", sanitizeID(addr)),
		Type:        "misconfig",
		Severity:    "critical",
		Confidence:  "high",
		Target:      target,
		Description: fmt.Sprintf("MySQL at %s (%s) accepted a login for %q with an empty password", addr, serverVersion, mysqlProbeUser),
		Evidence: map[string]string{
			"server_version": serverVersion,
			"probe_user":     mysqlProbeUser,
		},
	}}, nil
}

// mysqlServerVersion extracts HandshakeV10's null-terminated server-version
// string (starts right after the 1-byte protocol-version field) — evidence
// only, never used to decide anything.
func mysqlServerVersion(handshake []byte) string {
	rest := handshake[1:]
	if i := bytes.IndexByte(rest, 0x00); i >= 0 {
		return string(rest[:i])
	}
	return ""
}

// buildMySQLHandshakeResponse builds a minimal HandshakeResponse41 payload
// for user with a zero-length auth response (empty-password attempt) and
// no database/plugin-name fields (see mysqlClientCapabilities' doc
// comment for why those are safe to omit).
func buildMySQLHandshakeResponse(user string) []byte {
	var b bytes.Buffer
	writeUint32LE(&b, mysqlClientCapabilities)
	writeUint32LE(&b, 1<<24)  // max_packet_size: 16 MiB, an arbitrary generous client-side cap
	b.WriteByte(0x21)         // charset: utf8_general_ci
	b.Write(make([]byte, 23)) // reserved
	b.WriteString(user)
	b.WriteByte(0x00) // null-terminate username
	b.WriteByte(0x00) // auth-response length: 0 (CLIENT_SECURE_CONNECTION length-encoded-as-single-byte form)
	return b.Bytes()
}

func writeUint32LE(b *bytes.Buffer, v uint32) {
	b.WriteByte(byte(v))
	b.WriteByte(byte(v >> 8))
	b.WriteByte(byte(v >> 16))
	b.WriteByte(byte(v >> 24))
}

// mysqlReadPacket reads one MySQL protocol packet: a 3-byte little-endian
// payload length + 1-byte sequence number header, then exactly that many
// payload bytes. Uses io.ReadFull (not tcpproto.Read's single-syscall,
// partial-read-is-fine semantics) because a structured binary protocol
// needs its exact byte counts, unlike a banner grab.
func mysqlReadPacket(conn net.Conn, timeout time.Duration) (seq byte, payload []byte, err error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeoutOrDefault(timeout))); err != nil {
		return 0, nil, err
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, nil, err
	}
	length := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if length > mysqlMaxPacketPayload {
		return 0, nil, fmt.Errorf("mysql: packet too large (%d bytes)", length)
	}
	payload = make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(conn, payload); err != nil {
			return 0, nil, err
		}
	}
	return header[3], payload, nil
}

// mysqlWritePacket frames payload with the same 3-byte-length+1-byte-
// sequence header mysqlReadPacket parses and writes it in one call.
func mysqlWritePacket(conn net.Conn, timeout time.Duration, seq byte, payload []byte) error {
	if err := conn.SetWriteDeadline(time.Now().Add(timeoutOrDefault(timeout))); err != nil {
		return err
	}
	header := []byte{byte(len(payload)), byte(len(payload) >> 8), byte(len(payload) >> 16), seq}
	if _, err := conn.Write(header); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := conn.Write(payload)
	return err
}
