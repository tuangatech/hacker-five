package netservice

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/template/tcpproto"
)

// pgProbeUser/pgProbeDatabase are the standard PostgreSQL default
// superuser/database names (initdb's own convention) — the same
// "well-known default account" class of probe as mysqlProbeUser, not a
// guessed credential.
const (
	pgProbeUser     = "postgres"
	pgProbeDatabase = "postgres"
)

// pgAuthenticationOk / pgErrorResponse are the two PostgreSQL backend
// message types this check distinguishes; every other message type (an
// AuthenticationCleartextPassword/MD5Password/SASL request, or anything
// else) means "this server demanded a credential exchange this check
// doesn't attempt" — a clean non-match, not a partial success.
const (
	pgMsgAuthentication = 'R'
	pgMsgErrorResponse  = 'E'
)

// pgAuthTypeOk is AuthenticationRequest's own auth-type code for
// AuthenticationOk — sent by the server immediately, with no password
// challenge at all, only under "trust" (or unauthenticated "peer" over a
// TCP socket, which the server itself would normally refuse) host-based
// authentication in pg_hba.conf. This is the exact "did it let me in with
// no credential" signal, independent of whether the requested pgProbeDatabase
// actually exists — a real server that grants AuthenticationOk on startup
// has already answered the only question this check asks.
const pgAuthTypeOk = 0

// pgMaxMessagePayload mirrors mysqlMaxPacketPayload's role: a generous
// memory-exhaustion cap on a single backend message, regardless of what its
// length field claims — a real Authentication/ErrorResponse message here is
// at most a few hundred bytes.
const pgMaxMessagePayload = 1 << 20

// checkPostgresTrustAuth dials addr, sends a StartupMessage for
// pgProbeUser/pgProbeDatabase (protocol version 3.0, no SSL negotiation
// attempted first — a server requiring SSL is a documented non-match below,
// not chased with a second connection), and reports a Finding only when the
// server's very first reply is AuthenticationOk: it let this check begin a
// session with no password exchange whatsoever. Never sends a query — the
// connection is closed the moment the authentication outcome is known.
func (d *Detector) checkPostgresTrustAuth(ctx context.Context, addr, target string) ([]detectors.Finding, error) {
	timeout := timeoutOrDefault(d.timeout)
	conn, err := tcpproto.Dial(ctx, addr, timeout)
	if err != nil {
		return nil, nil
	}
	defer func() { _ = conn.Close() }()

	startup := buildPGStartupMessage(pgProbeUser, pgProbeDatabase)
	if err := pgWriteRaw(conn, timeout, startup); err != nil {
		return nil, nil
	}

	msgType, payload, err := pgReadMessage(conn, timeout)
	if err != nil {
		return nil, nil
	}
	switch msgType {
	case pgMsgAuthentication:
		// fall through to the auth-type check below
	case pgMsgErrorResponse:
		return nil, nil // e.g. SSL required, protocol rejected, role doesn't exist — not vulnerable
	default:
		return nil, nil // not a PostgreSQL server, or a message shape this minimal check doesn't recognize
	}
	if len(payload) < 4 {
		return nil, nil
	}
	authType := binary.BigEndian.Uint32(payload[:4])
	if authType != pgAuthTypeOk {
		return nil, nil // a real credential exchange was demanded (cleartext/MD5/SASL/...) — not vulnerable
	}

	return []detectors.Finding{{
		ID:          fmt.Sprintf("netservice-postgres-trust-auth-%s", sanitizeID(addr)),
		Type:        "misconfig",
		Severity:    "critical",
		Confidence:  "high",
		Target:      target,
		Description: fmt.Sprintf("PostgreSQL at %s accepted a startup for user %q with no password at all (trust/peer authentication, or pg_hba.conf misconfigured for this remote address)", addr, pgProbeUser),
		Evidence: map[string]string{
			"probe_user":     pgProbeUser,
			"probe_database": pgProbeDatabase,
		},
	}}, nil
}

// buildPGStartupMessage encodes the client-to-server StartupMessage: a
// 4-byte length-of-message-including-itself prefix (PostgreSQL's own
// framing convention, distinct from pgReadMessage's server-message framing
// which carries a leading type byte the StartupMessage does not), the
// protocol-version word 3.0, then the "user"/"database" parameter pairs as
// null-terminated strings, ending in one extra 0x00 terminator byte.
func buildPGStartupMessage(user, database string) []byte {
	body := make([]byte, 0, 64)
	body = append(body, 0x00, 0x03, 0x00, 0x00) // protocol version 3.0
	body = append(body, []byte("user")...)
	body = append(body, 0x00)
	body = append(body, []byte(user)...)
	body = append(body, 0x00)
	body = append(body, []byte("database")...)
	body = append(body, 0x00)
	body = append(body, []byte(database)...)
	body = append(body, 0x00)
	body = append(body, 0x00) // final terminator

	msg := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(msg[:4], uint32(len(msg)))
	copy(msg[4:], body)
	return msg
}

// pgWriteRaw sends data under a write deadline — same shape as
// mysqlWritePacket, but PostgreSQL's StartupMessage carries no separate
// sequence-number header, so this is a plain deadline-then-write.
func pgWriteRaw(conn net.Conn, timeout time.Duration, data []byte) error {
	if err := conn.SetWriteDeadline(time.Now().Add(timeoutOrDefault(timeout))); err != nil {
		return err
	}
	_, err := conn.Write(data)
	return err
}

// pgReadMessage reads one PostgreSQL backend message: a 1-byte type +
// 4-byte big-endian length (counting the length field itself, but not the
// type byte), then exactly length-4 payload bytes. PostgreSQL's wire
// protocol is big-endian throughout, unlike MySQL's little-endian framing
// (mysqlReadPacket) — a real, documented difference between the two
// protocols, not an inconsistency in this codebase.
func pgReadMessage(conn net.Conn, timeout time.Duration) (msgType byte, payload []byte, err error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeoutOrDefault(timeout))); err != nil {
		return 0, nil, err
	}
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint32(header[1:5])
	if length < 4 || int(length)-4 > pgMaxMessagePayload {
		return 0, nil, fmt.Errorf("postgres: implausible message length (%d bytes)", length)
	}
	payload = make([]byte, length-4)
	if len(payload) > 0 {
		if _, err := io.ReadFull(conn, payload); err != nil {
			return 0, nil, err
		}
	}
	return header[0], payload, nil
}
