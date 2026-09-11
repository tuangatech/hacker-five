package netservice

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/template/tcpproto"
)

// ftpAnonymousUser/ftpAnonymousPass are the standard, universally-documented
// anonymous-FTP credential pair (RFC 1635) — not a guessed password, the
// same "well-known, intentionally public convention" class of check as an
// empty-password attempt. Sending an email-shaped password (rather than a
// literal blank) matches real anonymous-FTP client convention and several
// servers' own stricter PASS validation.
const (
	ftpAnonymousUser = "anonymous"
	ftpAnonymousPass = "anonymous@example.com"
)

// checkFTPAnonymous dials addr, performs the standard anonymous-FTP login
// sequence (USER anonymous / PASS <email-shaped>), and reports a Finding
// only if the server's final reply is a genuine 230 ("User logged in") —
// every other reply (530 access denied, 421 service unavailable, a
// malformed/short response) is a clean non-match, not an error.
func (d *Detector) checkFTPAnonymous(ctx context.Context, addr, target string) ([]detectors.Finding, error) {
	timeout := timeoutOrDefault(d.timeout)
	conn, err := tcpproto.Dial(ctx, addr, timeout)
	if err != nil {
		return nil, nil
	}
	defer func() { _ = conn.Close() }()

	greeting, err := tcpproto.Read(conn, 0, timeout)
	if err != nil || !ftpReplyStartsWith(greeting, "220") {
		return nil, nil // no banner, or not an FTP greeting at all
	}

	userReply, err := ftpCommand(conn, timeout, "USER "+ftpAnonymousUser)
	if err != nil || !ftpReplyStartsWith(userReply, "331") {
		return nil, nil // server didn't ask for a password the way a real anonymous-capable server does
	}

	passReply, err := ftpCommand(conn, timeout, "PASS "+ftpAnonymousPass)
	if err != nil || !ftpReplyStartsWith(passReply, "230") {
		return nil, nil // login rejected — not anonymous-accessible
	}

	return []detectors.Finding{{
		ID:          fmt.Sprintf("netservice-ftp-anonymous-%s", sanitizeID(addr)),
		Type:        "misconfig",
		Severity:    "medium",
		Confidence:  "high",
		Target:      target,
		Description: fmt.Sprintf("anonymous FTP login succeeded against %s (USER anonymous / PASS %s accepted)", addr, ftpAnonymousPass),
		Evidence: map[string]string{
			"greeting":   string(greeting),
			"user_reply": string(userReply),
			"pass_reply": string(passReply),
		},
	}}, nil
}

// ftpCommand sends cmd+"\r\n" and reads the single reply that follows —
// good enough for FTP's simple one-command-one-reply control-channel
// convention (RFC 959); a real server occasionally sends a multi-line
// reply (a "150-" continuation), which ftpReplyStartsWith's three-digit
// prefix check still recognizes correctly since the leading reply code is
// always the first thing on the wire either way.
func ftpCommand(conn net.Conn, timeout time.Duration, cmd string) ([]byte, error) {
	if _, err := tcpproto.Write(conn, []byte(cmd+"\r\n"), timeout); err != nil {
		return nil, err
	}
	return tcpproto.Read(conn, 0, timeout)
}

func ftpReplyStartsWith(reply []byte, code string) bool {
	return len(reply) >= len(code) && string(reply[:len(code)]) == code
}
