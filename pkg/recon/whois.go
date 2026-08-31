package recon

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// whoisDialTimeout bounds each of lookupWHOIS's up-to-two TCP connections.
// The raw WHOIS protocol (RFC 3912) has no request framing beyond "send a
// query line, read until the peer closes the connection" — there is no way
// to cancel a stalled read via ctx once it's in flight, so this fixed
// per-dial timeout is the real bound, not full context-cancellation
// support. Documented here rather than silently assumed.
const whoisDialTimeout = 8 * time.Second

// ianaWHOISServer is WHOIS's own bootstrap root: querying it for any domain
// returns a "refer:" line naming the registry-specific server that actually
// holds the record (e.g. whois.verisign-grs.com for .com).
const ianaWHOISServer = "whois.iana.org:43"

// lookupWHOIS queries the real WHOIS protocol for domain: one query against
// IANA's bootstrap server, followed by one referral query if IANA's
// response names a more specific server — doc91's own call for "no
// dominant Go-native CLI, first-party stdlib-only client" (§Dependencies).
// Returns the referral response's raw text if a referral was followed,
// otherwise IANA's own response.
func lookupWHOIS(ctx context.Context, domain string) (string, error) {
	raw, err := whoisQuery(ctx, ianaWHOISServer, domain)
	if err != nil {
		return "", fmt.Errorf("recon: whois query to %s: %w", ianaWHOISServer, err)
	}
	if referTo := parseWHOISRefer(raw); referTo != "" {
		referred, err := whoisQuery(ctx, referTo+":43", domain)
		if err == nil {
			return referred, nil
		}
		// A broken/unreachable referral shouldn't discard IANA's own
		// response — that's still real, if less specific, data.
	}
	return raw, nil
}

func whoisQuery(ctx context.Context, serverAddr, query string) (string, error) {
	dialer := net.Dialer{Timeout: whoisDialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(whoisDialTimeout))

	if _, err := conn.Write([]byte(query + "\r\n")); err != nil {
		return "", err
	}
	var sb strings.Builder
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		sb.WriteString(scanner.Text())
		sb.WriteByte('\n')
	}
	return sb.String(), nil
}

// parseWHOISRefer extracts a "refer:"-prefixed line's server name, per
// IANA's own WHOIS referral convention (case-insensitive field name).
func parseWHOISRefer(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "refer:") {
			return strings.TrimSpace(line[len("refer:"):])
		}
	}
	return ""
}

// lookupASN resolves ip's Autonomous System via Team Cymru's DNS-based
// WHOIS service (a plain TXT lookup against <reversed-ip>.origin.asn.cymru.com)
// — genuinely stdlib-only (net.LookupTXT, the system resolver), doc91's
// other named exception to "shell out to a dominant Go-native CLI."
// Returns asn, the announced prefix, and the country code from the first
// TXT record, formatted as "ASN | prefix | CC | registry | allocated".
func lookupASN(ctx context.Context, ip string) (asn, prefix, country string, err error) {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return "", "", "", fmt.Errorf("recon: %q is not a valid IPv4 address", ip)
	}
	octets := parsed.To4()
	reversed := fmt.Sprintf("%d.%d.%d.%d", octets[3], octets[2], octets[1], octets[0])
	query := reversed + ".origin.asn.cymru.com"

	resolver := net.DefaultResolver
	txts, err := resolver.LookupTXT(ctx, query)
	if err != nil {
		return "", "", "", fmt.Errorf("recon: asn lookup for %s: %w", ip, err)
	}
	if len(txts) == 0 {
		return "", "", "", fmt.Errorf("recon: no asn record for %s", ip)
	}
	fields := strings.Split(txts[0], "|")
	for i := range fields {
		fields[i] = strings.TrimSpace(fields[i])
	}
	if len(fields) < 3 {
		return "", "", "", fmt.Errorf("recon: unexpected asn TXT record shape: %q", txts[0])
	}
	return fields[0], fields[1], fields[2], nil
}

// firstIPv4 resolves host's first IPv4 address, used to feed lookupASN.
func firstIPv4(ctx context.Context, host string) (string, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", err
	}
	for _, a := range addrs {
		if v4 := a.IP.To4(); v4 != nil {
			return v4.String(), nil
		}
	}
	return "", fmt.Errorf("recon: no IPv4 address found for %s", host)
}
