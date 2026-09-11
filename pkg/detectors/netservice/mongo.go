package netservice

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"time"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/template/tcpproto"
)

// mongoOpMsg is OP_MSG's wire-protocol opcode (MongoDB 3.6+) — this check
// is deliberately scoped to it and doesn't fall back to the legacy
// OP_QUERY/OP_REPLY opcodes a pre-3.6 server would need: OP_MSG covers the
// overwhelming majority of currently-deployed real servers, and a
// pre-OP_MSG server simply won't answer this check's request the way
// mongoReadOpMsgDocument expects — a clean non-match, not a special case.
const mongoOpMsg = 2013

// mongoAdminDB is the database every MongoDB administrative command
// (listDatabases included) is issued against.
const mongoAdminDB = "admin"

// mongoMaxMessagePayload mirrors mysqlMaxPacketPayload/pgMaxMessagePayload:
// a memory-exhaustion cap on a single reply, regardless of what its own
// length field claims.
const mongoMaxMessagePayload = 1 << 20

// checkMongoUnauthListDatabases dials addr and sends a single OP_MSG
// "listDatabases" command against the admin database — no authentication
// handshake of any kind, no credential attempted.
//
// listDatabases is deliberately chosen over isMaster/hello: those two
// always succeed with no authentication at all, by design (MongoDB's own
// topology-discovery convention every driver relies on before it has
// authenticated) — a successful reply to either would prove nothing and
// would false-positive on every correctly-secured server. listDatabases
// requires the listDatabases privilege once authorization is enabled, so a
// reply that actually returns ok:1 (real database names, not an error) is
// the genuine "let me in with zero credentials" signal; ok:0 (typically
// carrying code 13, "Unauthorized") means it isn't.
func (d *Detector) checkMongoUnauthListDatabases(ctx context.Context, addr, target string) ([]detectors.Finding, error) {
	timeout := timeoutOrDefault(d.timeout)
	conn, err := tcpproto.Dial(ctx, addr, timeout)
	if err != nil {
		return nil, nil
	}
	defer func() { _ = conn.Close() }()

	cmd := bsonDoc(
		bsonInt32Elem("listDatabases", 1),
		bsonStringElem("$db", mongoAdminDB),
	)
	if err := mongoWriteOpMsg(conn, timeout, cmd); err != nil {
		return nil, nil
	}

	reply, err := mongoReadOpMsgDocument(conn, timeout)
	if err != nil {
		return nil, nil
	}
	fields, err := bsonScanTopLevel(reply, map[string]bool{"ok": true})
	if err != nil {
		return nil, nil
	}
	ok, hasOk := fields["ok"]
	if !hasOk || ok.asFloat64() != 1 {
		return nil, nil // ok:0 (commonly code 13/Unauthorized), or a reply shape this check doesn't recognize
	}

	return []detectors.Finding{{
		ID:          fmt.Sprintf("netservice-mongodb-unauth-listdatabases-%s", sanitizeID(addr)),
		Type:        "misconfig",
		Severity:    "critical",
		Confidence:  "high",
		Target:      target,
		Description: fmt.Sprintf("MongoDB at %s ran listDatabases with no authentication at all (authorization disabled, or a bindIp exposing an internal-trust deployment)", addr),
		Evidence: map[string]string{
			"command": "listDatabases",
		},
	}}, nil
}

// mongoWriteOpMsg frames doc (an already-encoded BSON command document) as
// a single-section OP_MSG request: the standard 16-byte MsgHeader
// (messageLength/requestID/responseTo/opCode, all little-endian — BSON and
// the wire protocol built on it are little-endian throughout, the opposite
// of PostgreSQL's big-endian framing, see pgReadMessage's doc comment) +
// a 4-byte flagBits word (0: no checksum, no more-to-come) + one kind-0x00
// section (the body document itself, no document-sequence sections).
func mongoWriteOpMsg(conn net.Conn, timeout time.Duration, doc []byte) error {
	body := make([]byte, 0, 5+len(doc))
	body = append(body, 0, 0, 0, 0) // flagBits
	body = append(body, 0x00)       // section kind 0: body document
	body = append(body, doc...)

	header := make([]byte, 16)
	binary.LittleEndian.PutUint32(header[0:4], uint32(16+len(body)))
	binary.LittleEndian.PutUint32(header[4:8], 1)  // requestID: arbitrary, non-zero
	binary.LittleEndian.PutUint32(header[8:12], 0) // responseTo: none, this is a request
	binary.LittleEndian.PutUint32(header[12:16], mongoOpMsg)

	if err := conn.SetWriteDeadline(time.Now().Add(timeoutOrDefault(timeout))); err != nil {
		return err
	}
	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err := conn.Write(body)
	return err
}

// mongoReadOpMsgDocument reads one OP_MSG reply and returns its first
// section's BSON document (own length prefix still included, exactly the
// shape bsonScanTopLevel expects) — the only section this check ever needs,
// since a command reply's first section is always the reply document
// itself. Rejects (as a plain error, always treated by the caller as "not
// vulnerable", never surfaced) anything that isn't a well-formed
// single-section OP_MSG reply: a different opcode, an implausible length,
// or a reply too short to carry even an empty section.
func mongoReadOpMsgDocument(conn net.Conn, timeout time.Duration) ([]byte, error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeoutOrDefault(timeout))); err != nil {
		return nil, err
	}
	header := make([]byte, 16)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	messageLength := binary.LittleEndian.Uint32(header[0:4])
	opCode := binary.LittleEndian.Uint32(header[12:16])
	if opCode != mongoOpMsg {
		return nil, fmt.Errorf("mongo: unexpected opcode %d", opCode)
	}
	if messageLength < 21 || int(messageLength) > mongoMaxMessagePayload {
		return nil, fmt.Errorf("mongo: implausible message length (%d bytes)", messageLength)
	}
	rest := make([]byte, messageLength-16)
	if _, err := io.ReadFull(conn, rest); err != nil {
		return nil, err
	}
	// rest = flagBits(4 bytes) + section kind(1 byte) + BSON document.
	kind := rest[4]
	if kind != 0x00 {
		return nil, fmt.Errorf("mongo: unexpected section kind %d", kind)
	}
	return rest[5:], nil
}

// --- a minimal BSON codec, just enough to build a flat command document
// and read back the two top-level scalar fields ("ok", and any future
// caller's own field set) this check needs — not a general-purpose BSON
// library. Encoding covers only the int32/string element types this
// check's own outgoing command uses; decoding (bsonSkipValue) recognizes
// every common top-level reply field type well enough to skip over it
// correctly (a correct byte-length skip is required even for a field this
// check doesn't care about, or the next field's name/value would be
// misread), but only ever returns the value for a field the caller asked
// for. ---

// bsonScalar holds a decoded BSON scalar value tagged by its original wire
// type — bsonSkipValue leaves the zero value here for the compound/opaque
// types this codec correctly skips but doesn't decode a value for.
type bsonScalar struct {
	kind byte
	f64  float64
	i32  int32
	i64  int64
	str  string
}

// asFloat64 normalizes whichever numeric BSON type a real server used for
// "ok" (in practice always a double, but int32/int64 are accepted too) —
// mirrors how a real MongoDB driver treats "ok" as numeric regardless of
// its exact wire type.
func (s bsonScalar) asFloat64() float64 {
	switch s.kind {
	case 0x01:
		return s.f64
	case 0x10:
		return float64(s.i32)
	case 0x12:
		return float64(s.i64)
	default:
		return 0
	}
}

// bsonInt32Elem encodes a BSON int32 element (type 0x10): type byte + a
// null-terminated name + a 4-byte little-endian value.
func bsonInt32Elem(name string, v int32) []byte {
	b := make([]byte, 0, 1+len(name)+1+4)
	b = append(b, 0x10)
	b = append(b, []byte(name)...)
	b = append(b, 0x00)
	val := make([]byte, 4)
	binary.LittleEndian.PutUint32(val, uint32(v))
	return append(b, val...)
}

// bsonStringElem encodes a BSON UTF-8 string element (type 0x02): type
// byte + a null-terminated name + a 4-byte little-endian length (counting
// the value's own trailing null) + the value bytes + that trailing null.
func bsonStringElem(name, v string) []byte {
	b := make([]byte, 0, 1+len(name)+1+4+len(v)+1)
	b = append(b, 0x02)
	b = append(b, []byte(name)...)
	b = append(b, 0x00)
	length := make([]byte, 4)
	binary.LittleEndian.PutUint32(length, uint32(len(v)+1))
	b = append(b, length...)
	b = append(b, []byte(v)...)
	return append(b, 0x00)
}

// bsonDoc wraps one or more already-encoded elements into a complete BSON
// document: a 4-byte little-endian total length (including itself), the
// elements themselves, and one trailing 0x00 terminator.
func bsonDoc(elems ...[]byte) []byte {
	total := 4
	for _, e := range elems {
		total += len(e)
	}
	total++ // terminator
	doc := make([]byte, 0, total)
	length := make([]byte, 4)
	binary.LittleEndian.PutUint32(length, uint32(total))
	doc = append(doc, length...)
	for _, e := range elems {
		doc = append(doc, e...)
	}
	return append(doc, 0x00)
}

// bsonScanTopLevel walks doc's top-level elements only — no recursion into
// embedded documents/arrays, this check never needs a nested field — and
// returns the decoded scalar value of each element named in wanted. A
// wanted field that's absent, or present with a type bsonSkipValue doesn't
// decode a value for, simply isn't in the result; the caller
// (checkMongoUnauthListDatabases) already treats a missing "ok" as "not
// confirmed vulnerable", the correct conservative default.
func bsonScanTopLevel(doc []byte, wanted map[string]bool) (map[string]bsonScalar, error) {
	if len(doc) < 5 {
		return nil, fmt.Errorf("bson: document too short")
	}
	length := binary.LittleEndian.Uint32(doc[:4])
	if length < 5 || int(length) > len(doc) {
		return nil, fmt.Errorf("bson: declared length %d out of range", length)
	}
	body := doc[4:length]
	if body[len(body)-1] != 0x00 {
		return nil, fmt.Errorf("bson: missing document terminator")
	}
	body = body[:len(body)-1]

	out := make(map[string]bsonScalar)
	for len(body) > 0 {
		kind := body[0]
		body = body[1:]
		nameEnd := bytes.IndexByte(body, 0x00)
		if nameEnd < 0 {
			return nil, fmt.Errorf("bson: unterminated element name")
		}
		name := string(body[:nameEnd])
		body = body[nameEnd+1:]

		val, consumed, err := bsonSkipValue(kind, body)
		if err != nil {
			return nil, err
		}
		if wanted[name] {
			out[name] = val
		}
		if consumed > len(body) {
			return nil, fmt.Errorf("bson: element %q overruns document", name)
		}
		body = body[consumed:]
	}
	return out, nil
}

// bsonSkipValue decodes (when it's a scalar type this check cares about)
// or otherwise correctly measures the byte length of one BSON element
// value of the given kind, so the caller can skip to the next element
// regardless of whether this element's own name was one it wanted. Every
// type a real mongod command reply commonly carries (double/string/
// embedded-doc/array/binary/ObjectId/bool/datetime/null/int32/timestamp/
// int64/decimal128) is recognized; anything else is a decode error —
// which bsonScanTopLevel's caller always turns into a clean non-match, per
// this package's "only report what's directly confirmed" convention.
func bsonSkipValue(kind byte, data []byte) (bsonScalar, int, error) {
	switch kind {
	case 0x01: // double
		if len(data) < 8 {
			return bsonScalar{}, 0, fmt.Errorf("bson: truncated double")
		}
		return bsonScalar{kind: kind, f64: math.Float64frombits(binary.LittleEndian.Uint64(data[:8]))}, 8, nil
	case 0x02: // UTF-8 string
		if len(data) < 4 {
			return bsonScalar{}, 0, fmt.Errorf("bson: truncated string length")
		}
		n := int(binary.LittleEndian.Uint32(data[:4]))
		if n < 1 || 4+n > len(data) {
			return bsonScalar{}, 0, fmt.Errorf("bson: truncated string")
		}
		return bsonScalar{kind: kind, str: string(data[4 : 4+n-1])}, 4 + n, nil
	case 0x03, 0x04: // embedded document, array — both length-prefixed the same way
		if len(data) < 4 {
			return bsonScalar{}, 0, fmt.Errorf("bson: truncated embedded doc/array")
		}
		n := int(binary.LittleEndian.Uint32(data[:4]))
		if n < 5 || n > len(data) {
			return bsonScalar{}, 0, fmt.Errorf("bson: truncated embedded doc/array")
		}
		return bsonScalar{}, n, nil
	case 0x05: // binary
		if len(data) < 5 {
			return bsonScalar{}, 0, fmt.Errorf("bson: truncated binary")
		}
		n := int(binary.LittleEndian.Uint32(data[:4]))
		if 5+n > len(data) {
			return bsonScalar{}, 0, fmt.Errorf("bson: truncated binary")
		}
		return bsonScalar{}, 5 + n, nil
	case 0x07: // ObjectId
		if len(data) < 12 {
			return bsonScalar{}, 0, fmt.Errorf("bson: truncated objectid")
		}
		return bsonScalar{}, 12, nil
	case 0x08: // boolean
		if len(data) < 1 {
			return bsonScalar{}, 0, fmt.Errorf("bson: truncated bool")
		}
		return bsonScalar{}, 1, nil
	case 0x09, 0x11: // UTC datetime, timestamp — both a fixed 8 bytes
		if len(data) < 8 {
			return bsonScalar{}, 0, fmt.Errorf("bson: truncated 8-byte value")
		}
		return bsonScalar{}, 8, nil
	case 0x0A: // null — no value bytes at all
		return bsonScalar{}, 0, nil
	case 0x10: // int32
		if len(data) < 4 {
			return bsonScalar{}, 0, fmt.Errorf("bson: truncated int32")
		}
		return bsonScalar{kind: kind, i32: int32(binary.LittleEndian.Uint32(data[:4]))}, 4, nil
	case 0x12: // int64
		if len(data) < 8 {
			return bsonScalar{}, 0, fmt.Errorf("bson: truncated int64")
		}
		return bsonScalar{kind: kind, i64: int64(binary.LittleEndian.Uint64(data[:8]))}, 8, nil
	case 0x13: // decimal128
		if len(data) < 16 {
			return bsonScalar{}, 0, fmt.Errorf("bson: truncated decimal128")
		}
		return bsonScalar{}, 16, nil
	default:
		return bsonScalar{}, 0, fmt.Errorf("bson: unsupported element type 0x%02x", kind)
	}
}
