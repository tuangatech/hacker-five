package netservice

import (
	"context"
	"encoding/binary"
	"io"
	"math"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeMongoOpMsgReply frames a BSON reply document as a single-section
// OP_MSG server reply — the exact shape mongoReadOpMsgDocument parses.
func fakeMongoOpMsgReply(doc []byte) []byte {
	body := make([]byte, 0, 5+len(doc))
	body = append(body, 0, 0, 0, 0) // flagBits
	body = append(body, 0x00)       // section kind 0
	body = append(body, doc...)

	header := make([]byte, 16)
	binary.LittleEndian.PutUint32(header[0:4], uint32(16+len(body)))
	binary.LittleEndian.PutUint32(header[4:8], 2)
	binary.LittleEndian.PutUint32(header[8:12], 1)
	binary.LittleEndian.PutUint32(header[12:16], mongoOpMsg)
	return append(header, body...)
}

func fakeMongoOkDoubleReply() []byte {
	doc := bsonDoc(bsonDoubleElem("ok", 1.0))
	return fakeMongoOpMsgReply(doc)
}

func fakeMongoUnauthorizedReply() []byte {
	doc := bsonDoc(
		bsonDoubleElem("ok", 0.0),
		bsonInt32Elem("code", 13),
		bsonStringElem("errmsg", "command listDatabases requires authentication"),
	)
	return fakeMongoOpMsgReply(doc)
}

// bsonDoubleElem is a test-only helper — real MongoDB replies always
// encode "ok" as a double, so the check's own outgoing command (int32/
// string only) never needed an encoder for it, but a realistic fake server
// reply does.
func bsonDoubleElem(name string, v float64) []byte {
	b := make([]byte, 0, 1+len(name)+1+8)
	b = append(b, 0x01)
	b = append(b, []byte(name)...)
	b = append(b, 0x00)
	val := make([]byte, 8)
	binary.LittleEndian.PutUint64(val, math.Float64bits(v))
	return append(b, val...)
}

func TestCheckMongoUnauthListDatabases_Vulnerable(t *testing.T) {
	addr := newFakeListener(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		header := make([]byte, 16)
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}
		length := binary.LittleEndian.Uint32(header[:4])
		rest := make([]byte, length-16)
		if _, err := io.ReadFull(conn, rest); err != nil {
			return
		}
		_, _ = conn.Write(fakeMongoOkDoubleReply())
	})

	d := New(WithTimeout(2 * time.Second))
	findings, err := d.checkMongoUnauthListDatabases(context.Background(), addr, "tcp://"+addr)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "critical", findings[0].Severity)
	assert.Equal(t, "listDatabases", findings[0].Evidence["command"])
}

func TestCheckMongoUnauthListDatabases_NotVulnerable_Unauthorized(t *testing.T) {
	addr := newFakeListener(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		header := make([]byte, 16)
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}
		length := binary.LittleEndian.Uint32(header[:4])
		rest := make([]byte, length-16)
		if _, err := io.ReadFull(conn, rest); err != nil {
			return
		}
		_, _ = conn.Write(fakeMongoUnauthorizedReply())
	})

	d := New(WithTimeout(2 * time.Second))
	findings, err := d.checkMongoUnauthListDatabases(context.Background(), addr, "tcp://"+addr)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestCheckMongoUnauthListDatabases_NotMongoProtocol(t *testing.T) {
	addr := newFakeListener(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		_, _ = conn.Write([]byte("not mongo at all, no valid header"))
	})

	d := New(WithTimeout(2 * time.Second))
	findings, err := d.checkMongoUnauthListDatabases(context.Background(), addr, "tcp://"+addr)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestMongoOpMsg_RoundTrip(t *testing.T) {
	addr := newFakeListener(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		doc, err := mongoReadOpMsgDocument(conn, 2*time.Second)
		if err != nil {
			return
		}
		fields, err := bsonScanTopLevel(doc, map[string]bool{"listDatabases": true, "$db": true})
		if err != nil || fields["listDatabases"].i32 != 1 || fields["$db"].str != "admin" {
			return
		}
		_ = mongoWriteOpMsg(conn, 2*time.Second, bsonDoc(bsonDoubleElem("ok", 1.0)))
	})

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	cmd := bsonDoc(bsonInt32Elem("listDatabases", 1), bsonStringElem("$db", "admin"))
	require.NoError(t, mongoWriteOpMsg(conn, 2*time.Second, cmd))

	reply, err := mongoReadOpMsgDocument(conn, 2*time.Second)
	require.NoError(t, err)
	fields, err := bsonScanTopLevel(reply, map[string]bool{"ok": true})
	require.NoError(t, err)
	assert.Equal(t, float64(1), fields["ok"].asFloat64())
}

func TestBSONScanTopLevel_SkipsUnwantedFieldsOfEveryCommonType(t *testing.T) {
	// A realistic listDatabases reply: ok (double), an embedded "databases"
	// array, and a "totalSize" int64 — bsonScanTopLevel must skip the array
	// and int64 correctly to still find "ok" afterward.
	databasesArray := bsonDoc(
		bsonInt32Elem("0", 42), // array elements are just BSON elements keyed "0","1",...
	)
	arrayElem := make([]byte, 0, 1+len("databases")+1+len(databasesArray))
	arrayElem = append(arrayElem, 0x04)
	arrayElem = append(arrayElem, []byte("databases")...)
	arrayElem = append(arrayElem, 0x00)
	arrayElem = append(arrayElem, databasesArray...)

	totalSizeElem := make([]byte, 0, 1+len("totalSize")+1+8)
	totalSizeElem = append(totalSizeElem, 0x12)
	totalSizeElem = append(totalSizeElem, []byte("totalSize")...)
	totalSizeElem = append(totalSizeElem, 0x00)
	sizeVal := make([]byte, 8)
	binary.LittleEndian.PutUint64(sizeVal, uint64(1024))
	totalSizeElem = append(totalSizeElem, sizeVal...)

	doc := bsonDoc(arrayElem, totalSizeElem, bsonDoubleElem("ok", 1.0))

	fields, err := bsonScanTopLevel(doc, map[string]bool{"ok": true})
	require.NoError(t, err)
	assert.Equal(t, float64(1), fields["ok"].asFloat64())
}
