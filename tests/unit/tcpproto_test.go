package unit

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/template/tcpproto"
)

// newFakeTCPServer starts a local listener that runs handle once per
// accepted connection, in its own goroutine, until the listener is closed.
// Mirrors the project's existing newFakeOOBServer/httptest.NewServer
// convention: a real local socket, never a real external service.
func newFakeTCPServer(t *testing.T, handle func(net.Conn)) string {
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

func TestTCPProto_Probe_ReadsUnsolicitedBanner(t *testing.T) {
	addr := newFakeTCPServer(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		_, _ = conn.Write([]byte("220 fake-ftp ready\r\n"))
	})

	got, err := tcpproto.Probe(context.Background(), addr, time.Second, nil, 0)
	require.NoError(t, err)
	require.Contains(t, string(got), "220 fake-ftp ready")
}

func TestTCPProto_Probe_SendsThenReadsReply(t *testing.T) {
	addr := newFakeTCPServer(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 64)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		_, _ = conn.Write([]byte("echo:" + string(buf[:n])))
	})

	got, err := tcpproto.Probe(context.Background(), addr, time.Second, []byte("PING\r\n"), 0)
	require.NoError(t, err)
	require.Equal(t, "echo:PING\r\n", string(got))
}

func TestTCPProto_Read_TimeoutWithNoDataIsNotAnError(t *testing.T) {
	addr := newFakeTCPServer(t, func(conn net.Conn) {
		// Accept and hold the connection open, sending nothing — a
		// listener that never volunteers a banner.
		<-time.After(2 * time.Second)
		_ = conn.Close()
	})

	conn, err := tcpproto.Dial(context.Background(), addr, time.Second)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	got, err := tcpproto.Read(conn, 0, 100*time.Millisecond)
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestTCPProto_Dial_ConnectionRefusedIsAnError(t *testing.T) {
	// A closed listener on a real (just-freed) port — connection refused,
	// a genuine error distinct from Read's "nothing arrived" non-error.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())

	_, err = tcpproto.Dial(context.Background(), addr, time.Second)
	require.Error(t, err)
}

func TestTCPProto_Probe_RespectsMaxReadCap(t *testing.T) {
	big := make([]byte, tcpproto.MaxReadBytes*2)
	for i := range big {
		big[i] = 'A'
	}
	addr := newFakeTCPServer(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		_, _ = conn.Write(big)
	})

	got, err := tcpproto.Probe(context.Background(), addr, time.Second, nil, 999999)
	require.NoError(t, err)
	require.LessOrEqual(t, len(got), tcpproto.MaxReadBytes)
}
