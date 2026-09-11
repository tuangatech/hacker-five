package netservice

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newFakeListener(t *testing.T, handle func(net.Conn)) string {
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

func TestCheckFTPAnonymous_Vulnerable(t *testing.T) {
	addr := newFakeListener(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 128)
		_, _ = conn.Write([]byte("220 fake-ftp ready\r\n"))
		if _, err := conn.Read(buf); err != nil {
			return
		}
		_, _ = conn.Write([]byte("331 Please specify the password.\r\n"))
		if _, err := conn.Read(buf); err != nil {
			return
		}
		_, _ = conn.Write([]byte("230 Login successful.\r\n"))
	})

	d := New(WithTimeout(2 * time.Second))
	findings, err := d.checkFTPAnonymous(context.Background(), addr, "tcp://"+addr)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "misconfig", findings[0].Type)
	assert.Equal(t, "medium", findings[0].Severity)
}

func TestCheckFTPAnonymous_NotVulnerable(t *testing.T) {
	addr := newFakeListener(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 128)
		_, _ = conn.Write([]byte("220 fake-ftp ready\r\n"))
		if _, err := conn.Read(buf); err != nil {
			return
		}
		_, _ = conn.Write([]byte("331 Please specify the password.\r\n"))
		if _, err := conn.Read(buf); err != nil {
			return
		}
		_, _ = conn.Write([]byte("530 Login incorrect.\r\n"))
	})

	d := New(WithTimeout(2 * time.Second))
	findings, err := d.checkFTPAnonymous(context.Background(), addr, "tcp://"+addr)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestCheckFTPAnonymous_NoGreeting(t *testing.T) {
	addr := newFakeListener(t, func(conn net.Conn) {
		_ = conn.Close() // closes immediately, no banner at all
	})

	d := New(WithTimeout(500 * time.Millisecond))
	findings, err := d.checkFTPAnonymous(context.Background(), addr, "tcp://"+addr)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestCheckFTPAnonymous_DialFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close()) // nothing listening now

	d := New(WithTimeout(500 * time.Millisecond))
	findings, err := d.checkFTPAnonymous(context.Background(), addr, "tcp://"+addr)
	require.NoError(t, err)
	assert.Empty(t, findings)
}
