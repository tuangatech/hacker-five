package netservice

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckRedisUnauth_Vulnerable(t *testing.T) {
	addr := newFakeListener(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 64)
		n, err := conn.Read(buf)
		if err != nil || string(buf[:n]) != "PING\r\n" {
			return
		}
		_, _ = conn.Write([]byte("+PONG\r\n"))
	})

	d := New(WithTimeout(2 * time.Second))
	findings, err := d.checkRedisUnauth(context.Background(), addr, "tcp://"+addr)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "high", findings[0].Severity)
}

func TestCheckRedisUnauth_NotVulnerable(t *testing.T) {
	addr := newFakeListener(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 64)
		if _, err := conn.Read(buf); err != nil {
			return
		}
		_, _ = conn.Write([]byte("-NOAUTH Authentication required.\r\n"))
	})

	d := New(WithTimeout(2 * time.Second))
	findings, err := d.checkRedisUnauth(context.Background(), addr, "tcp://"+addr)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestCheckRedisUnauth_CoincidentalPongSubstringDoesNotMatch(t *testing.T) {
	// "PONG" appearing somewhere inside an unrelated error line must not
	// false-positive — redisIsPong requires the RESP simple-string "+PONG"
	// prefix specifically, not a substring anywhere in the reply.
	addr := newFakeListener(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 64)
		if _, err := conn.Read(buf); err != nil {
			return
		}
		_, _ = conn.Write([]byte("-ERR unknown command 'PONG'\r\n"))
	})

	d := New(WithTimeout(2 * time.Second))
	findings, err := d.checkRedisUnauth(context.Background(), addr, "tcp://"+addr)
	require.NoError(t, err)
	assert.Empty(t, findings)
}
