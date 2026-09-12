package unit

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tlsdetector "github.com/tuangatech/hacker-five/pkg/detectors/tls"
)

// pkg/detectors/tls's own package tests (detector_test.go) cover every real
// handshake outcome (expired/not-yet-valid/near-expiry cert, chain trust,
// hostname mismatch, deprecated-protocol-by-default, downgrade-accepted,
// weak-cipher-accepted) against real local TLS listeners — those need
// hand-built certificates, which only make sense living next to the code
// they test. This file covers only Run's target-parsing/dispatch behavior,
// mirroring detector_netservice_test.go's own split for the same reason.

func TestTLSDetector_Run_NothingListening_NoFindingNoError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())

	d := tlsdetector.New(tlsdetector.WithTimeout(500 * time.Millisecond))
	findings, err := d.Run(context.Background(), "https://"+addr)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestTLSDetector_Run_InvalidTarget_ReturnsError(t *testing.T) {
	d := tlsdetector.New()
	_, err := d.Run(context.Background(), "")
	require.Error(t, err)
}
