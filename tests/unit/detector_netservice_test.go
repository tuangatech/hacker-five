package unit

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/detectors/netservice"
)

// The individual FTP/MySQL/Redis wire-protocol checks (vulnerable and
// not-vulnerable) are tested against real local listeners inside
// pkg/detectors/netservice's own package (ftp_test.go/mysql_test.go/
// redis_test.go) rather than here: Detector.Run dispatches purely on the
// port number named in a "tcp://host:port" target (registry.resolvePortFacts'
// shape), and a test can't bind a real listener to the literal privileged
// port 21 (or safely claim 3306/6379, which a real local MySQL/Redis might
// already own) the way it can an OS-assigned ephemeral one — see
// pkg/scanner's own engine_internal_test.go for the same
// external-black-box-tests-plus-internal-package-tests split this mirrors.
// This file covers only Run's own dispatch behavior, which needs no real
// listener at all.

func TestNetservice_Run_UncoveredPort_NoFindingNoError(t *testing.T) {
	// Port 5432 (PostgreSQL) has no check yet (registry.netserviceCheckedPorts)
	// — Run's port lookup misses before ever dialing, so this returns
	// cleanly with nothing listening at all.
	d := netservice.New()
	findings, err := d.Run(context.Background(), "tcp://127.0.0.1:5432")
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestNetservice_Run_InvalidTarget_ReturnsError(t *testing.T) {
	d := netservice.New()
	_, err := d.Run(context.Background(), "https://example.test")
	require.Error(t, err)
}

func TestNetservice_Run_NoPort_ReturnsError(t *testing.T) {
	d := netservice.New()
	_, err := d.Run(context.Background(), "tcp://127.0.0.1")
	require.Error(t, err)
}
