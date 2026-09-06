package unit

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
)

func TestSessionLog_Begin_RecordsOnFinish(t *testing.T) {
	log := agenttask.NewSessionLog(nil)

	finish := log.Begin("scan", "check the login flow", map[string]any{"targets": []string{"https://x.example"}})
	assert.Empty(t, log.Entries(), "nothing recorded until finish is called")

	finish("2 finding(s)", nil)

	entries := log.Entries()
	require.Len(t, entries, 1)
	e := entries[0]
	assert.Equal(t, int64(1), e.Seq)
	assert.Equal(t, "scan", e.Tool)
	assert.Equal(t, "check the login flow", e.Reason)
	assert.Equal(t, "2 finding(s)", e.Result)
	assert.Empty(t, e.Error)
	assert.False(t, e.StartedAt.IsZero())
	assert.False(t, e.FinishedAt.IsZero())
	assert.GreaterOrEqual(t, e.DurationMS, int64(0))
	assert.JSONEq(t, `{"targets":["https://x.example"]}`, string(e.Params))
}

func TestSessionLog_Begin_RecordsError(t *testing.T) {
	log := agenttask.NewSessionLog(nil)
	log.Begin("recon", "", nil)("", errors.New("scope required"))

	entries := log.Entries()
	require.Len(t, entries, 1)
	assert.Equal(t, "scope required", entries[0].Error)
	assert.Empty(t, entries[0].Reason)
	assert.Nil(t, entries[0].Params)
}

func TestSessionLog_SeqIsMonotonicAcrossInterleavedCalls(t *testing.T) {
	log := agenttask.NewSessionLog(nil)

	f1 := log.Begin("scan", "", nil)
	f2 := log.Begin("recon", "", nil)
	// Finish in reverse start order — completion order, not start order,
	// is what Entries() reflects, but Seq still reflects start order.
	f2("", nil)
	f1("", nil)

	entries := log.Entries()
	require.Len(t, entries, 2)
	assert.Equal(t, "recon", entries[0].Tool)
	assert.Equal(t, int64(2), entries[0].Seq)
	assert.Equal(t, "scan", entries[1].Tool)
	assert.Equal(t, int64(1), entries[1].Seq)
}

func TestSessionLog_Query_FilterAndLimit(t *testing.T) {
	log := agenttask.NewSessionLog(nil)
	for _, tool := range []string{"scan", "recon", "scan", "plan", "scan"} {
		log.Begin(tool, "", nil)("", nil)
	}

	assert.Len(t, log.Query("", 0), 5)
	assert.Len(t, log.Query("scan", 0), 3)
	assert.Len(t, log.Query("recon", 0), 1)
	assert.Empty(t, log.Query("findings.export", 0))

	// limit keeps the most recent N in completion order
	last2 := log.Query("", 2)
	require.Len(t, last2, 2)
	assert.Equal(t, "plan", last2[0].Tool)
	assert.Equal(t, "scan", last2[1].Tool)

	lastScan := log.Query("scan", 1)
	require.Len(t, lastScan, 1)
	assert.Equal(t, int64(5), lastScan[0].Seq)
}

func TestSessionLog_JSONLSink(t *testing.T) {
	var sink bytes.Buffer
	log := agenttask.NewSessionLog(&sink)

	log.Begin("scan", "r1", map[string]any{"detector": "misconfig"})("1 finding(s)", nil)
	log.Begin("findings.export", "r2", nil)("512 byte(s)", nil)

	lines := strings.Split(strings.TrimSpace(sink.String()), "\n")
	require.Len(t, lines, 2)

	var first agenttask.SessionLogEntry
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &first))
	assert.Equal(t, "scan", first.Tool)
	assert.Equal(t, "r1", first.Reason)
	assert.Equal(t, "1 finding(s)", first.Result)

	var second agenttask.SessionLogEntry
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &second))
	assert.Equal(t, "findings.export", second.Tool)
}

func TestSessionLog_ConcurrentBeginFinish(t *testing.T) {
	log := agenttask.NewSessionLog(nil)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Begin("scan", "", map[string]any{"i": 1})("done", nil)
		}()
	}
	wg.Wait()

	entries := log.Entries()
	assert.Len(t, entries, 50)

	seqs := map[int64]bool{}
	for _, e := range entries {
		assert.False(t, seqs[e.Seq], "seq %d handed out twice", e.Seq)
		seqs[e.Seq] = true
	}
	assert.Len(t, seqs, 50)
}
