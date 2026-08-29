package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/templatesync"
)

func TestNewTemplatesCmd_RegistersSyncAndListSubcommands(t *testing.T) {
	cmd := newTemplatesCmd()

	var haveSync, haveList bool
	for _, child := range cmd.Commands() {
		switch child.Name() {
		case "sync":
			haveSync = true
		case "list":
			haveList = true
		}
	}
	assert.True(t, haveSync, "'templates sync' must be registered")
	assert.True(t, haveList, "'templates list' must be registered")
}

func TestNewTemplatesListCmd_HasTagsFlag(t *testing.T) {
	cmd := newTemplatesListCmd()
	flag := cmd.Flags().Lookup("tags")
	require.NotNil(t, flag, "'templates list' must expose --tags")
	assert.Equal(t, "", flag.DefValue)
}

// TestDefaultTemplateDirsWithLabels_Invariants avoids asserting a specific
// machine's sync state (whether 'hackerfive templates sync' has ever run
// under this test environment's real os.UserConfigDir() is not something a
// unit test should assume either way) — instead it locks in the invariants
// that must hold regardless: bundled is always first and always labeled
// "bundled", dirs/labels stay the same length, and a second entry (if
// present at all) is always the synced one.
func TestDefaultTemplateDirsWithLabels_Invariants(t *testing.T) {
	dirs, labels := defaultTemplateDirsWithLabels()

	require.Equal(t, len(dirs), len(labels))
	require.GreaterOrEqual(t, len(dirs), 1)
	assert.Equal(t, templatesync.DefaultBundledDir, dirs[0])
	assert.Equal(t, "bundled", labels[0])

	if len(dirs) == 2 {
		assert.Equal(t, "synced", labels[1])
		assert.NotEqual(t, templatesync.DefaultBundledDir, dirs[1])
	} else {
		assert.Len(t, dirs, 1, "defaultTemplateDirsWithLabels must return either 1 (bundled only) or 2 (bundled + synced) entries")
	}
}

func TestNewScanCmd_TemplatesFlagDefaultsToBundledDir(t *testing.T) {
	cmd := newScanCmd(&rootFlags{})
	flag := cmd.Flags().Lookup("templates")
	require.NotNil(t, flag)
	assert.Equal(t, "[./templates/]", flag.DefValue, "--templates must default to the bundled directory")
}
