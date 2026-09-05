package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/detectors/ssrf"
	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/scanner"
	"github.com/tuangatech/hacker-five/pkg/templatesync"
)

func TestResolveTargets_Empty(t *testing.T) {
	targets, err := resolveTargets("")
	require.NoError(t, err)
	assert.Nil(t, targets)
}

func TestResolveTargets_LiteralURL(t *testing.T) {
	targets, err := resolveTargets("http://example.com")
	require.NoError(t, err)
	assert.Equal(t, []string{"http://example.com"}, targets)
}

func TestResolveTargets_FileWithMultipleTargets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.txt")
	require.NoError(t, os.WriteFile(path, []byte("http://a.example\n\nhttp://b.example\n"), 0o644))

	targets, err := resolveTargets(path)
	require.NoError(t, err)
	assert.Equal(t, []string{"http://a.example", "http://b.example"}, targets, "blank lines must be skipped")
}

func TestParseTags_Empty(t *testing.T) {
	assert.Nil(t, parseTags(""))
}

func TestParseTags_SplitsAndTrims(t *testing.T) {
	assert.Equal(t, []string{"wordpress", "grafana"}, parseTags(" wordpress, grafana "))
}

func TestParseTags_DropsEmptyEntries(t *testing.T) {
	assert.Equal(t, []string{"wordpress"}, parseTags("wordpress,,  "))
}

func TestParseHeaders_Empty(t *testing.T) {
	headers, err := parseHeaders(nil)
	require.NoError(t, err)
	assert.Nil(t, headers)
}

func TestParseHeaders_SplitsOnFirstColonAndTrims(t *testing.T) {
	headers, err := parseHeaders([]string{"Cookie: PHPSESSID=abc; security=low", "X-Custom:value"})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{
		"Cookie":   "PHPSESSID=abc; security=low",
		"X-Custom": "value",
	}, headers, "a header value may itself contain a colon (e.g. a cookie); only the first colon splits name from value")
}

func TestParseHeaders_MissingColonIsError(t *testing.T) {
	_, err := parseHeaders([]string{"not-a-valid-header"})
	assert.Error(t, err)
}

// TestNewScanCmd_OOBServerDefaultsToPublicPair locks in the 2026-09-02
// default change (docs/discussions.md, user's explicit choice): omitting
// --oob-server entirely now defaults to 2 of ProjectDiscovery's public OOB
// servers, not an empty/silent-skip default.
func TestNewScanCmd_OOBServerDefaultsToPublicPair(t *testing.T) {
	cmd := newScanCmd(&rootFlags{})

	flag := cmd.Flags().Lookup("oob-server")
	require.NotNil(t, flag, "--oob-server must be registered")
	assert.Equal(t, "[https://oast.pro,https://oast.live]", flag.DefValue)
	assert.Equal(t, ssrf.DefaultOOBServers, []string{"https://oast.pro", "https://oast.live"})
}

// TestNewScanCmd_NoOOBFlagRegistered confirms the escape hatch exists and
// defaults to false (OOB stays on unless explicitly disabled) — the
// StringArray --oob-server flag itself has no clean way to express "start
// from an explicitly empty list", so this dedicated flag is the only way a
// CLI user opts out for a real third-party engagement.
func TestNewScanCmd_NoOOBFlagRegistered(t *testing.T) {
	cmd := newScanCmd(&rootFlags{})

	flag := cmd.Flags().Lookup("no-oob")
	require.NotNil(t, flag, "--no-oob must be registered")
	assert.Equal(t, "false", flag.DefValue)
}

// TestNewScanCmd_NarrowByTechFlagsRegistered is LT-17's (docs/follow-up.md)
// CLI-parity flags — registry.TechStackTags was already transport-agnostic;
// this is just the missing plumbing scan itself needed.
func TestNewScanCmd_NarrowByTechFlagsRegistered(t *testing.T) {
	cmd := newScanCmd(&rootFlags{})

	narrowFlag := cmd.Flags().Lookup("narrow-by-tech")
	require.NotNil(t, narrowFlag, "--narrow-by-tech must be registered")
	assert.Equal(t, "false", narrowFlag.DefValue)

	reconFileFlag := cmd.Flags().Lookup("recon-file")
	require.NotNil(t, reconFileFlag, "--recon-file must be registered")

	indexFlag := cmd.Flags().Lookup("template-index")
	require.NotNil(t, indexFlag, "--template-index must be registered")
	assert.Equal(t, "templates/index.json", indexFlag.DefValue)
}

// TestNarrowScanConfigByTech_NarrowsWhenNoExplicitTags confirms the happy
// path: an empty cfg.Tags gets narrowed to the tech stack's relevant tags.
func TestNarrowScanConfigByTech_NarrowsWhenNoExplicitTags(t *testing.T) {
	techStack := []recon.TechFact{{Name: "WordPress", Host: "example.com"}}
	index := []templatesync.Entry{{ID: "wordpress-panel", Tags: []string{"wordpress"}, Severity: "info"}}
	cfg := scanner.Config{}
	var stderr bytes.Buffer

	narrowScanConfigByTech(&stderr, techStack, index, &cfg)

	assert.Equal(t, []string{"wordpress"}, cfg.Tags)
}

// TestNarrowScanConfigByTech_NeverOverridesExplicitTags confirms an
// operator's own --tags value is left completely alone, never widened or
// replaced — same posture pkg/webui's narrowConfigsByTechStack established.
func TestNarrowScanConfigByTech_NeverOverridesExplicitTags(t *testing.T) {
	techStack := []recon.TechFact{{Name: "WordPress", Host: "example.com"}}
	index := []templatesync.Entry{{ID: "wordpress-panel", Tags: []string{"wordpress"}, Severity: "info"}}
	cfg := scanner.Config{Tags: []string{"custom"}}
	var stderr bytes.Buffer

	narrowScanConfigByTech(&stderr, techStack, index, &cfg)

	assert.Equal(t, []string{"custom"}, cfg.Tags)
}

// TestNarrowScanConfigByTech_DegradesToFullCorpusWhenNothingUsable covers
// every "nothing to narrow with" case — each must warn to stderr and leave
// cfg.Tags empty (the full-corpus fallback), never error.
func TestNarrowScanConfigByTech_DegradesToFullCorpusWhenNothingUsable(t *testing.T) {
	cases := []struct {
		name      string
		techStack []recon.TechFact
		index     []templatesync.Entry
	}{
		{"no tech stack", nil, []templatesync.Entry{{ID: "x", Tags: []string{"wordpress"}}}},
		{"no template index", []recon.TechFact{{Name: "WordPress", Host: "example.com"}}, nil},
		{"tech stack ties to no tag", []recon.TechFact{{Name: "Unmapped Thing", Host: "example.com"}}, []templatesync.Entry{{ID: "x", Tags: []string{"wordpress"}}}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			cfg := scanner.Config{}
			var stderr bytes.Buffer

			narrowScanConfigByTech(&stderr, tt.techStack, tt.index, &cfg)

			assert.Empty(t, cfg.Tags)
			assert.NotEmpty(t, stderr.String(), "a degrade case must still explain itself to stderr")
		})
	}
}

func TestExpandOOBServers(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil in nil out", nil, nil},
		{"empty in nil out", []string{}, nil},
		{"public expands to full pool", []string{"public"}, ssrf.PublicInteractshServers},
		{"case-insensitive public", []string{"PUBLIC"}, ssrf.PublicInteractshServers},
		{
			"mixes public with a custom server, order preserved",
			[]string{"https://my-own.example.com", "public"},
			append([]string{"https://my-own.example.com"}, ssrf.PublicInteractshServers...),
		},
		{"non-public entries pass through unchanged", []string{"https://a.example.com", "https://b.example.com"}, []string{"https://a.example.com", "https://b.example.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, expandOOBServers(tt.in))
		})
	}
}
