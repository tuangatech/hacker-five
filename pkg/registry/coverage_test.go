package registry

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/tuangatech/hacker-five/pkg/templatesync"
)

func TestCoverageStatus_NativeRuleMatch(t *testing.T) {
	hasNative, hasTemplate, nonActionable := CoverageStatus("WordPress 6.4", nil)
	assert.True(t, hasNative, "WordPress has a native techRules entry")
	assert.False(t, nonActionable)
	_ = hasTemplate
}

func TestCoverageStatus_TemplateTagMatch(t *testing.T) {
	index := []templatesync.Entry{
		{ID: "nginx-misconfig", Tags: []string{"nginx", "misconfig"}},
	}
	hasNative, hasTemplate, nonActionable := CoverageStatus("Nginx", index)
	assert.True(t, hasTemplate)
	assert.False(t, nonActionable)
	_ = hasNative
}

func TestCoverageStatus_NonActionable(t *testing.T) {
	hasNative, hasTemplate, nonActionable := CoverageStatus("HTTP/2", nil)
	assert.False(t, hasNative)
	assert.False(t, hasTemplate)
	assert.True(t, nonActionable)
}

func TestCoverageStatus_GenuineGap(t *testing.T) {
	hasNative, hasTemplate, nonActionable := CoverageStatus("Webmin 2.111", nil)
	assert.False(t, hasNative)
	assert.False(t, hasTemplate)
	assert.False(t, nonActionable)
}
