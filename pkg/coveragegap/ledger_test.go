package coveragegap

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/templatesync"
)

func TestLedger_MixedFixture(t *testing.T) {
	techStack := []recon.TechFact{
		{Host: "app.example.com", Name: "WordPress 6.4", Source: "header"},   // native rule match -> not a gap
		{Host: "app.example.com", Name: "Nginx", Source: "header"},          // template-tag match -> not a gap
		{Host: "app.example.com", Name: "HTTP/2", Source: "header"},         // non-actionable -> not a gap
		{Host: "gateway.example.com", Name: "Webmin 2.111", Source: "banner"}, // genuine gap
	}
	loaded := []templatesync.Entry{
		{ID: "nginx-misconfig", Tags: []string{"nginx", "misconfig"}},
	}

	rows := Ledger(techStack, loaded)

	assert.Len(t, rows, 1)
	assert.Equal(t, GapRow{Host: "gateway.example.com", Product: "Webmin 2.111", Reason: ReasonNoCoverage}, rows[0])
}

func TestLedger_NoTechStack_NoRows(t *testing.T) {
	assert.Empty(t, Ledger(nil, nil))
}
