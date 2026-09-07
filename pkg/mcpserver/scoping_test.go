package mcpserver

import (
	"context"
	"sort"
	"testing"
)

// toolNames connects a client to a freshly built server at the given agency
// and returns the sorted tool names in its tools/list response — the
// client-visible surface, which is exactly what A5's filtering changes (not a
// runtime refusal inside a handler).
func toolNames(t *testing.T, agency Agency) []string {
	t.Helper()
	ctx := context.Background()
	session, err := connect(ctx, NewWithAgency(agency))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = session.Close() }()

	res, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	var names []string
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	sort.Strings(names)
	return names
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// TestNewWithAgency_ReadOnly_OmitsWriteCapableTools is A5's core check: a
// readonly server never registers scan / plan / templates.sync, so a client's
// tools/list cannot see them at all (doc16 Phase 7 Step 1).
func TestNewWithAgency_ReadOnly_OmitsWriteCapableTools(t *testing.T) {
	names := toolNames(t, AgencyReadOnly)

	for _, omitted := range []string{"scan", "plan", "templates.sync"} {
		if contains(names, omitted) {
			t.Errorf("readonly tools/list must not contain %q; got %v", omitted, names)
		}
	}
	for _, kept := range []string{"recon", "templates.list", "templates.search", "tools.search", "findings.export", "findings.triage", "session.log"} {
		if !contains(names, kept) {
			t.Errorf("readonly tools/list must still contain %q; got %v", kept, names)
		}
	}
}

// TestNewWithAgency_Full_RegistersEveryTool — the default level is unchanged
// from the pre-A5 New(): every tool present.
func TestNewWithAgency_Full_RegistersEveryTool(t *testing.T) {
	names := toolNames(t, AgencyFull)

	for _, want := range []string{
		"recon", "scan", "plan", "templates.list", "templates.sync",
		"templates.search", "tools.search", "findings.export", "findings.triage", "session.log",
	} {
		if !contains(names, want) {
			t.Errorf("full tools/list must contain %q; got %v", want, names)
		}
	}
}

// TestNew_DefaultsToFull — the back-compatible New() convenience is AgencyFull.
func TestNew_DefaultsToFull(t *testing.T) {
	ctx := context.Background()
	session, err := connect(ctx, New())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = session.Close() }()

	res, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	var names []string
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	if !contains(names, "scan") || !contains(names, "plan") {
		t.Errorf("New() must default to full agency (scan + plan present); got %v", names)
	}
}
