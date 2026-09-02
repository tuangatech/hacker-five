package mcpserver

import "testing"

func TestRequireScope_Empty_ReturnsError(t *testing.T) {
	if _, err := requireScope(nil); err == nil {
		t.Fatal("expected an error for a nil scope — D3 (doc15 Step 1) requires an agent-initiated call to be refused, not warned, on a missing scope")
	}
	if _, err := requireScope([]string{}); err == nil {
		t.Fatal("expected an error for an empty scope slice")
	}
}

func TestRequireScope_NonEmpty_Succeeds(t *testing.T) {
	sc, err := requireScope([]string{"example.com"})
	if err != nil {
		t.Fatalf("requireScope returned an error for a valid entry: %v", err)
	}
	if !sc.Allowed("https://example.com/") {
		t.Fatal("expected the built Scope to allow the entry it was given")
	}
}
