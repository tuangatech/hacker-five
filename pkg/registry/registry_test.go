package registry

import "testing"

func TestFind_Hit(t *testing.T) {
	found, ok := Find("idor")
	if !ok {
		t.Fatal("expected to find the idor capability")
	}
	if found.Kind != KindDetector {
		t.Errorf("expected idor to be a %q capability, got %q", KindDetector, found.Kind)
	}
}

func TestFind_Miss(t *testing.T) {
	if _, ok := Find("does-not-exist"); ok {
		t.Fatal("expected no match for an unregistered capability name")
	}
}

func TestSearch_MatchesNameDescriptionWhenToUse(t *testing.T) {
	if got := Search("idor"); len(got) == 0 {
		t.Fatal("expected at least one match on capability name")
	}
	// "coupon" appears in businesslogic's own Description, matched via that
	// field rather than its Name.
	got := Search("coupon")
	found := false
	for _, c := range got {
		if c.Name == "businesslogic" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected Search(%q) to match businesslogic via its Description, got %+v", "coupon", got)
	}
	// Case-insensitive.
	if got := Search("IDOR"); len(got) == 0 {
		t.Fatal("expected Search to be case-insensitive")
	}
}

func TestSearch_EmptyQuery_ReturnsNil(t *testing.T) {
	if got := Search(""); got != nil {
		t.Fatalf("expected nil for an empty query, got %+v", got)
	}
	if got := Search("   "); got != nil {
		t.Fatalf("expected nil for a whitespace-only query, got %+v", got)
	}
}

func TestSearch_NoMatch_ReturnsNil(t *testing.T) {
	if got := Search("no-such-capability-exists"); got != nil {
		t.Fatalf("expected nil for a query with no match, got %+v", got)
	}
}

func TestCapabilities_EveryEntryHasRequiredFields(t *testing.T) {
	for _, c := range Capabilities {
		if c.Name == "" {
			t.Errorf("capability with empty Name: %+v", c)
		}
		if c.Description == "" {
			t.Errorf("capability %q has no Description", c.Name)
		}
		if c.Kind != KindDetector && c.Kind != KindReconTool && c.Kind != KindTemplateCategory {
			t.Errorf("capability %q has unrecognized Kind %q", c.Name, c.Kind)
		}
	}
}
