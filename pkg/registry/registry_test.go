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
