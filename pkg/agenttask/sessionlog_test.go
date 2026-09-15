package agenttask

import "testing"

func TestSessionLogBeginDefaultsToHumanActor(t *testing.T) {
	log := NewSessionLog(nil)
	finish := log.Begin("scan", "manual run", nil)
	finish("ok", nil)

	entries := log.Entries()
	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(entries))
	}
	if got := entries[0].Actor; got != "human" {
		t.Errorf("Begin: want actor %q, got %q", "human", got)
	}
}

func TestSessionLogBeginActorRecordsGivenActor(t *testing.T) {
	log := NewSessionLog(nil)
	finish := log.BeginActor("agent", "scan.leaf", "orchestrator decided to probe", map[string]string{"target": "https://example.test"})
	finish("found nothing", nil)

	entries := log.Entries()
	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(entries))
	}
	got := entries[0]
	if got.Actor != "agent" {
		t.Errorf("want actor %q, got %q", "agent", got.Actor)
	}
	if got.Tool != "scan.leaf" {
		t.Errorf("want tool %q, got %q", "scan.leaf", got.Tool)
	}
	if got.Params == nil {
		t.Error("want non-nil params")
	}
}
