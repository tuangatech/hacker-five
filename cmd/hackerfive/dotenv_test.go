package main

import (
	"os"
	"testing"
)

func TestParseDotEnvLine(t *testing.T) {
	cases := []struct {
		name      string
		line      string
		wantKey   string
		wantValue string
		wantOK    bool
	}{
		{"plain", "FOO=bar", "FOO", "bar", true},
		{"export prefix", "export FOO=bar", "FOO", "bar", true},
		{"double-quoted value", `FOO="bar baz"`, "FOO", "bar baz", true},
		{"single-quoted value", "FOO='bar baz'", "FOO", "bar baz", true},
		{"whitespace around key/value", "  FOO = bar  ", "FOO", "bar", true},
		{"empty value", "FOO=", "FOO", "", true},
		{"no equals sign", "FOO", "", "", false},
		{"equals with empty key", "=bar", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, value, ok := parseDotEnvLine(tc.line)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if key != tc.wantKey || value != tc.wantValue {
				t.Fatalf("got (%q, %q), want (%q, %q)", key, value, tc.wantKey, tc.wantValue)
			}
		})
	}
}

func TestLoadDotEnv_RealEnvVarWins(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.WriteFile(".env", []byte("HACKERFIVE_TEST_VAR=from-dotenv\nHACKERFIVE_TEST_VAR2=from-dotenv-2\n"), 0o644); err != nil {
		t.Fatalf("writing .env: %v", err)
	}

	t.Setenv("HACKERFIVE_TEST_VAR", "from-real-env")
	_ = os.Unsetenv("HACKERFIVE_TEST_VAR2")

	loadDotEnv()

	if got := os.Getenv("HACKERFIVE_TEST_VAR"); got != "from-real-env" {
		t.Fatalf("a real env var must win over .env, got %q", got)
	}
	if got := os.Getenv("HACKERFIVE_TEST_VAR2"); got != "from-dotenv-2" {
		t.Fatalf("expected .env to fill an otherwise-unset var, got %q", got)
	}
}

func TestLoadDotEnv_NoFile_NoPanic(t *testing.T) {
	t.Chdir(t.TempDir()) // no .env here
	loadDotEnv()         // must not panic or error out
}

func TestLoadDotEnv_MalformedLine_SkippedNotFatal(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.WriteFile(".env", []byte("not a valid line\nHACKERFIVE_TEST_VAR3=ok\n"), 0o644); err != nil {
		t.Fatalf("writing .env: %v", err)
	}
	_ = os.Unsetenv("HACKERFIVE_TEST_VAR3")

	loadDotEnv()

	if got := os.Getenv("HACKERFIVE_TEST_VAR3"); got != "ok" {
		t.Fatalf("a malformed line must not block later valid lines, got %q", got)
	}
}
