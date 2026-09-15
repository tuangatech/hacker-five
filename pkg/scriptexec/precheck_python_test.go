package scriptexec

import (
	"strings"
	"testing"

	"github.com/tuangatech/hacker-five/pkg/scanner/scope"
)

func mustScope(t *testing.T, entries ...string) *scope.Scope {
	t.Helper()
	sc, err := scope.New(entries)
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	return sc
}

func requirePython(t *testing.T) {
	t.Helper()
	if _, err := runPythonASTChecker("pass"); err != nil {
		t.Skipf("python3 unavailable in this environment: %v", err)
	}
}

func TestPrecheckPython_BenignScript_NotBlocked(t *testing.T) {
	requirePython(t)
	src := `
import requests
r = requests.get("https://example.test/api/1")
print(r.status_code)
`
	got, err := precheckPython(src, mustScope(t, "example.test"))
	if err != nil {
		t.Fatalf("precheckPython: %v", err)
	}
	if got.Blocked {
		t.Fatalf("got blocked, reasons=%v", got.Reasons)
	}
}

func TestPrecheckPython_SubprocessImport_Blocked(t *testing.T) {
	requirePython(t)
	src := "import subprocess\nsubprocess.run(['ls'])\n"
	got, err := precheckPython(src, nil)
	if err != nil {
		t.Fatalf("precheckPython: %v", err)
	}
	if !got.Blocked {
		t.Fatal("want blocked for subprocess import")
	}
}

func TestPrecheckPython_OSSystemCall_Blocked(t *testing.T) {
	requirePython(t)
	src := "import os\nos.system('whoami')\n"
	got, err := precheckPython(src, nil)
	if err != nil {
		t.Fatalf("precheckPython: %v", err)
	}
	if !got.Blocked {
		t.Fatal("want blocked for os.system call")
	}
}

func TestPrecheckPython_RawSocket_Blocked(t *testing.T) {
	requirePython(t)
	src := "import socket\ns = socket.socket()\n"
	got, err := precheckPython(src, nil)
	if err != nil {
		t.Fatalf("precheckPython: %v", err)
	}
	if !got.Blocked {
		t.Fatal("want blocked for raw socket import")
	}
}

func TestPrecheckPython_FileWriteOutsideScratch_Blocked(t *testing.T) {
	requirePython(t)
	src := `open("/etc/passwd", "w")` + "\n"
	got, err := precheckPython(src, nil)
	if err != nil {
		t.Fatalf("precheckPython: %v", err)
	}
	if !got.Blocked {
		t.Fatal("want blocked for filesystem write outside scratch dir")
	}
}

func TestPrecheckPython_FileWriteInsideScratch_Allowed(t *testing.T) {
	requirePython(t)
	src := `open("` + ScratchDir + `/notes.txt", "w")` + "\n"
	got, err := precheckPython(src, nil)
	if err != nil {
		t.Fatalf("precheckPython: %v", err)
	}
	if got.Blocked {
		t.Fatalf("got blocked, reasons=%v", got.Reasons)
	}
}

func TestPrecheckPython_OutOfScopeHostLiteral_Blocked(t *testing.T) {
	requirePython(t)
	src := `url = "https://evil.example.com/steal"` + "\n"
	got, err := precheckPython(src, mustScope(t, "example.test"))
	if err != nil {
		t.Fatalf("precheckPython: %v", err)
	}
	if !got.Blocked {
		t.Fatal("want blocked for out-of-scope host literal")
	}
}

func TestPrecheckPython_DynamicImportEvasion_Blocked(t *testing.T) {
	requirePython(t)
	src := `__import__("subprocess").run(["ls"])` + "\n"
	got, err := precheckPython(src, nil)
	if err != nil {
		t.Fatalf("precheckPython: %v", err)
	}
	if !got.Blocked {
		t.Fatal("want blocked for __import__ dynamic-import evasion")
	}
}

func TestPrecheckPython_SyntaxError_Blocked(t *testing.T) {
	requirePython(t)
	got, err := precheckPython("def broken(:\n", nil)
	if err != nil {
		t.Fatalf("precheckPython: %v", err)
	}
	if !got.Blocked || !strings.Contains(strings.Join(got.Reasons, " "), "syntax error") {
		t.Fatalf("got %+v, want blocked with a syntax error reason", got)
	}
}
