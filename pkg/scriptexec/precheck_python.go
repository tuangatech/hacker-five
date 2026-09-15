package scriptexec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/tuangatech/hacker-five/pkg/scanner/scope"
)

// pythonCheckerTimeout bounds the trusted checker subprocess — parsing and
// walking an AST is fast; a hang here would only ever mean a pathological
// input, not real work, so this stays short.
const pythonCheckerTimeout = 10 * time.Second

// pythonASTChecker is small, fixed, first-party, and reviewed — it is
// trusted code, never the untrusted script. It only extracts structural
// facts (imports, dotted call names, string literals, and the first
// argument of filesystem-shaped calls) from the untrusted source via
// Python's own stdlib ast module; every policy decision (which imports/
// calls are disallowed, which literals are out of scope) is made in Go by
// precheckPython below, not here. Go has no Python AST library of its own —
// this subprocess call is the one deliberate exception to "no exec inside
// the trusted codebase," scoped narrowly to a fixed script with no
// untrusted input on its command line (the untrusted source goes over
// stdin, never as an argument or into the script text itself).
const pythonASTChecker = `
import ast, json, sys

FS_FUNCS = {
    "open", "os.remove", "os.unlink", "os.mkdir", "os.makedirs", "os.rmdir",
    "os.rename", "os.replace", "os.chdir", "os.chmod", "os.chown",
    "shutil.rmtree", "shutil.copy", "shutil.copy2", "shutil.copyfile",
    "shutil.move", "pathlib.Path", "Path",
}

def dotted_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        return None if base is None else base + "." + node.attr
    return None

result = {
    "imports": [], "calls": [], "string_literals": [],
    "file_path_args": [], "syntax_error": None,
}
src = sys.stdin.read()
try:
    tree = ast.parse(src)
except SyntaxError as e:
    result["syntax_error"] = str(e)
    print(json.dumps(result))
    sys.exit(0)

for node in ast.walk(tree):
    if isinstance(node, ast.Import):
        for alias in node.names:
            result["imports"].append(alias.name)
    elif isinstance(node, ast.ImportFrom):
        if node.module:
            result["imports"].append(node.module)
    elif isinstance(node, ast.Constant) and isinstance(node.value, str):
        result["string_literals"].append(node.value)
    elif isinstance(node, ast.Call):
        name = dotted_name(node.func)
        if name:
            result["calls"].append(name)
            if name in FS_FUNCS and node.args:
                arg0 = node.args[0]
                if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                    result["file_path_args"].append(arg0.value)

print(json.dumps(result))
`

type pythonASTFacts struct {
	Imports       []string `json:"imports"`
	Calls         []string `json:"calls"`
	StringLiteral []string `json:"string_literals"`
	FilePathArgs  []string `json:"file_path_args"`
	SyntaxError   string   `json:"syntax_error"`
}

// pythonBlockedImports are modules whose mere presence means the script
// intends further subprocess/interpreter spawning, raw socket/TLS access,
// or dynamic-import evasion of the exact checks above — blocked outright,
// not name-by-name, since any use of these modules reaches capability this
// sandbox's read-only rootfs / --cap-drop=ALL / egress proxy exist to deny.
var pythonBlockedImports = map[string]string{
	"subprocess":      "further subprocess spawning",
	"pty":             "pseudo-terminal / interactive shell spawning",
	"multiprocessing": "further process spawning",
	"socket":          "raw socket use (bypasses the egress proxy)",
	"ssl":             "raw TLS socket use (bypasses the egress proxy)",
	"ctypes":          "native code / syscall access",
	"importlib":       "dynamic import (can evade the static import check)",
	"imp":             "dynamic import (can evade the static import check)",
}

// pythonBlockedCalls are exact dotted call names blocked regardless of
// which module they were imported from (e.g. `from os import system`
// wouldn't show up as an "os" import name the way `import os` would, so the
// call itself — not just the import — is checked).
var pythonBlockedCalls = map[string]string{
	"os.system":      "further subprocess spawning",
	"os.popen":       "further subprocess spawning",
	"os.fork":        "further process spawning",
	"os.posix_spawn": "further process spawning",
	"eval":           "dynamic code execution (can evade every static check above)",
	"exec":           "dynamic code execution (can evade every static check above)",
	"compile":        "dynamic code execution (can evade every static check above)",
	"__import__":     "dynamic import (can evade the static import check)",
}

// pythonBlockedCallPrefixes covers os.exec*/os.spawn* families (execl,
// execle, execlp, execlpe, execv, execve, execvp, execvpe, spawnl, spawnv,
// ...) without enumerating every variant.
var pythonBlockedCallPrefixes = []string{"os.exec", "os.spawn"}

func precheckPython(source string, sc *scope.Scope) (PrecheckResult, error) {
	facts, err := runPythonASTChecker(source)
	if err != nil {
		return PrecheckResult{}, err
	}
	if facts.SyntaxError != "" {
		return PrecheckResult{Blocked: true, Reasons: []string{"python syntax error: " + facts.SyntaxError}}, nil
	}

	var reasons []string
	for _, imp := range facts.Imports {
		if reason, blocked := pythonBlockedImports[imp]; blocked {
			reasons = append(reasons, fmt.Sprintf("import %q: %s", imp, reason))
		}
	}
	for _, call := range facts.Calls {
		if reason, blocked := pythonBlockedCalls[call]; blocked {
			reasons = append(reasons, fmt.Sprintf("call %q: %s", call, reason))
			continue
		}
		for _, prefix := range pythonBlockedCallPrefixes {
			if strings.HasPrefix(call, prefix) {
				reasons = append(reasons, fmt.Sprintf("call %q: further process spawning", call))
				break
			}
		}
	}
	for _, p := range facts.FilePathArgs {
		if pathOutsideScratch(p) {
			reasons = append(reasons, fmt.Sprintf("filesystem access to %q falls outside the sandbox scratch dir %s", p, ScratchDir))
		}
	}
	reasons = append(reasons, hostLiteralsOutOfScope(facts.StringLiteral, sc)...)

	return PrecheckResult{Blocked: len(reasons) > 0, Reasons: reasons}, nil
}

func runPythonASTChecker(source string) (pythonASTFacts, error) {
	ctx, cancel := context.WithTimeout(context.Background(), pythonCheckerTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "python3", "-c", pythonASTChecker)
	cmd.Stdin = strings.NewReader(source)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return pythonASTFacts{}, fmt.Errorf("scriptexec: running python AST checker: %w (stderr: %s)", err, stderr.String())
	}

	var facts pythonASTFacts
	if err := json.Unmarshal(stdout.Bytes(), &facts); err != nil {
		return pythonASTFacts{}, fmt.Errorf("scriptexec: decoding python AST checker output: %w", err)
	}
	return facts, nil
}
