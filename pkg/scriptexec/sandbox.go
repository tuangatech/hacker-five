package scriptexec

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Sandbox container images: small, stock, unmodified base images — no
// custom image build step, so this package needs nothing beyond a working
// Docker daemon to run. Alpine's ash (LangShell) and its python3 package
// (LangPython) are both sufficient for a short exploration script; neither
// image is ever given network access to fetch anything else (the container
// never sees the internet directly — see the egress-proxy topology below).
const (
	pythonImage = "python:3.12-alpine"
	shellImage  = "alpine:3.20"
	proxyImage  = "alpine:3.20"
)

// Resource/time limits for the script container — deliberately tight: this
// tool runs a short exploration snippet, not a workload.
const (
	containerMemory    = "256m"
	containerCPUs      = "0.5"
	containerPIDsLimit = "64"
	// scratchTmpfsSize caps the one writable path (ScratchDir) a script has.
	scratchTmpfsSize = "10m"
	// maxCapturedOutput caps stdout/stderr capture — a runaway script that
	// floods output is truncated, not allowed to exhaust host memory.
	maxCapturedOutput = 256 * 1024
	// defaultScriptTimeout is used when the caller leaves ScriptRequest.Timeout unset.
	defaultScriptTimeout = 60 * time.Second
	// proxyListenPort is the fixed port the egress-proxy sidecar listens on
	// inside its own container — internal to the per-run --internal network,
	// never published to the host.
	proxyListenPort = "8080"
	// sandboxUID/sandboxGID: the script container's non-root user. Alpine
	// and python:3.12-alpine both accept an arbitrary numeric uid:gid with
	// no matching /etc/passwd entry, which is fine for a script that never
	// needs a real username.
	sandboxUID = "10001"
	sandboxGID = "10001"
)

// runDockerCLI is a docker(1) invocation, its stdout/stderr and exit
// handling factored out so runSandboxed's orchestration is exercised the
// same way in both a real run and (via dockerCmdRunner) a unit test with no
// Docker daemon at all.
type dockerCmdFunc func(ctx context.Context, stdin string, args ...string) (stdout, stderr string, err error)

// dockerCmdRunner executes a real `docker` CLI invocation. Overridable in
// tests (same injectable-function convention as pkg/recon/exec.go's runFunc).
var dockerCmdRunner dockerCmdFunc = runDockerCLI

func runDockerCLI(ctx context.Context, stdin string, args ...string) (string, string, error) {
	path, err := exec.LookPath("docker")
	if err != nil {
		return "", "", fmt.Errorf("scriptexec: docker not found on PATH: %w", err)
	}
	cmd := exec.CommandContext(ctx, path, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	return stdout.String(), stderr.String(), err
}

// runID returns a short random hex string used to namespace one run's
// networks/containers so concurrent script.explore calls never collide.
func runID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// imageAndCommand picks the sandbox image and the in-container command for
// req.Language — both read the untrusted script off stdin, so it is never
// written to a file the container (or a bind mount) has to trust.
func imageAndCommand(lang Language) (image string, command []string, err error) {
	switch lang {
	case LangPython:
		return pythonImage, []string{"python3", "-"}, nil
	case LangShell:
		return shellImage, []string{"sh", "-s"}, nil
	default:
		return "", nil, fmt.Errorf("%w: %q", ErrUnsupportedLanguage, lang)
	}
}

// commonContainerSecurityArgs are the flags every container this package
// starts shares: read-only rootfs, no capabilities, no privilege
// escalation, and a size-capped tmpfs for the one writable path
// (ScratchDir) a script gets. The egress-proxy sidecar gets these same
// flags too — it never executes untrusted input, but it has no reason to
// need a writable root or extra capabilities either.
func commonContainerSecurityArgs() []string {
	return []string{
		"--read-only",
		"--tmpfs", fmt.Sprintf("%s:rw,size=%s,uid=%s,gid=%s", ScratchDir, scratchTmpfsSize, sandboxUID, sandboxGID),
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
		"--user", sandboxUID + ":" + sandboxGID,
	}
}

// buildScriptContainerArgs constructs the full `docker run` argument list
// for the script container: no capabilities, read-only rootfs but for a
// size-capped scratch tmpfs, hard resource limits, and network access
// wired only to the per-run internal network (proxyAddr, e.g.
// "http://172.20.0.2:8080", is the sidecar's address on that same network —
// the container's only route anywhere). Pure and side-effect-free so every
// flag is unit-testable without a Docker daemon.
func buildScriptContainerArgs(req ScriptRequest, containerName, internalNet, proxyAddr string) ([]string, error) {
	image, command, err := imageAndCommand(req.Language)
	if err != nil {
		return nil, err
	}
	args := []string{
		"run", "--rm", "-i",
		"--name", containerName,
		"--network", internalNet,
		"-e", "HTTP_PROXY=" + proxyAddr,
		"-e", "HTTPS_PROXY=" + proxyAddr,
		"-e", "http_proxy=" + proxyAddr,
		"-e", "https_proxy=" + proxyAddr,
		"-e", "NO_PROXY=",
		"-e", "no_proxy=",
	}
	args = append(args, commonContainerSecurityArgs()...)
	args = append(args,
		"--pids-limit", containerPIDsLimit,
		"--memory", containerMemory,
		"--cpus", containerCPUs,
		image,
	)
	args = append(args, command...)
	return args, nil
}

// buildProxyContainerArgs constructs the sidecar's `docker run` argument
// list: attached only to internalNet at creation (dockerNetworkConnect
// attaches egressNet separately afterward, since `docker run` only accepts
// one --network), the compiled proxyBinaryHostPath bind-mounted read-only as
// its entrypoint, and scopeFileHostPath bind-mounted read-only as the scope
// file it reads via scope.Parse.
func buildProxyContainerArgs(containerName, internalNet, proxyBinaryHostPath, scopeFileHostPath string) []string {
	args := []string{
		"run", "-d",
		"--name", containerName,
		"--network", internalNet,
		"-v", proxyBinaryHostPath + ":/hf-egressproxy:ro",
		"-v", scopeFileHostPath + ":/scope.txt:ro",
		"-e", "HF_SCOPE_FILE=/scope.txt",
		"-e", "HF_LISTEN_ADDR=0.0.0.0:" + proxyListenPort,
		"--entrypoint", "/hf-egressproxy",
	}
	args = append(args, commonContainerSecurityArgs()...)
	args = append(args, proxyImage)
	return args
}

func dockerCreateNetwork(ctx context.Context, name string, internal bool) error {
	args := []string{"network", "create"}
	if internal {
		args = append(args, "--internal")
	}
	args = append(args, name)
	if _, stderr, err := dockerCmdRunner(ctx, "", args...); err != nil {
		return fmt.Errorf("scriptexec: creating docker network %s: %w (%s)", name, err, stderr)
	}
	return nil
}

func dockerRemoveNetworkBestEffort(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _, _ = dockerCmdRunner(ctx, "", "network", "rm", name)
}

func dockerRemoveContainerBestEffort(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _, _ = dockerCmdRunner(ctx, "", "rm", "-f", name)
}

func dockerNetworkConnect(ctx context.Context, network, container string) error {
	if _, stderr, err := dockerCmdRunner(ctx, "", "network", "connect", network, container); err != nil {
		return fmt.Errorf("scriptexec: connecting %s to network %s: %w (%s)", container, network, err, stderr)
	}
	return nil
}

func dockerContainerIP(ctx context.Context, container, network string) (string, error) {
	format := fmt.Sprintf(`{{(index .NetworkSettings.Networks %q).IPAddress}}`, network)
	stdout, stderr, err := dockerCmdRunner(ctx, "", "inspect", "-f", format, container)
	if err != nil {
		return "", fmt.Errorf("scriptexec: inspecting %s: %w (%s)", container, err, stderr)
	}
	ip := strings.TrimSpace(stdout)
	if ip == "" {
		return "", fmt.Errorf("scriptexec: container %s has no address on network %s yet", container, network)
	}
	return ip, nil
}

// waitForContainerRunning polls `docker inspect` briefly for the sidecar to
// reach the "running" state before the script container starts relying on
// it — closing the startup race between the sidecar's process binding its
// listen port and the script container's first request.
func waitForContainerRunning(ctx context.Context, container string) error {
	deadline := time.Now().Add(5 * time.Second)
	for {
		stdout, _, err := dockerCmdRunner(ctx, "", "inspect", "-f", "{{.State.Running}}", container)
		if err == nil && strings.TrimSpace(stdout) == "true" {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("scriptexec: egress-proxy sidecar %s did not reach running state in time", container)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// proxyBinaryCache memoizes ensureEgressProxyBinary's cross-compile per
// (os.TempDir(), GOARCH) for this process's lifetime — every script.explore
// call in one `hackerfive agent` run reuses the same compiled sidecar
// binary instead of rebuilding it per script.
var proxyBinaryCache sync.Map // key: goarch string -> cached result

type proxyBinaryResult struct {
	path string
	err  error
}

// ensureEgressProxyBinary cross-compiles pkg/scriptexec/egressproxy/cmd/hf-
// egressproxy for the Docker daemon's own OS/architecture (always linux;
// the daemon's arch is queried via `docker version`) and returns its path,
// building it once and caching the result. This requires a Go toolchain on
// the machine running `hackerfive agent` — a real, deliberate limitation
// logged at docs/follow-up.md (a distributed release build would need to
// embed a prebuilt binary per target arch instead); until that's done,
// --allow-agent-scripts degrades to an error here rather than fabricating a
// working sandbox, on any machine without `go` on PATH.
func ensureEgressProxyBinary(ctx context.Context) (string, error) {
	arch, err := dockerServerArch(ctx)
	if err != nil {
		return "", err
	}
	if cached, ok := proxyBinaryCache.Load(arch); ok {
		res := cached.(proxyBinaryResult)
		return res.path, res.err
	}

	path, err := buildEgressProxyBinary(ctx, arch)
	proxyBinaryCache.Store(arch, proxyBinaryResult{path: path, err: err})
	return path, err
}

func dockerServerArch(ctx context.Context) (string, error) {
	stdout, stderr, err := dockerCmdRunner(ctx, "", "version", "--format", "{{.Server.Arch}}")
	if err != nil {
		return "", fmt.Errorf("scriptexec: querying docker server arch: %w (%s)", err, stderr)
	}
	arch := strings.TrimSpace(stdout)
	switch arch {
	case "amd64", "arm64":
		return arch, nil
	default:
		return "", fmt.Errorf("scriptexec: unsupported docker server arch %q (want amd64 or arm64)", arch)
	}
}

func buildEgressProxyBinary(ctx context.Context, goarch string) (string, error) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		return "", fmt.Errorf("scriptexec: building the egress-proxy sidecar requires a Go toolchain on PATH: %w", err)
	}

	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = os.TempDir()
	}
	outDir := filepath.Join(cacheDir, "hackerfive", "scriptexec")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", fmt.Errorf("scriptexec: preparing %s: %w", outDir, err)
	}
	outPath := filepath.Join(outDir, "hf-egressproxy-linux-"+goarch)
	if info, err := os.Stat(outPath); err == nil && info.Size() > 0 {
		return outPath, nil
	}

	pkgDir, err := thisModuleDir()
	if err != nil {
		return "", err
	}

	cmd := exec.CommandContext(ctx, goBin, "build", "-o", outPath, "./pkg/scriptexec/egressproxy/cmd/hf-egressproxy")
	cmd.Dir = pkgDir
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+goarch, "CGO_ENABLED=0")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("scriptexec: building egress-proxy sidecar: %w (%s)", err, stderr.String())
	}
	return outPath, nil
}

// thisModuleDir locates the hackerfive module root so buildEgressProxyBinary
// can run `go build` with the right working directory regardless of the
// caller's own cwd — resolved via runtime.Caller against this source file's
// known position (pkg/scriptexec/sandbox.go, two directories below the
// module root).
func thisModuleDir() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("scriptexec: could not resolve this package's source path")
	}
	return filepath.Dir(filepath.Dir(filepath.Dir(file))), nil
}

// runSandboxed is Execute's final stage, run only after Precheck passed and
// ApprovalGate approved: stand up a per-run --internal network plus an
// egress-proxy sidecar (attached to that internal network and, separately,
// to a normal network with real internet access), then run the script
// container attached ONLY to the internal network — its sole route anywhere
// is through the sidecar. Every resource created here (both networks, both
// containers) is torn down before returning, regardless of outcome.
func runSandboxed(ctx context.Context, req ScriptRequest) (ScriptResult, error) {
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = defaultScriptTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout+30*time.Second) // + setup/teardown budget
	defer cancel()

	if req.Scope == nil {
		return ScriptResult{}, errors.New("scriptexec: ScriptRequest.Scope is required — refusing to run with no egress allow-list")
	}

	id := runID()
	internalNet := "hf-scriptexec-int-" + id
	egressNet := "hf-scriptexec-egr-" + id
	proxyContainer := "hf-scriptexec-proxy-" + id
	scriptContainer := "hf-scriptexec-run-" + id

	proxyBinary, err := ensureEgressProxyBinary(ctx)
	if err != nil {
		return ScriptResult{}, err
	}
	scopeFile, cleanupScopeFile, err := writeScopeFile(req.Scope)
	if err != nil {
		return ScriptResult{}, err
	}
	defer cleanupScopeFile()

	if err := dockerCreateNetwork(ctx, internalNet, true); err != nil {
		return ScriptResult{}, err
	}
	defer dockerRemoveNetworkBestEffort(internalNet)
	if err := dockerCreateNetwork(ctx, egressNet, false); err != nil {
		return ScriptResult{}, err
	}
	defer dockerRemoveNetworkBestEffort(egressNet)

	proxyArgs := buildProxyContainerArgs(proxyContainer, internalNet, proxyBinary, scopeFile)
	if _, stderr, err := dockerCmdRunner(ctx, "", proxyArgs...); err != nil {
		return ScriptResult{}, fmt.Errorf("scriptexec: starting egress-proxy sidecar: %w (%s)", err, stderr)
	}
	defer dockerRemoveContainerBestEffort(proxyContainer)

	if err := dockerNetworkConnect(ctx, egressNet, proxyContainer); err != nil {
		return ScriptResult{}, err
	}
	if err := waitForContainerRunning(ctx, proxyContainer); err != nil {
		return ScriptResult{}, err
	}
	proxyIP, err := dockerContainerIP(ctx, proxyContainer, internalNet)
	if err != nil {
		return ScriptResult{}, err
	}
	proxyAddr := "http://" + proxyIP + ":" + proxyListenPort

	scriptArgs, err := buildScriptContainerArgs(req, scriptContainer, internalNet, proxyAddr)
	if err != nil {
		return ScriptResult{}, err
	}
	defer dockerRemoveContainerBestEffort(scriptContainer)

	scriptCtx, scriptCancel := context.WithTimeout(ctx, timeout)
	defer scriptCancel()
	stdout, stderr, runErr := dockerCmdRunner(scriptCtx, req.Source, scriptArgs...)

	result := ScriptResult{
		Stdout: truncate(stdout, maxCapturedOutput),
		Stderr: truncate(stderr, maxCapturedOutput),
	}
	result.Truncated = len(stdout) > maxCapturedOutput || len(stderr) > maxCapturedOutput

	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
			return result, nil // a non-zero exit is a normal script outcome, not a sandbox failure
		}
		if scriptCtx.Err() != nil {
			return result, fmt.Errorf("scriptexec: script exceeded its %s timeout", timeout)
		}
		return result, fmt.Errorf("scriptexec: running script container: %w", runErr)
	}
	return result, nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

func writeScopeFile(sc interface{ Entries() []string }) (path string, cleanup func(), err error) {
	f, err := os.CreateTemp("", "hackerfive-scriptexec-scope-*.txt")
	if err != nil {
		return "", nil, fmt.Errorf("scriptexec: creating scope file: %w", err)
	}
	defer func() { _ = f.Close() }()

	for _, entry := range sc.Entries() {
		if _, err := fmt.Fprintln(f, entry); err != nil {
			_ = os.Remove(f.Name())
			return "", nil, fmt.Errorf("scriptexec: writing scope file: %w", err)
		}
	}
	if err := f.Chmod(0o644); err != nil {
		_ = os.Remove(f.Name())
		return "", nil, fmt.Errorf("scriptexec: chmod scope file: %w", err)
	}
	return f.Name(), func() { _ = os.Remove(f.Name()) }, nil
}
