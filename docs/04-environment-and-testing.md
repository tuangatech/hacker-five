# Development Environment & Testing Strategy

> Part of the [HackerFive documentation set](../README.md).

## Development Environment Setup

### Prerequisites

The team develops on a mix of **macOS (Apple Silicon)** and **Windows 11** laptops. Both are first-class; pick the block below for your machine. Shell commands throughout the rest of this doc (`mkdir -p`, `touch`, `cat <<EOF`, etc.) assume a POSIX shell — on Windows that means running everything inside **WSL2**, not PowerShell/cmd, so commands can be copy-pasted as-is and behave the same as on macOS and in CI (`ubuntu-latest`).

#### 1. **System Requirements**

**macOS (Apple Silicon: M4/M4 Pro/M4 Max)**
- **OS:** macOS 14 (Sonoma) or later; macOS 14.1+ ships with Rosetta's Docker integration enabled by default
- **RAM:** 16GB minimum (base M4). If you run crAPI's full Compose stack alongside another vulnerable target (e.g. DVWA + WebGoat under Rosetta) at the same time, 24GB+ is noticeably smoother — Docker VM + amd64 emulation both compete for the same unified memory pool.
- **Disk:** 20GB free space (more if pulling several amd64 images — Rosetta-emulated images aren't cached smaller than native ones)
- **Rosetta 2:** install it once, up front, so Docker's amd64 emulation actually works:
  ```bash
  softwareupdate --install-rosetta --agree-to-license
  ```
- **Docker Desktop for Mac (Apple Silicon build):** required for vulnerable test targets.
  - "Use Rosetta for x86/amd64 emulation" (Settings > General) is on by default on macOS 14.1+ — verify it's checked; some test images (e.g. WebGoat) only publish amd64 builds and silently fall back to slow QEMU emulation if it's off.
  - Set file sharing implementation to **VirtioFS** (Settings > General) — it's the default on modern Docker Desktop and is 2–5x faster than the legacy gRPC-FUSE backend for bind-mounted repo directories.
  - If running multiple compose stacks concurrently, bump Settings > Resources to at least 8GB RAM / 4 CPUs for Docker Desktop itself.

**Windows 11**
- **OS:** Windows 11 (any edition — Home, Pro, Enterprise all support WSL2), hardware virtualization enabled in BIOS/UEFI
- **RAM:** 16GB minimum, 24GB+ if running multiple compose stacks concurrently — WSL2's VM and Docker containers share the same allocation
- **Disk:** 20GB+ free; the WSL2 virtual disk (`.vhdx`) grows dynamically as you pull images, so leave headroom beyond the base 20GB
- **WSL2 + Ubuntu:** install and set as default, then reboot:
  ```powershell
  wsl --install -d Ubuntu
  wsl --set-default-version 2
  ```
  All Go/Git/Docker work below happens *inside* this Ubuntu shell — it's your dev environment, not the Windows host. This is what gives parity with the Mac/Linux instructions in this doc without a second, PowerShell-flavored copy of every command.
- **Docker Desktop for Windows:** install with the WSL2 backend (selected by default) — Settings > General > "Use the WSL 2 based engine" — then enable Settings > Resources > WSL Integration for your Ubuntu distro so `docker`/`docker compose` work from inside it.
  - Because the host CPU is already x86_64, all test images (including WebGoat) pull and run **natively** — no Rosetta-equivalent emulation step needed, and no platform flags required.
- **Git line endings:** if you ever touch files from the Windows side (VS Code's Windows binary, Explorer, etc.), set `git config --global core.autocrlf input` inside WSL2 to avoid CRLF diffs — the repo's `.gitignore` and Go source expect LF.

CI still builds and tests cross-platform (Linux, macOS, Windows) binaries via GitHub Actions — see [Continuous Integration](#continuous-integration) — but day-to-day local development happens on macOS (native shell) or Windows (inside WSL2's Ubuntu shell).

#### 2. **Install Go**
```bash
# macOS (Homebrew) — installs the current stable release, native arm64 build
brew install go
go version  # Verify: go version go1.26.5 darwin/arm64
```
Homebrew on Apple Silicon installs to `/opt/homebrew` (not `/usr/local`). If `go version` isn't found after install, confirm your shell profile has `eval "$(/opt/homebrew/bin/brew shellenv)"` (the Homebrew installer adds this automatically on first run, but double-check on a fresh M4 machine).

```bash
# Windows — inside the WSL2 Ubuntu shell (not PowerShell), install the linux/amd64 build via apt or the official tarball
sudo apt update && sudo apt install -y golang-go
go version  # Verify: go version go1.26.5 linux/amd64
```
If `apt`'s Go package lags behind 1.26.5, install from the official tarball at https://go.dev/dl/ instead (check for the current release before pinning). Avoid installing Go natively on the Windows side (`winget install -e --id GoLang.Go`) as your primary toolchain — it works, but then editors/terminals split across two filesystems (`C:\` vs `\\wsl$\`), which reintroduces the path and line-ending issues WSL2 is meant to avoid.

#### 3. **Install Git**
```bash
# macOS — ships with Xcode Command Line Tools, or install via Homebrew
xcode-select --install
# or
brew install git
```

```bash
# Windows — inside WSL2 Ubuntu
sudo apt update && sudo apt install -y git
```

#### 4. **Set Up GitHub Account**
- Create GitHub account if you don't have one
- Generate SSH key: `ssh-keygen -t ed25519 -C "your_email@example.com"` (run inside WSL2 on Windows, so the key and `~/.ssh/config` live alongside the repo you'll clone)
- Add public key to GitHub (Settings > SSH Keys)

### Project Setup

#### 1. **Clone/Initialize Repository**
```bash
# Clone if forking from existing repo
git clone https://github.com/tuangatech/hacker-five.git
cd hacker-five

# Or initialize new project
mkdir hacker-five
cd hacker-five
git init
go mod init github.com/tuangatech/hacker-five
```

#### 2. **Create Project Structure**
```bash
mkdir -p cmd/hackerfive pkg/{scanner,detectors,template,reporter} templates/{idor,misconfig} tests

# Create main entry point
touch cmd/hackerfive/main.go
```

#### 3. **Initialize Go Modules**
```bash
go mod init github.com/tuangatech/hacker-five
go get github.com/spf13/cobra
go get gopkg.in/yaml.v3
go get github.com/json-iterator/go
```
Before adding a regex dependency for the matcher engine, check whether the standard library `regexp` (RE2) is sufficient — it's arm64-native and avoids cgo, which matters for reproducible cross-compiled CI builds. Only reach for a third-party engine (e.g. `github.com/dlclark/regexp2`) if a template genuinely needs PCRE-only features (backreferences, lookahead) that RE2 can't express.

#### 4. **Create .gitignore**
```bash
# Binaries
/hackerfive
*.exe
*.dll
*.so

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# Go
vendor/

# OS
.DS_Store
Thumbs.db
*.log

# Test outputs
coverage.out
*.test
```
Two fixes from an earlier draft of this list: the binary entry needs the leading `/` — a bare `hackerfive` pattern matches *any* path component named `hackerfive` anywhere in the tree, which silently excludes the whole `cmd/hackerfive/` source directory (see [09-implementation-plan-ph1a.md](09-implementation-plan-ph1a.md)'s package layout) since gitignore patterns without a leading slash match at every directory level, not just the repo root. And `go.sum` is deliberately *not* listed — this is an application, not a library, so `go.sum` should be committed for reproducible builds (`go mod download`/CI/goreleaser all rely on it matching what's checked in).

#### 5. **Set Up GitHub Actions (CI/CD)**
Create `.github/workflows/ci.yml`:
```yaml
name: CI

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v4
        with:
          go-version: '1.26.5'
      - run: go test -v -race -coverprofile=coverage.out ./...
      - run: go vet ./...
      - run: golangci-lint run
```

CI builds cross-platform release binaries (Linux, macOS, Windows). The Mac setup (native arm64) and Windows setup (WSL2, linux/amd64) each match one of those CI targets directly, so platform-specific bugs are easy to reproduce locally without a third machine.

### Local Development Tools

#### 1. **Code Linting**
```bash
# macOS: Install golangci-lint (check https://golangci-lint.run for the current release before pinning —
# v2.12.2 as of writing; note the v2 line moved the module path to .../golangci-lint/v2)
brew install golangci-lint
golangci-lint --version  # confirm v2.x, native arm64 build
```
```bash
# Windows — inside WSL2 Ubuntu
curl -sSfL https://golangci-lint.run/install.sh | sh -s -- -b $(go env GOPATH)/bin v2.12.2
golangci-lint --version  # confirm v2.x, linux/amd64
```
```bash
# Run linter (same command, either platform)
golangci-lint run ./...
```

#### 2. **Testing Targets (Docker)**
All commands use `docker compose` (v2, no hyphen) — the standalone `docker-compose` (v1) binary reached end-of-life in 2024 and isn't shipped by current Docker Desktop; v2 ships as a plugin and is what both the Mac and Windows/WSL2 installs actually have available.
```bash
# Juice Shop and DVWA publish native arm64 images — no emulation needed on Mac; native on Windows/WSL2 too
docker pull bkimminich/juice-shop
docker pull vulnerables/web-dvwa

# WebGoat/goatandwolf is amd64-only — needs Rosetta on Mac; runs natively on Windows/WSL2, no flag needed there
docker pull --platform linux/amd64 webgoat/goatandwolf

# Run crAPI (API testing) — docker compose pulls per-service images, mostly multi-arch
git clone https://github.com/OWASP/crAPI.git
cd crAPI/deploy && docker compose up

# Access at http://localhost:8888
```
**Mac:** if an image doesn't publish a `linux/arm64` variant, `docker pull --platform linux/amd64 <image>` runs it under Rosetta rather than the much slower QEMU fallback — but confirm Settings > General > "Use Rosetta for x86/amd64 emulation" is checked first, or Docker Desktop will silently use QEMU. Run `docker inspect <image> --format '{{.Architecture}}'` if a container feels unexpectedly slow to confirm which path it's using.

**Windows:** run `docker` and `docker compose` from inside the WSL2 Ubuntu shell (not PowerShell) so bind-mounted paths resolve the same way they do on the Mac/Linux instructions in this doc. `localhost:PORT` from a WSL2 container is reachable directly from the Windows browser — no extra port-forwarding needed with the WSL2 backend.

#### 3. **HTTP Interception (Debugging)**
```bash
# Option 1: Burp Suite Community
# Download from https://portswigger.net/burp/communitydownload
# Native installer for both macOS and Windows — install on the host OS, not inside WSL2

# Option 2: MitmProxy
pip install mitmproxy
mitmproxy --listen-host 127.0.0.1 --listen-port 8080

# Configure tool to use proxy:
hackerfive scan -t http://localhost:8888 --proxy http://127.0.0.1:8080
```
On Windows, run `hackerfive` and `mitmproxy` inside WSL2 for consistency with the rest of this doc; `127.0.0.1` inside WSL2 is reachable from the Windows host, so pointing a Windows-native Burp at the same port works too.

#### 4. **Postman (Template Development)**
```bash
# Download from https://www.postman.com/downloads/
# Native installer for both macOS and Windows; use to test API endpoints before converting to YAML templates
```

### IDE Setup (Recommended)

#### **VS Code**
```bash
# Install Go extension
code --install-extension golang.go

# Create .vscode/settings.json
cat > .vscode/settings.json << 'EOF'
{
  "go.lintTool": "golangci-lint",
  "go.lintOnSave": "package",
  "go.formatTool": "goimports",
  "editor.formatOnSave": true
}
EOF
```
**Windows:** install VS Code natively on Windows, then add the **Remote - WSL** extension (`code --install-extension ms-vscode-remote.remote-wsl`) and open the repo with `code .` *from inside the WSL2 Ubuntu shell*, in the repo's WSL2 path (e.g. `/home/you/hackerfive`). This runs the Go extension, terminal, and file watching inside WSL2 — the same environment used for `go build`/`docker`/`git` above — instead of against the slower, path-mismatched `\\wsl$\...` network share.

#### **GoLand / IntelliJ IDEA**
- Built-in Go support
- File > New > Project > Go
- Automatically configures for GOPATH

---

## Testing Strategy

### Unit Testing

#### Test Structure
```
tests/
├── unit/
│   ├── detector_idor_test.go
│   ├── detector_misconfig_test.go
│   ├── template_parser_test.go
│   └── matcher_test.go
├── integration/
│   ├── scanner_test.go
│   └── e2e_test.go
└── fixtures/
    ├── payloads.json
    ├── responses/
    └── templates/
```

#### Example Unit Test (IDOR Detector)
```go
package unit

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"yourmodule/pkg/detectors"
)

func TestIDORDetector_SimpleSequentialIDs(t *testing.T) {
	detector := detectors.NewIDORDetector()
	
	// Mock responses: ID 1 returns {"user": "alice", "id": 1}, 
	// ID 2 returns {"user": "bob", "id": 2}
	findings := detector.Test("http://localhost:8888/api/users/", AuthToken)
	
	assert.Greater(t, len(findings), 0)
	assert.Equal(t, "IDOR", findings[0].Type)
	assert.Equal(t, "high", findings[0].Severity)
}
```

### Integration Testing

#### Against Vulnerable Applications

| Target | Endpoint | Expected Findings | Command |
|--------|----------|-------------------|---------|
| **crAPI** | `/dashboard` | IDOR (vehicle access) | `hackerfive scan -t http://localhost:8888 --template idor/` |
| **DVWA** | `/vulnerabilities/` | Misc (SQL injection, XSS) | `hackerfive scan -t http://localhost/DVWA --template misconfig/` |
| **Juice Shop** | `/api/` | XSS, Auth bypass, IDOR | `hackerfive scan -t http://localhost:3000 --template xss/` |

#### Test Execution Plan
```bash
# 1. Start vulnerable apps
docker compose up -d

# 2. Run integration tests
go test -v -tags=integration ./tests/integration/...

# 3. Compare against expected findings (false positive check)
hackerfive scan -t http://localhost:8888 --json > findings.json
python3 scripts/validate_findings.py findings.json

# 4. Measure performance
time hackerfive scan -t http://localhost:8888 -c 50
```

### Performance Benchmarking

```go
// Benchmark concurrent request handling
func BenchmarkWorkerPool(b *testing.B) {
	pool := NewWorkerPool(25)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 1000; j++ {
			pool.Submit(mockTask)
		}
	}
}
```

**Target Metrics:**
- 150+ requests/second (single target)
- <100ms latency per request (p95)
- Memory usage <100MB for 1000 concurrent requests
- Scan 100 targets in <2 minutes (with 25 workers)

On the Mac, `go test -bench` numbers reflect native arm64 performance directly — no emulation involved for the binary under test (only Docker-hosted amd64-only targets like WebGoat run under Rosetta, which affects the target's response latency, not the scanner's). For memory/CPU profiling beyond `go test -benchmem`, `Activity Monitor` or `sudo powermetrics --samplers cpu_power -i 1000` give per-core and power figures across the M4's performance/efficiency cores.

On Windows, run benchmarks inside WSL2 — the scanner binary is native linux/amd64 there too, so numbers are directly comparable to CI's `ubuntu-latest` runner (more so than the Mac's arm64 numbers). Use `htop` (`sudo apt install -y htop`) inside the WSL2 shell for live CPU/memory, rather than Windows Task Manager, which shows the whole WSL2 VM as one process and won't break down per-goroutine-pool usage.

`pprof` (`go tool pprof`) remains the primary tool for allocation and CPU profiles on both platforms.

### Manual Testing Checklist

- [ ] CLI argument parsing works
- [ ] Proxy routing works (test with MitmProxy)
- [ ] Authentication handling works (Bearer tokens, API keys)
- [ ] Rate limiting is respected
- [ ] Output formats are correct (JSON, Markdown, HTML)
- [ ] Handles network timeouts gracefully
- [ ] Finds expected vulnerabilities in crAPI
- [ ] Finds expected vulnerabilities in DVWA
- [ ] False positive rate <5%
- [ ] No crashes on malformed input

### Continuous Integration

Use GitHub Actions to automatically:
- Run unit tests on every push
- Run linting (golangci-lint)
- Build Docker image
- Run integration tests against vulnerable apps
- Generate coverage reports
- Build cross-platform binaries (Linux, macOS, Windows)

## See also
- [03-development-roadmap.md](03-development-roadmap.md) — where each week's deliverable gets validated by this test plan
- [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md) — components under test
