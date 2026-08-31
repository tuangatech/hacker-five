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
- **Docker Desktop for Windows:** install with the WSL2 backend (selected by default) — Settings > General > "Use the WSL 2 based engine" — then, in Settings > Resources > WSL Integration: if Ubuntu is your only WSL distro (the normal case, since it's the first one installed above and Windows auto-defaults the first-ever distro), check **"Enable integration with my default WSL distro"** — that alone covers Ubuntu. Only reach for the separate **"Enable integration with additional distros"** toggle if Ubuntu *isn't* the default — e.g. you had another distro installed before this doc's `wsl --install -d Ubuntu` step, in which case that command didn't change the default. Run `wsl -l -v` (the `*` marks the default) if unsure which case applies.
  - Because the host CPU is already x86_64, all test images (including WebGoat) pull and run **natively** — no Rosetta-equivalent emulation step needed, and no platform flags required.
- **Git line endings:** if you ever touch files from the Windows side (VS Code's Windows binary, Explorer, etc.), set `core.autocrlf input` inside WSL2 (not from PowerShell/cmd) to avoid CRLF diffs — the repo's `.gitignore` and Go source expect LF:
  ```bash
  wsl                                        # enter the Ubuntu shell first — this setting lives in WSL2's own ~/.gitconfig
  git config --global core.autocrlf input
  ```

CI still builds and tests cross-platform (Linux, macOS, Windows) binaries via GitHub Actions — see [Continuous Integration](#continuous-integration) — but day-to-day local development happens on macOS (native shell) or Windows (inside WSL2's Ubuntu shell).

#### 2. **Install Go**
HackerFive's CLI and every detector are Go code — nothing in this repo builds, tests, or runs without a working Go toolchain.
```bash
# macOS (Homebrew) — installs the current stable release, native arm64 build
brew install go
go version  # Verify: go version go1.26.5 darwin/arm64
```
Homebrew on Apple Silicon installs to `/opt/homebrew` (not `/usr/local`). If `go version` isn't found after install, confirm your shell profile has `eval "$(/opt/homebrew/bin/brew shellenv)"` (the Homebrew installer adds this automatically on first run, but double-check on a fresh M4 machine).

```bash
# Windows — inside the WSL2 Ubuntu shell (not PowerShell)
wsl
```
Ubuntu's `apt` package (`golang-go`) is often several minor versions behind — in practice, on a fresh Ubuntu install, `apt` has resolved to go1.22.2, well short of this repo's `go.mod` requirement (`go 1.26.5`). Install from the official tarball instead:
```bash
# Check https://go.dev/dl/ for the current patch first — go1.26.6 as of writing (Aug 2026),
# which satisfies the go.mod directive since a module's `go` line is a *minimum*, not exact-match
curl -L -o go.tar.gz https://go.dev/dl/go1.26.6.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
go version  # Verify: go version go1.26.6 linux/amd64
```
(`sudo apt update && sudo apt install -y golang-go` is a faster shortcut *if* `apt`'s version happens to be current enough — check `go version` against `go.mod`'s requirement before relying on it; don't assume.) Avoid installing Go natively on the Windows side (`winget install -e --id GoLang.Go`) as your primary toolchain — it works, but then editors/terminals split across two filesystems (`C:\` vs `\\wsl$\`), which reintroduces the path and line-ending issues WSL2 is meant to avoid.

#### 3. **Install Git**
```bash
# macOS — ships with Xcode Command Line Tools, or install via Homebrew
xcode-select --install
# or
brew install git
```

```bash
# Windows — inside WSL2 Ubuntu
wsl
sudo apt update && sudo apt install -y git
```

#### 4. **Set Up GitHub Account**
- Create GitHub account if you don't have one
- Generate SSH key: `ssh-keygen -t ed25519 -C "anhtuantran@gmail.com"` (run inside WSL2 on Windows, so the key and `~/.ssh/config` live alongside the repo you'll clone)
- Add public key to GitHub (Settings > SSH Keys)

### Project Setup

The steps below (project skeleton, `go.mod`, `.gitignore`, CI workflow) were the original from-scratch bootstrap, done once during Phase 1a — see [09-implementation-plan-ph1a.md](09-implementation-plan-ph1a.md)'s Step 1. The repo already has all of it, and in some cases the real files have since evolved past this doc's original draft (e.g. `.github/workflows/ci.yml` now runs a macOS+Ubuntu matrix with newer action versions; `go.mod` carries the actual Phase 1a/1b dependency set, not the placeholder list originally sketched here — `github.com/json-iterator/go` in particular was deliberately *not* added, see [10-implementation-plan-ph1b.md](10-implementation-plan-ph1b.md)'s "Dependencies added in this plan"). Don't re-run `go mod init`, recreate `.gitignore`, or recreate the CI workflow from a stale copy here — read the actual files in the repo instead. The only step that still applies to a new checkout is cloning it:

```bash
git clone https://github.com/tuangatech/hacker-five.git
cd hacker-five
```

**Already cloned it on the Windows-side filesystem** (e.g. `C:\...`, visible from WSL2 as `/mnt/c/...`) and want to switch to WSL2's native filesystem for speed? Don't move the files — clone a second, independent copy into your Linux home instead (safe as long as everything's committed and pushed — check with `git status` and `git log origin/main..HEAD` first):
```bash
mkdir -p ~/projects && cd ~/projects   # a dedicated parent dir, not your home root — more will follow
git clone git@github.com:tuangatech/hacker-five.git   # SSH form, using the key set up in step 4 above
cd hacker-five
```
Your original `/mnt/c/...` checkout can stay as-is (e.g. as a Windows-side reference) or be deleted once you've confirmed the new clone works — everything else in this doc (Go, git config, SSH key, golangci-lint) is set up per-user in WSL2, not per-checkout, so none of it needs redoing for the new clone.

CI builds cross-platform release binaries (Linux, macOS, Windows). The Mac setup (native arm64) and Windows setup (WSL2, linux/amd64) each match one of those CI targets directly, so platform-specific bugs are easy to reproduce locally without a third machine.

### Local Development Tools

#### 1. **Code Linting**
Catches style, correctness, and staleness issues before CI does — `golangci-lint run ./...` is a required check in docs 09/10's Definition of Done, so running it locally saves a red CI run.
```bash
# macOS: Install golangci-lint (check https://golangci-lint.run for the current release before pinning —
# v2.13.1 as of writing; note the v2 line moved the module path to .../golangci-lint/v2)
brew install golangci-lint
golangci-lint --version  # confirm v2.x, native arm64 build
```
```bash
# Windows — inside WSL2 Ubuntu
wsl
curl -sSfL https://golangci-lint.run/install.sh | sh -s -- -b $(go env GOPATH)/bin v2.13.1

echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
golangci-lint --version  # confirm v2.x, linux/amd64
```
```bash
# Run linter (same command, either platform)
golangci-lint run ./...
```

#### 2. **Recon binaries** (`pkg/recon`, `hackerfive recon` — docs/14-implementation-plan-ph5.md Step 3)
Six ProjectDiscovery CLI tools recon shells out to with fixed arguments (same scoped-subprocess precedent as `pkg/templatesync`'s `git` call, not a general shell) — **not linked into this module's own `go.mod`**, each is installed as a standalone binary via `go install`, same class of prerequisite as `golangci-lint` above. A missing binary degrades that one wave to a logged `ReconResult.Warnings` entry, not a hard failure — these are optional for `go build`/`go test ./...` (CI itself doesn't have them installed either, which is exactly what exercises that degrade path), only needed for a live `hackerfive recon --recon-depth active|full` run.
```bash
# Verify current stable versions at https://github.com/projectdiscovery before pinning —
# @latest confirmed working versions as of 2026-08-30: subfinder v2.16.0, tlsx/dnsx/naabu/httpx/katana (current @latest)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
# each installs to $(go env GOPATH)/bin — same PATH entry golangci-lint above already needs
```
**Two real things found installing/running these, not assumed:** (1) `subfinder`'s own build pulls a large dependency tree (AWS/Azure SDKs, a Postgres driver, etc., for its cloud-source API-key config) — harmless here since `go install` builds it as a separate binary, never a dependency of this module's own `go.mod` (confirmed: `go.mod`/`go.sum` gained nothing from installing these). (2) `httpx`'s `-tech-detect` flag downloads a ~93MB Wappalyzer-based model file to `~/.dit/model.json` on its *first* invocation — a one-time, unannounced-until-it-happens network fetch, not a bug, but worth knowing about before a first `hackerfive recon --recon-depth active` run appears to hang.

**A real, deliberate gap, named rather than left for someone to discover silently:** the `Dockerfile` does not bundle any of these 6 binaries. `docker run hackerfive recon --recon-depth active` today only ever exercises Wave 0-1 (zero-touch + passive) — every active-wave binary is reported missing and that wave degrades to a `Warnings` entry, per the design above, not a hard failure. Installing them natively per this section (or building them into a custom image yourself) is currently the only way to exercise Wave 2/3 from inside a container. Not bundled this pass: meaningfully larger image size/build time for binaries most users, per this section's own instructions, install natively.

#### 3. **Testing Targets (Docker)**
Docker here serves two purposes: running the vulnerable targets to scan against, and (once you reach [09-implementation-plan-ph1a.md](09-implementation-plan-ph1a.md)/[10-implementation-plan-ph1b.md](10-implementation-plan-ph1b.md)'s verification steps) building/running HackerFive's own image (`docker build -t hackerfive:dev .`). Day-to-day `go build`/`go test`/`golangci-lint run` don't touch Docker at all.

Bring-up steps for each target (crAPI, DVWA, and what's not needed yet) live in [20-setup-testing-targets.md](20-setup-testing-targets.md) — identical on both platforms, since Docker Desktop abstracts the difference. This section only covers Docker/platform quirks that aren't target-specific:

**Mac:** if an image doesn't publish a `linux/arm64` variant, `docker pull --platform linux/amd64 <image>` runs it under Rosetta rather than the much slower QEMU fallback — but confirm Settings > General > "Use Rosetta for x86/amd64 emulation" is checked first, or Docker Desktop will silently use QEMU. Run `docker inspect <image> --format '{{.Architecture}}'` if a container feels unexpectedly slow to confirm which path it's using.

**Windows:** run `docker` and `docker compose` from inside the WSL2 Ubuntu shell (not PowerShell) so bind-mounted paths resolve the same way they do on the Mac/Linux instructions in this doc. `localhost:PORT` from a WSL2 container is reachable directly from the Windows browser — no extra port-forwarding needed with the WSL2 backend.

#### 4. **HTTP Interception (Debugging)**
```bash
# Option 1: Burp Suite Community
# Download from https://portswigger.net/burp/communitydownload
# Native installer for both macOS and Windows — install on the host OS, not inside WSL2

# Option 2: MitmProxy
pip install mitmproxy
mitmproxy --listen-host 127.0.0.1 --listen-port 8080

# Configure tool to use proxy (from the hackerfive repo root):
cd ~/hacker-five
./hackerfive scan -t http://localhost:8888 --proxy http://127.0.0.1:8080
```
On Windows, run `hackerfive` and `mitmproxy` inside WSL2 for consistency with the rest of this doc; `127.0.0.1` inside WSL2 is reachable from the Windows host, so pointing a Windows-native Burp at the same port works too.

#### 5. **Postman (Template Development)**
```bash
# Download from https://www.postman.com/downloads/
# Native installer for both macOS and Windows; use to test API endpoints before converting to YAML templates
```

### IDE Setup (Recommended)

#### **VS Code**

**macOS:**
```bash
code --install-extension golang.go

cat > .vscode/settings.json << 'EOF'
{
  "go.lintTool": "golangci-lint",
  "go.lintOnSave": "package",
  "go.formatTool": "goimports",
  "editor.formatOnSave": true
}
EOF
```

**Windows — recommended workflow: VS Code opens the WSL2 repo directly, no edit-on-Windows-then-push/pull round trip.** Editing the Windows-side filesystem and syncing to WSL2 via git only adds friction and risk (two clones to keep straight, no working Go toolchain on the Windows side to build/test against anyway). Instead:

1. Install VS Code natively on Windows (once), then add the **Remote - WSL** extension:
   ```powershell
   code --install-extension ms-vscode-remote.remote-wsl
   ```
2. Open the repo *from inside the WSL2 Ubuntu shell*, not via Windows Explorer or VS Code's own "Open Folder":
   ```bash
   wsl
   cd ~/projects/hacker-five
   code .
   ```
3. VS Code reopens in a new window — check the bottom-left green indicator reads **"WSL: Ubuntu"** before doing anything else. Extensions installed from here go *into* that WSL window, separately from your main Windows-side VS Code install.
4. Inside that WSL window's integrated terminal, install the Go extension and project settings:
   ```bash
   code --install-extension golang.go

   cat > .vscode/settings.json << 'EOF'
   {
     "go.lintTool": "golangci-lint",
     "go.lintOnSave": "package",
     "go.formatTool": "goimports",
     "editor.formatOnSave": true
   }
   EOF
   ```

From this point on, the integrated terminal, file editing, file watching, and Go tooling all run inside WSL2 against `~/projects/hacker-five` directly — `go build`, `go test`, `golangci-lint run`, `git` all just work from the same terminal, instead of against the slower, path-mismatched `\\wsl$\...` network share.

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

# 2b. Run the Phase 5 eval harness (docs/14-implementation-plan-ph5.md Step 1) —
#     same opt-in-per-target convention as above, plus a binary pass/fail per
#     challenge against tests/fixtures/expected-findings/*.json
make eval

# 2c. Run the Phase 5 recon phase standalone (docs/14-implementation-plan-ph5.md
#     Step 3) — no agent required; needs the recon binaries above installed
#     for anything beyond Wave 0-1 (passive) to produce real Wave 2-3 facts
hackerfive recon -t http://localhost:8888 --recon-depth full --scope path/to/scope.txt

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
