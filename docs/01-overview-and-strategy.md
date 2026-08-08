# Overview & Strategy

> Part of the [VulnDetector documentation set](../README.md).

**Project Name:** VulnDetector (Working Title)
**Goal:** Build an open-source, high-performance vulnerability scanner to participate in HackerOne bug bounty programs
**Phase 1 Launch:** ~10 weeks (IDOR + Misconfiguration)
**Full Product Launch:** ~26 weeks (all phases) — see [03-development-roadmap.md](03-development-roadmap.md) for the authoritative week-by-week schedule
**Last Updated:** August 2026

## Project Overview

### Mission
Build a **fast, extensible, open-source vulnerability detection engine** to automate security testing across APIs, web applications, and network services. The tool will be designed specifically to support bug bounty hunting on platforms like HackerOne, BugCrowd, and Intigriti.

### Why Now?
- **Market Opportunity:** HackerOne paid out $81M in bug bounties (2024-2025), a 13% increase year-over-year
- **Tool Gap:** Most existing scanners (Burp, ZAP) are either too slow, too complex, or too expensive for distributed bug hunters
- **Community:** Nuclei (27,000+ GitHub stars) proved that open-source, template-driven detection works; opportunity to build specialized tool for APIs and authorization flaws
- **Emerging Vulnerabilities:** Prompt injection grew 540% YoY; fewer specialized tools available → less competition

### Target Users
- **Primary:** Independent bug bounty hunters and small security teams
- **Secondary:** Startups needing affordable continuous security scanning
- **Tertiary:** Pentesting firms needing modular, customizable detection engine

## Market Analysis & Goals

### HackerOne Data (2024-2025 Report)

#### Most-Reported Vulnerabilities
| Rank | Vulnerability | Volume | Reward Trend | Notes |
|------|---------------|--------|--------------|-------|
| 1 | **Broken Access Control / IDOR** | 42% of all | ↑ +23% | Highest impact, growing focus |
| 2 | **Misconfiguration** | High | Stable | Easier to detect, lower false positives |
| 3 | **XSS (Cross-Site Scripting)** | Declining | ↓ Declining | Most tools find these; lower unique rewards |
| 4 | **Information Disclosure** | High | Stable | Medium effort, consistent bounties |
| 5 | **Prompt Injection (AI/ML)** | Rare | ↑↑ +540% | Emerging, least competition |
| 6 | **SSRF** | Medium | ↑ High reward | Complex, few automated tools |
| 7 | **SQL Injection** | Declining | ↓ Low | Mostly automated away by WAFs |
| 8 | **Authentication Bypass** | Medium | ↑ Growing | Multi-step exploits, high value |

#### Key Insights
- **For automation:** IDOR, misconfiguration, and prompt injection have highest reward-to-detection-effort ratio
- **For hunters using AI:** 67% of researchers now use AI/automation; hackbots (autonomous agents) submitted 560+ valid reports
- **For depth:** Business logic flaws and multi-step exploits still require human analysis but earn highest bounties

## Target Vulnerability Classes

*(Week ranges below are approximate — see [03-development-roadmap.md](03-development-roadmap.md) for the authoritative week-by-week schedule.)*

### Phase 1: Foundation (Weeks 1-10)
Focus on **high-volume, automatable** vulnerabilities where competitors have weak solutions.

#### 1. IDOR (Insecure Direct Object Reference)
- **Why First?** 42% of all vulnerabilities; 49% of critical/high-severity issues; +29% report growth
- **Detection Approach:**
  - Enumerate object IDs (users, orders, documents, etc.)
  - Test ID mutation (1→2, alice→bob, UUID permutation)
  - Compare HTTP responses (status, body hash, content length)
  - Flag if unauthorized user can access another's data
- **Template Format:** VulnDetector-native (baseline-mode two-account comparison has no Nuclei equivalent)
- **False Positive Rate:** Very low (response content differs significantly)
- **Automation Difficulty:** Medium (requires state awareness)
- **Estimated Effort:** 3 weeks

#### 2. Misconfiguration
- **Why Second?** Consistent discovery, low false positives, no payload complexity
- **Detections to Include:**
  - **Security Headers Missing:** Content-Security-Policy, X-Frame-Options, Strict-Transport-Security
  - **Default Credentials:** /admin, /admin123, /test:test
  - **Exposed Paths:** /.env, /.git, /debug, /.well-known/*, /swagger, /graphql
  - **Verbose Errors:** Stack traces, database errors, internal IPs
  - **HTTP Methods Misconfigured:** PUT/DELETE on endpoints that shouldn't allow them
  - **CORS Misconfiguration:** Access-Control-Allow-Origin: *
  - **S3 Bucket Exposure:** Public read/write on cloud storage
- **Detection Approach:** Fixed path + status code + keyword matching
- **Template Source:** Nuclei-compatible parser running the upstream `nuclei-templates` repo (MIT-licensed) directly — no local template fork
- **False Positive Rate:** Very low
- **Automation Difficulty:** Low (no fuzzing needed)
- **Estimated Effort:** 2 weeks

#### 3. API-Specific Auth Issues
- **Why Third?** APIs are growing attack surface; traditional scanners weak at API auth
- **Detections:**
  - **Missing Authentication:** Endpoints returning 200 without credentials
  - **Broken JWT:** Weak signatures, "none" algorithm, key injection
  - **Rate Limiting Bypass:** Rapid credential brute force without throttle
  - **Token Reuse:** Same token works across multiple accounts
  - **Broken Session:** Cookie/token not invalidated on logout
- **Detection Approach:** State-based requests (auth → access → compare)
- **False Positive Rate:** Medium (needs multi-step validation)
- **Automation Difficulty:** Medium-High (complex request sequencing)
- **Estimated Effort:** 3 weeks

### Phase 2: Expansion (Weeks 11-18)
Add detection engines for broader coverage.

#### 4. XSS (Cross-Site Scripting)
- **Context:** Historically #1 reported, but declining as most tools catch these
- **Approach:** Start with passive detection (build on Nuclei patterns) + browser-based validation if needed
- **Effort:** 2-3 weeks

#### 5. SQL Injection
- **Context:** Declining due to WAFs and parameterized queries, but still valuable in niche cases
- **Approach:** Template-based patterns + error matching
- **Effort:** 1-2 weeks

#### 6. Information Disclosure
- **Detections:**
  - API responses leaking unnecessary fields (internal IDs, timestamps, role info)
  - Verbose error messages revealing tech stack
  - Commented code in responses
- **Effort:** 1-2 weeks

### Phase 3: Specialization (Weeks 19-26)
Target emerging and high-value vulnerabilities.

#### 7. Prompt Injection (AI/ML Applications)
- **Why Important?** 540% surge in reports; least competition
- **Detections:**
  - Instruction injection bypasses system prompts
  - Token smuggling attacks
  - Data exfiltration via LLM chains
- **Effort:** 3-4 weeks (requires understanding of LLM behavior)

#### 8. SSRF (Server-Side Request Forgery)
- **Context:** Complex to automate, high reward
- **Approach:** Blind SSRF detection (via timing, DNS callback services)
- **Effort:** 3-4 weeks

#### 9. Business Logic Flaws
- **Context:** Requires deeper understanding of application flow
- **Examples:**
  - Price manipulation in e-commerce
  - Race conditions in payment processing
  - Workflow bypass (skip approval steps)
- **Approach:** Hardcoded patterns for common apps + extensible framework
- **Effort:** 4+ weeks (human analysis still needed)

## See also
- [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md) — how these detectors are implemented
- [03-development-roadmap.md](03-development-roadmap.md) — week-by-week plan to build this list
