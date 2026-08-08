# HackerOne & Bug Bounty Workflow, Security & Legal Considerations

> Part of the [VulnDetector documentation set](../README.md).

## Joining HackerOne & Bug Bounty Programs

### Prerequisites Before Joining

#### 1. **Legal & Ethical**
- [ ] Read HackerOne terms of service (https://hackerone.com/terms)
- [ ] Understand responsible disclosure
- [ ] Understand scope limitations (only test within authorized targets)
- [ ] Never access data you're not supposed to
- [ ] Do not disrupt services (DoS attacks prohibited)
- [ ] Sign up as individual if working solo

#### 2. **Tool Maturity**
- [ ] v0.2+ released (minimum IDOR + misconfiguration + XSS)
- [ ] <5% false positive rate validated
- [ ] Documentation complete
- [ ] Docker image available
- [ ] Performance tested (150+ req/sec)

#### 3. **Researcher Profile**
- [ ] Professional email (avoid free emails for initial credibility)
- [ ] LinkedIn profile (helps with program applications)
- [ ] GitHub profile with public contributions
- [ ] Basic portfolio (blog, write-ups, or past reports)

### Step 1: Join HackerOne

#### 1.1 Create Account
- Visit https://hackerone.com/users/sign_up
- Sign up as "Security Researcher"
- Complete profile:
  - Profile photo (professional)
  - Bio (2-3 sentences about your security focus)
  - Interests (API security, web security, authorization flaws)
  - Languages you speak
  - Experience level (select appropriate)

#### 1.2 Verify Identity
- Verify email address
- (Optional) Verify phone number for added credibility

#### 1.3 Customize Settings
- Notification preferences (important for staying on top of programs)
- Paypal or Stripe account (for receiving bounties)
- Tax information (HackerOne will send 1099 if earnings >$600)

### Step 2: Understand the Platform

#### 2.1 Browse Active Programs
- Filter by scope: **API Security, Web Application, Authentication**
- Filter by maturity level: Start with "default" or "not fully matured" programs (less competition, same or better payouts)
- Look for programs with:
  - Clear scope definition
  - High bounty payouts (median $500+)
  - Active response times (<1 week)
  - Recent activity (updated within last month)

#### 2.2 Read Program Scope
Each program defines:
- **In-Scope:**
  - Domains / APIs to test
  - Vulnerability types that count
  - Examples of what they've paid before
- **Out-of-Scope:**
  - Rate limiting, DoS, brute force (almost always OOS)
  - Third-party services
  - Physical security
  - Social engineering

**Rule:** If it's not explicitly in scope, don't test it.

### Step 3: Target Selection Strategy

#### 3.1 Programs Suitable for Automation
- **Emerging targets:** Not yet heavily scanned
- **Stable APIs:** Less likely to change scope
- **Large scopes:** More endpoints = more chance of bugs
- **API-heavy companies:** Web2.0 startups, SaaS platforms, fintech

#### 3.2 Programs to Avoid Early
- Huge companies (Microsoft, Google, Apple) — hyper-competitive
- Programs with low bounties (<$100) — not worth your time
- Programs with lots of resolved reports already (likely already scanned)

#### 3.3 Recommended Starting Targets
1. **Small-to-medium SaaS platforms** (Series A-C funding)
2. **Fintech/Crypto (if you specialize)** — higher payouts
3. **E-commerce platforms** — IDOR, auth, logic flaws common
4. **API-first companies** — your tool's sweet spot

### Step 4: Responsible Disclosure Workflow

#### 4.1 Test & Validate Finding
- [ ] Confirm vulnerability with tool
- [ ] Manually verify (use Burp or curl)
- [ ] Check severity: Is it exploitable? What's the impact?
- [ ] Document step-by-step reproduction

#### 4.2 Write HackerOne Report
Include:
- **Summary:** 1 sentence description
- **Vulnerability Details:** What, where, how
- **Step-by-Step Reproduction:** Copy-paste steps so they can verify
- **Proof of Concept (PoC):** Curl command, screenshot, or tool output
- **Impact:** What can attacker do? Data stolen? Privilege escalation?
- **Recommendations:** How to fix

**Example Report Structure:**
```
**Title:** IDOR in /api/users/{id} - Access to other users' data

**Description:**
The endpoint /api/users/{id} does not properly validate user 
authorization. An authenticated user can access data for other 
users by modifying the {id} parameter.

**Steps to Reproduce:**
1. Create account and authenticate
2. Send: GET /api/users/1 Authorization: Bearer {your_token}
3. Receive personal data
4. Change ID to 2: GET /api/users/2
5. Receive other user's email, phone, address

**PoC:**
curl -H "Authorization: Bearer ABC123" \
  https://api.target.com/api/users/2

**Impact:**
- Information Disclosure (PII leak)
- Potential account takeover if token reuse detected

**Recommendations:**
- Implement authorization check: verify user_id matches authenticated user
- Use UUIDs instead of sequential IDs
```

#### 4.3 Submit Report
- Go to program > "Submit Vulnerability"
- Fill in required fields
- Attach any proof (screenshots, HAR files)
- Submit

#### 4.4 Interact with Program
- Respond to clarification requests within 24 hours
- Provide additional PoCs if requested
- Be professional and patient
- Don't disclose publicly until they authorize

### Step 5: Building Your Portfolio

#### 5.1 Report Quality Matters
- Well-written reports get triaged faster
- First-time reporters have lower acceptance rate (~30-40%)
- Aim for clarity and professionalism

#### 5.2 Track Your Metrics
- Reports submitted
- Reports accepted
- Total bounties earned
- Average bounty per report
- Acceptance rate

#### 5.3 Build Reputation
- Respond to questions quickly
- Write public disclosures (after embargo ends) on Medium/Substack
- Contribute to open-source security projects
- Speak at local meetups or conferences

### Step 6: Scaling Your Efforts

#### 6.1 Use Your Tool Strategically
- Don't blast reports to every program
- Target programs where IDOR/misconfiguration are common
- Use tool to do initial reconnaissance
- Reserve human analysis for promising leads

#### 6.2 Diversify Programs
- Don't rely on one program (payouts vary)
- Join 5-10 programs at different maturity levels
- Participate in swags (VDP) alongside paid programs

#### 6.3 Continuous Learning
- Read accepted disclosures
- Study what other researchers find
- Improve your templates based on feedback
- Contribute templates back to community

### Expected Timeline & Earnings (Realistic)

| Phase | Timeframe | Effort | Expected Earnings |
|-------|-----------|--------|-------------------|
| **Setup & Tool Dev** | Weeks 1-12 | 20+ hrs/week | $0 (investment) |
| **First Reports** | Weeks 13-16 | 10 hrs/week | $200-500 |
| **Momentum** | Weeks 17-26 | 15 hrs/week | $1,500-3,000/month |
| **Mature (6+ months)** | Ongoing | Flexible | $3,000-10,000+/month |

**Notes:**
- First bounty typically takes 2-4 weeks after first report submission
- Average bug bounty: $500-1,500
- IDOR/auth flaws: $1,000-5,000
- Complex logic flaws: $5,000-20,000+
- Cryptocurrency/fintech: 2x average payouts

---

## Security & Legal Considerations

### Legal Requirements

#### 1. **Authorization**
- **ALWAYS** only test targets within a program's scope
- Never test outside scope without explicit written permission
- Unauthorized testing is illegal (Computer Fraud & Abuse Act in US, similar laws elsewhere)

#### 2. **Responsible Disclosure**
- Report vulnerabilities directly to the program (don't post publicly)
- Follow their timeline for patching (usually 90 days)
- Don't weaponize or sell exploits
- Don't use findings for personal gain (e.g., blackmail)

#### 3. **Data Handling**
- Don't retain PII longer than necessary
- Don't download large datasets
- Don't exfiltrate credentials or API keys
- Test with minimal data impact

#### 4. **Tax & Reporting**
- In the US, bounties are taxable income
- HackerOne sends 1099 for earnings >$600
- Keep records of all payments
- Consult a tax advisor if unsure

### Tool Security

#### 1. **No Malicious Payloads**
Your tool should:
- [ ] Never deploy shell code or reverse shells
- [ ] Never exfiltrate data
- [ ] Never modify target systems
- [ ] Only read/enumerate, never write/destroy

#### 2. **Secure Credential Handling**
```go
// Example: Store API keys securely
type Config struct {
	BearerToken string `envvar:"VULNDETECTOR_TOKEN"`
	APIKey      string `envvar:"VULNDETECTOR_API_KEY"`
}

// Load from environment, never hardcode
func LoadConfig() *Config {
	return &Config{
		BearerToken: os.Getenv("VULNDETECTOR_TOKEN"),
		APIKey:      os.Getenv("VULNDETECTOR_API_KEY"),
	}
}
```

#### 3. **Request Logging Best Practices**
- [ ] Log request/response headers (sanitize tokens/keys)
- [ ] Log URLs and methods
- [ ] Log timestamps and latencies
- [ ] Don't log response bodies (may contain PII)
- [ ] Provide --no-log-requests flag for users who want privacy

#### 4. **HTTPS/TLS Verification**
- Default: Verify certificates (fail if invalid)
- Provide --insecure flag only for testing local labs
- Don't auto-accept self-signed certs in production

### Ethical Considerations

#### 1. **Resource Usage**
- Limit concurrency (default 25, max 100) to avoid DoS
- Respect rate limits
- Add delays between targets
- Provide cooldown mechanisms

#### 2. **Scope Creep**
- Never test outside authorized scope
- If you discover something OOS, report it separately (don't exploit)
- Stop immediately if program asks you to

#### 3. **Honesty & Integrity**
- Report findings truthfully (don't exaggerate severity)
- Don't manufacture false positives
- Give program time to fix before public disclosure
- Don't sell findings to other buyers

## See also
- [03-development-roadmap.md](03-development-roadmap.md) — tool maturity gates required before joining HackerOne
- [06-metrics-resources-faq.md](06-metrics-resources-faq.md) — business metrics tracking bounty income
