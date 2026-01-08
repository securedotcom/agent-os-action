# Agent-OS Security Action

> **GitHub Action for Production Security Scanning**
> Orchestrates TruffleHog, Semgrep, Trivy, Checkov + AI triage + policy gates

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](#contributing)
[![AI-Powered](https://img.shields.io/badge/AI-Claude%20%7C%20OpenAI-blue.svg)](#ai-triage-options)

---

## What It Does

**Runs multiple security scanners, applies AI triage to suppress false positives, and blocks PRs only on verified, high-confidence threats.**

- **Multi-Scanner**: TruffleHog, Semgrep, Trivy, Checkov in parallel
- **AI Triage**: Claude (Anthropic) or OpenAI for intelligent noise reduction
- **Smart Blocking**: Only fails on verified secrets, critical CVEs, and high-confidence SAST findings
- **60% Noise Reduction**: ML-powered false positive suppression
- **Intelligent Caching**: 10-100x faster repeat scans with smart caching
- **Real-Time Progress**: Live progress bars for all scanning operations

---

## Quick Start (3 minutes)

### 1. Add Workflow File

Create `.github/workflows/agent-os.yml`:

```yaml
name: Agent-OS Security
on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: securedotcom/agent-os-action@v1
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

### 2. Add API Key

- Add `ANTHROPIC_API_KEY` in Settings → Secrets for Claude analysis (~$0.35/run)
- Alternatively, use `OPENAI_API_KEY` for OpenAI GPT-4 analysis
- For free local analysis, use Ollama (see [Configuration](#configuration))

### 3. Open a PR

Agent-OS will comment with security findings, suppressing test files and low-confidence issues.

**Done!** 🎉

---

## Sample Output

When Agent-OS scans your PR, it comments with actionable findings:

```markdown
## 🔍 Agent-OS Security Report

**Analysis Complete**: 4 findings (2 actionable, 2 suppressed)

### 🔴 Critical: Verified Secret Exposed
**File**: `config/database.yml`  
**Line**: 42  
**Risk Score**: 95/100  
**Exploitability**: Trivial  

AWS access key verified via API validation. Immediate rotation required.

**Remediation**: Rotate key immediately and use AWS Secrets Manager.

---

### ⚠️  High: SQL Injection Risk
**File**: `app/controllers/users_controller.rb`  
**Line**: 156  
**Risk Score**: 78/100  

User input directly concatenated into SQL query.

**Suggested Fix**:
# BEFORE
User.where("email = '#{params[:email]}'")

# AFTER
User.where(email: params[:email])

---

### ℹ️ Suppressed Findings (2)
- `test/fixtures/sample_secret.txt` - Test file (noise score: 0.89)
- `docs/examples/api_key_format.md` - Documentation (noise score: 0.72)

---

**Metrics**:
- Files Analyzed: 247
- Duration: 3.2 minutes
- Cost: $0.32 (Claude Sonnet)
- Noise Reduction: 67% (6 findings → 2 actionable)
```

See full example: [examples/reports/sample-pr-comment.md](examples/reports/sample-pr-comment.md)

---

## How It Works

| Aspect | Details |
|--------|---------|
| **Scanners Orchestrated** | **TruffleHog** (verified secrets), **Semgrep** (SAST, 2000+ rules), **Trivy** (CVE scanning), **Checkov** (IaC security). Note: GitLeaks is a paid tool and not included. |
| **AI Analysis** | **Claude Sonnet** (Anthropic, ~$0.35/run) or **OpenAI GPT-4** (~$0.40/run). For free local option, use **Ollama** (requires self-hosted runner). |
| **Data Handling** | All scanning runs **in your GitHub Actions runner**. Optional: API calls to Anthropic/OpenAI if using cloud AI (code snippets for context only). **No telemetry, no data collection**. |
| **Permissions Required** | `contents: read` (scan code), `pull-requests: write` (comment), `actions: read` (upload artifacts). Optional: `contents: write` (create audit PRs) |
| **Runtime** | **<5 minutes** for typical repos (p95). Scales linearly with repo size. Parallelized scanning with intelligent caching for 10-100x speedup on repeat scans. |
| **Cost** | **$0.20-0.50** with Claude/OpenAI (depends on findings count), **$0.00** with Ollama (local, requires self-hosted runner) |
| **Noise Reduction** | **60-70%** false positive suppression via ML scoring + historical analysis |
| **When It Blocks** | Only on: **(1)** Verified secrets (API-validated), **(2)** Critical CVEs with known exploits, **(3)** High-confidence SAST findings (low noise score). Customizable via Rego policies. |

---

## AI Triage Options

Agent-OS uses AI to reduce noise and assess exploitability. Choose one:

| Option | Cost | Quality | Setup |
|--------|------|---------|-------|
| **Claude Sonnet** (Recommended) | ~$0.35/run | ⭐⭐⭐⭐⭐ | Requires `ANTHROPIC_API_KEY` |
| **OpenAI GPT-4** | ~$0.40/run | ⭐⭐⭐⭐⭐ | Requires `OPENAI_API_KEY` |
| **Ollama** (Free) | $0 | ⭐⭐⭐ | Requires self-hosted runner with GPU/CPU model |

**Recommendation**: Use Claude Sonnet for best results. For cost-conscious teams with self-hosted infrastructure, Ollama provides free local inference.

---

## Configuration

### Basic Options

```yaml
- uses: securedotcom/agent-os-action@v1
  with:
    # Review type: audit (full), security (secrets+CVE), review (PR-only)
    review-type: 'audit'
    
    # Fail PR if blockers found (default: true)
    fail-on-blockers: 'true'
    
    # Comment on PR with results (default: true)
    comment-on-pr: 'true'
    
    # AI provider: anthropic, openai, ollama (default: auto)
    ai-provider: 'auto'
    
    # Enable Semgrep SAST (default: true)
    semgrep-enabled: 'true'
```

### Advanced Options

```yaml
- uses: securedotcom/agent-os-action@v1
  with:
    # Only analyze changed files in PRs
    only-changed: 'true'
    
    # Max files to analyze (cost control)
    max-files: '50'
    
    # Cost limit in USD
    cost-limit: '1.0'
    
    # Exploit analysis (Aardvark mode)
    enable-exploit-analysis: 'true'
    
    # Auto-generate security tests
    generate-security-tests: 'true'
    
    # Block threshold: trivial, moderate, complex
    exploitability-threshold: 'trivial'
```

Full configuration reference: [PLATFORM.md#configuration](PLATFORM.md#configuration)

---

## Common Use Cases

### 1. PR Security Gate

Block PRs with verified secrets or critical vulnerabilities:

```yaml
name: PR Security Gate
on:
  pull_request:
    branches: [main, develop]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: securedotcom/agent-os-action@v1
        with:
          review-type: 'security'
          fail-on-blockers: 'true'
          only-changed: 'true'
```

### 2. Scheduled Full Audit

Weekly security audit of entire codebase:

```yaml
name: Weekly Security Audit
on:
  schedule:
    - cron: '0 2 * * 0'  # Sundays at 2 AM

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: securedotcom/agent-os-action@v1
        with:
          review-type: 'audit'
          fail-on-blockers: 'false'  # Don't fail, just report
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

### 3. Multi-Agent Parallel Analysis

Run multiple specialized agents in parallel:

```yaml
- uses: securedotcom/agent-os-action@v1
  with:
    multi-agent-mode: 'parallel'
    enable-exploit-analysis: 'true'
    generate-security-tests: 'true'
```

More examples: [examples/workflows/](examples/workflows/)

---

## Why Agent-OS?

### vs Manual Security Scanning

| Challenge | Manual Approach | Agent-OS |
|-----------|----------------|----------|
| **False Positives** | 100+ noisy findings | 60% suppressed, ~40 actionable |
| **Context** | Raw tool output | AI-explained with fix suggestions |
| **Prioritization** | All treated equal | Risk-scored: CVSS × Exploitability × Reachability |
| **Coverage** | Run 1-2 tools | 4 tools orchestrated + correlated |
| **Cost** | Dev time to triage | $0-0.35 automated |

### vs Generic GitHub Actions

| Feature | Generic Scanner Actions | Agent-OS |
|---------|------------------------|----------|
| **Noise Reduction** | ❌ Raw output | ✅ ML-powered suppression |
| **Correlation** | ❌ Isolated findings | ✅ Exploit chain detection |
| **Smart Blocking** | ❌ All findings block | ✅ Only verified threats |
| **Fix Suggestions** | ❌ Manual research | ✅ AI-generated remediations |
| **Compliance** | ❌ DIY | ✅ SOC2, PCI-DSS policy packs |

---

## When to Use Agent-OS

### ✅ Perfect For

**You should use Agent-OS if you want to:**

- ✅ **Block PRs with verified secrets** (not just pattern matches)
- ✅ **Reduce security alert noise** by 60-70% automatically
- ✅ **Get AI-generated fix suggestions** for vulnerabilities
- ✅ **Run multiple scanners** without managing each separately
- ✅ **Enforce security policies** via Rego gates
- ✅ **Generate SBOMs** for supply chain transparency
- ✅ **Zero-cost security scanning** (with Ollama on self-hosted runners)
- ✅ **Enterprise compliance** (SOC2, PCI-DSS)

**Ideal Teams:**

| Team Type | Why Agent-OS Fits |
|-----------|-------------------|
| **Startups** | Low cost (~$0.35/scan), easy setup, production-ready |
| **Scale-ups** | Handles repos at scale, multi-repo support, cost-efficient |
| **Enterprises** | Compliance packs, policy enforcement, self-hosted option |
| **Security Teams** | Comprehensive scanning, prioritization, metrics |
| **DevOps Teams** | CI/CD integration, automated gates, low maintenance |

### ❌ Not Ideal For

**Consider alternatives if you:**

- ❌ **Need runtime security** (Agent-OS is static analysis only)
- ❌ **Want dynamic testing** (use DAST tools like OWASP ZAP)
- ❌ **Need penetration testing** (hire pen testers)
- ❌ **Want network security** (use Wiz, Lacework, etc.)
- ❌ **Need real-time monitoring** (use Datadog, Sentry, etc.)
- ❌ **Have <10 PRs/month** (GitHub's free tools may suffice)
- ❌ **Can't use GitHub Actions** (use CLI mode instead)

**What Agent-OS Doesn't Do:**

| What It's NOT | What to Use Instead |
|---------------|---------------------|
| Dynamic Application Security Testing (DAST) | OWASP ZAP, Burp Suite |
| Runtime monitoring | Datadog, Sentry, New Relic |
| Network security | Wiz, Lacework, Prisma Cloud |
| Penetration testing | Professional pen testers |
| Container runtime security | Falco, Aqua, Sysdig |
| Web Application Firewall (WAF) | Cloudflare, AWS WAF |

**Best Practice**: Use Agent-OS *alongside* these tools, not instead of them. Agent-OS excels at **shift-left security** (catching issues before production).

---

## Comparison: Agent-OS vs Alternatives

### vs Running Scanners Manually

| Aspect | Manual (Trivy + Semgrep + TruffleHog) | Agent-OS |
|--------|--------------------------------------|----------|
| **Setup Time** | 2-4 hours per repo | 3 minutes (copy YAML) |
| **Raw Findings** | 50-200+ per scan | 3-10 actionable (60-70% noise reduction) |
| **Triage Time** | 2-4 hours/week | Automated (0 hours) |
| **Fix Guidance** | Manual research | AI-generated suggestions |
| **Policy Enforcement** | Manual review | Automated Rego gates |
| **Cost** | Engineer time ($100+/hr) | $0-0.35 per scan |
| **Maintenance** | Update each tool | Single action update |
| **Expertise Required** | High (know each tool) | Low (unified interface) |

**ROI**: Agent-OS pays for itself if you value your time at >$20/hour.

### vs GitHub Advanced Security

| Feature | GitHub Advanced Security | Agent-OS | Winner |
|---------|-------------------------|----------|--------|
| **Cost** | $49/user/month | Free (open source) | 🏆 Agent-OS |
| **Secret Scanning** | Pattern-based | Pattern + API verification | 🏆 Agent-OS |
| **Noise Reduction** | Manual review | 60-70% auto-suppression | 🏆 Agent-OS |
| **SAST Coverage** | CodeQL | Semgrep (2000+ rules) | 🤝 Tie |
| **Dependency Scanning** | Dependabot | Trivy + reachability | 🤝 Tie |
| **Fix Suggestions** | Limited | AI-generated | 🏆 Agent-OS |
| **Policy Enforcement** | Manual | Rego-based automation | 🏆 Agent-OS |
| **Self-Hosted** | ❌ Cloud only | ✅ Full control | 🏆 Agent-OS |
| **GitHub Integration** | Native | Action-based | 🏆 GitHub |

**Recommendation**: Use **both**! GitHub Advanced Security for ongoing monitoring, Agent-OS for PR gates with AI triage.

### vs Commercial Tools (Snyk, Checkmarx, Veracode)

| Feature | Commercial SAST/SCA | Agent-OS | Notes |
|---------|---------------------|----------|-------|
| **Pricing** | $1,000-10,000+/year | ~$100-500/year (usage-based) | Commercial tools include support |
| **Coverage** | Excellent (mature) | Very Good (4 tools) | Commercial tools more specialized |
| **Noise Reduction** | Good (tuned rulesets) | Very Good (AI-powered) | Agent-OS learns from feedback |
| **Fix Suggestions** | Basic | AI-generated | Agent-OS uses LLMs |
| **Policy Engine** | Proprietary | Open (Rego) | Agent-OS more flexible |
| **Self-Hosted** | Enterprise plans | ✅ Always | Agent-OS full control |
| **Vendor Lock-in** | High | None | Agent-OS open source |
| **Support** | SLA-backed | Community | Commercial wins here |

**Best For**:
- **Commercial**: Large enterprises, require SLA support, deep integrations
- **Agent-OS**: Startups to mid-size, value flexibility, OSS-first culture

### vs Security-as-a-Service (GuardRails, Semgrep Cloud)

| Feature | Security-as-a-Service | Agent-OS |
|---------|----------------------|----------|
| **Data Handling** | Sent to vendor cloud | Stays in your runner |
| **Pricing Model** | Per-repo or per-scan | Free (OSS) |
| **Customization** | Vendor dashboard | Full Rego policies |
| **Privacy** | Trust vendor | Self-hosted option |
| **Integration** | Vendor-managed | GitHub Action |

**Agent-OS Advantage**: Minimal external data sharing (only code snippet context for AI analysis). Use Ollama on self-hosted runners for 100% local processing.

---

## Outputs

Agent-OS generates multiple artifact formats:

| Output | Description | Use Case |
|--------|-------------|----------|
| **Markdown Report** | Human-readable findings with context | PR comments, audit trails |
| **SARIF** | Standard format for GitHub Code Scanning | Security tab integration |
| **JSON** | Structured findings with all metadata | Custom dashboards, integrations |
| **SBOM** | CycloneDX software bill of materials | Supply chain transparency |

Access via GitHub Actions artifacts or programmatically:

```yaml
- name: Download Reports
  uses: actions/download-artifact@v4
  with:
    name: code-review-reports-${{ github.run_id }}
```

---

## What is Agent-OS?

Agent-OS is a **security control plane** that can be used in three ways:

1. **GitHub Action** (easiest) ← You are here
2. **CLI** (for local dev): `python3 scripts/run_ai_audit.py /path/to/repo`
3. **Platform** (for enterprises): Deploy on K8s, integrate with your security org

This repository packages all three. Most users start with the GitHub Action.

**Deep dive**: See [PLATFORM.md](PLATFORM.md) for full architecture, benchmarks, and advanced deployment.

---

## Deployment Models

### Cloud (GitHub Actions)
```yaml
# Already covered above - simplest option
uses: securedotcom/agent-os-action@v1
```

### Self-Hosted Runners
```yaml
jobs:
  security:
    runs-on: [self-hosted, linux, x64]
    steps:
      - uses: securedotcom/agent-os-action@v1
```

### Docker
```bash
docker run -v $(pwd):/workspace \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  agent-os:latest \
  python3 scripts/run_ai_audit.py /workspace audit
```

### Kubernetes CronJob
```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: agent-os-scan
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: agent-os
            image: agent-os:latest
            command: ["python3", "scripts/run_ai_audit.py", "/workspace", "audit"]
```

Full deployment guide: [PLATFORM.md#deployment](PLATFORM.md#deployment)

---

## Troubleshooting

### "Cost limit exceeded"
- **Cause**: Large repo or many findings triggered Claude/OpenAI API calls
- **Fix**: Use Ollama (free on self-hosted) or increase `cost-limit: '2.0'`

### "No blockers found but PR still fails"
- **Cause**: Custom Rego policy or `fail-on` configuration
- **Fix**: Check policy files in `policy/rego/` or set `fail-on-blockers: 'false'`

### "Agent-OS is too slow"
- **Cause**: Scanning large repo with many files
- **Fix**: Use `only-changed: 'true'` for PRs, `max-files: '50'`, or exclude paths

More: [docs/FAQ.md](docs/FAQ.md)

---

## Security & Privacy

### What Data Leaves Your Repo?

| Mode | Data Sent Externally | Recipient |
|------|---------------------|-----------|
| **Ollama (Local)** | ❌ Nothing | Local inference only |
| **Claude (Anthropic)** | ✅ Code snippets (findings context only, ~200 lines max) | Anthropic API (encrypted HTTPS) |
| **OpenAI GPT-4** | ✅ Code snippets (findings context only, ~200 lines max) | OpenAI API (encrypted HTTPS) |

**Guarantees**:
- ✅ No full repository data sent anywhere
- ✅ No telemetry or usage tracking
- ✅ No credentials stored or logged
- ✅ All processing in your GitHub Actions runner
- ✅ Open source - audit the code yourself

### Permissions Explained

```yaml
permissions:
  contents: read           # Read code to scan
  pull-requests: write     # Comment on PRs with findings
  actions: read            # Upload artifacts
  security-events: write   # Optional: upload SARIF to Code Scanning
```

**Least Privilege**: Run in `read` mode with `comment-on-pr: 'false'` for audit-only.

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Development setup
- Testing guidelines
- Pull request process
- Code of conduct

**Quick start for contributors**:
```bash
git clone https://github.com/securedotcom/agent-os-action.git
cd agent-os-action
pip install -r requirements.txt -r tests/requirements.txt
pytest tests/
```

---

## Support

- **Documentation**: [PLATFORM.md](PLATFORM.md) (full platform docs)
- **Examples**: [examples/workflows/](examples/workflows/) (workflow templates)
- **Issues**: [GitHub Issues](https://github.com/securedotcom/agent-os-action/issues) (bug reports)
- **Discussions**: [GitHub Discussions](https://github.com/securedotcom/agent-os-action/discussions) (questions, ideas)

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Acknowledgments

Agent-OS is built on:
- **TruffleHog** (secret scanning with verification)
- **Semgrep** (SAST analysis)
- **Trivy** (vulnerability scanning)
- **Checkov** (IaC security)
- **Claude** (Anthropic AI)
- **OpenAI** (GPT-4)
- **Ollama** (local LLM inference)
- **OPA** (policy engine)

Special thanks to the open-source security community.

---

**Built by security engineers, for security engineers.** 🛡️

*Need enterprise support, custom policies, or professional services? [Contact us](mailto:developer@secure.com)*
