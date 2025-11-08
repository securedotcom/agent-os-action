# Agent-OS Security Action

> **GitHub Action for Production Security Scanning**  
> Orchestrates TruffleHog, Gitleaks, Semgrep, Trivy, Checkov + AI triage + policy gates

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](#contributing)
[![Foundation-Sec](https://img.shields.io/badge/AI-Foundation--Sec--8B-green.svg)](#ai-triage-options)

---

## What It Does

**Runs multiple security scanners, applies AI triage to suppress false positives, and blocks PRs only on verified, high-confidence threats.**

- **Multi-Scanner**: TruffleHog, Gitleaks, Semgrep, Trivy, Checkov in parallel
- **AI Triage**: Foundation-Sec-8B (free) or Claude for intelligent noise reduction
- **Smart Blocking**: Only fails on verified secrets, critical CVEs, and high-confidence SAST findings
- **60% Noise Reduction**: ML-powered false positive suppression
- **Zero to $0.35**: Free with Foundation-Sec, optional Claude upgrade

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

### 2. Add Secret (Optional)

- **Free tier**: Omit `anthropic-api-key` to use Foundation-Sec-8B (local inference, $0)
- **Paid tier**: Add `ANTHROPIC_API_KEY` in Settings → Secrets for Claude analysis (~$0.35/run)

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
- Cost: $0.00 (Foundation-Sec)
- Noise Reduction: 67% (6 findings → 2 actionable)
```

See full example: [examples/reports/sample-pr-comment.md](examples/reports/sample-pr-comment.md)

---

## How It Works

| Aspect | Details |
|--------|---------|
| **Scanners Orchestrated** | **TruffleHog** (verified secrets), **Gitleaks** (pattern-based secrets), **Semgrep** (SAST, 2000+ rules), **Trivy** (CVE scanning), **Checkov** (IaC security) |
| **AI Analysis** | **Foundation-Sec-8B** (Cisco security-optimized LLM, local inference, $0) or **Claude Sonnet** (Anthropic, ~$0.35/run) |
| **Data Handling** | All scanning runs **in your GitHub Actions runner**. Optional: API calls to Anthropic if using Claude (code snippets for context only). **No telemetry, no data collection**. |
| **Permissions Required** | `contents: read` (scan code), `pull-requests: write` (comment), `actions: read` (upload artifacts). Optional: `contents: write` (create audit PRs) |
| **Runtime** | **<5 minutes** for typical repos (p95). Scales linearly with repo size. Parallelized scanning. |
| **Cost** | **$0.00** with Foundation-Sec-8B (default), **$0.20-0.50** with Claude (depends on findings count) |
| **Noise Reduction** | **60-70%** false positive suppression via ML scoring + historical analysis |
| **When It Blocks** | Only on: **(1)** Verified secrets (API-validated), **(2)** Critical CVEs with known exploits, **(3)** High-confidence SAST findings (low noise score). Customizable via Rego policies. |

---

## AI Triage Options

Agent-OS uses AI to reduce noise and assess exploitability. Choose one:

| Option | Cost | Quality | Setup |
|--------|------|---------|-------|
| **Foundation-Sec-8B** (Default) | $0 | ⭐⭐⭐⭐ | Runs locally in runner (4GB download, CPU-compatible) |
| **Claude Sonnet** (Optional) | ~$0.35/run | ⭐⭐⭐⭐⭐ | Requires `ANTHROPIC_API_KEY` |

**Recommendation**: Start with Foundation-Sec (free), upgrade to Claude if you need higher accuracy.

### Foundation-Sec-8B Details
- **What it is**: Cisco's security-optimized LLM, fine-tuned for vulnerability analysis
- **Why it's free**: Local inference in your GitHub Actions runner (no API calls)
- **Requirements**: ~4GB download (cached after first run), works on standard `ubuntu-latest` runners
- **Performance**: 84% recall on obfuscated secrets, 60%+ noise reduction

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
    
    # AI provider: auto, anthropic, foundation-sec (default: auto)
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
| **Coverage** | Run 1-2 tools | 5 tools orchestrated + correlated |
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

### "Failed to download Foundation-Sec model"
- **Cause**: Network timeout or insufficient disk space
- **Fix**: Model is ~4GB. Ensure runner has 10GB+ free space. Cached after first run.

### "Cost limit exceeded"
- **Cause**: Large repo or many findings triggered Claude API calls
- **Fix**: Use Foundation-Sec (free) or increase `cost-limit: '2.0'`

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
| **Foundation-Sec** | ❌ Nothing | Local inference only |
| **Claude (Anthropic)** | ✅ Code snippets (findings context only, ~200 lines max) | Anthropic API (encrypted HTTPS) |

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
- **TruffleHog** (secret scanning)
- **Gitleaks** (secret detection)
- **Semgrep** (SAST analysis)
- **Trivy** (vulnerability scanning)
- **Checkov** (IaC security)
- **Foundation-Sec-8B** (Cisco security-optimized LLM)
- **Claude** (Anthropic AI)
- **OPA** (policy engine)

Special thanks to the open-source security community.

---

**Built by security engineers, for security engineers.** 🛡️

*Need enterprise support, custom policies, or professional services? [Contact us](mailto:security@example.com)*
