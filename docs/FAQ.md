# Agent-OS: Frequently Asked Questions

## General Questions

### What is Agent-OS?

Agent-OS is a security control plane that orchestrates multiple security scanners (TruffleHog, Gitleaks, Semgrep, Trivy, Checkov), applies AI-powered triage to reduce false positives, and enforces policy gates. It can be used as a GitHub Action, CLI tool, or deployed platform.

### Is Agent-OS free?

Yes! Agent-OS is open source (MIT license) and free to use. The default AI provider (Foundation-Sec-8B) uses local inference, so there are zero API costs. Optionally, you can use Claude for enhanced accuracy (~$0.35/run).

### How is this different from GitHub's built-in security features?

| Feature | GitHub Security | Agent-OS |
|---------|----------------|----------|
| **Secret Scanning** | Pattern-based | Pattern + API verification |
| **Dependency Scanning** | Dependabot alerts | Trivy + reachability analysis |
| **Code Scanning** | CodeQL | Semgrep + AI triage |
| **Noise Reduction** | Manual review | 60-70% auto-suppression |
| **Policy Enforcement** | Manual | Automated Rego gates |
| **Fix Suggestions** | Limited | AI-generated remediations |

Agent-OS **complements** GitHub Security (you can use both), but adds AI triage and policy automation.

---

## Setup & Configuration

### Do I need an API key to use Agent-OS?

**No, not required!** Agent-OS works with Foundation-Sec-8B (local inference, zero cost) by default.

**Optional**: Add `ANTHROPIC_API_KEY` for Claude analysis if you want higher accuracy.

### How do I get started in under 5 minutes?

1. Create `.github/workflows/agent-os.yml`:
   ```yaml
   name: Security
   on: [pull_request]
   jobs:
     security:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - uses: securedotcom/agent-os-action@v1
   ```

2. Open a PR → Agent-OS comments with findings

3. Done! 🎉

### What permissions does Agent-OS need?

**Minimum** (read-only audit):
- `contents: read` - to scan code

**Recommended** (for PR comments):
- `contents: read`
- `pull-requests: write` - to comment on PRs

**Optional** (for automated PRs):
- `contents: write` - to create audit PRs

### Can I run Agent-OS locally (not in GitHub Actions)?

Yes! Install locally:

```bash
git clone https://github.com/securedotcom/agent-os-action.git
cd agent-os-action
pip install -r requirements.txt
python3 scripts/run_ai_audit.py /path/to/your/repo audit
```

See [PLATFORM.md](../PLATFORM.md#usage) for full CLI documentation.

---

## Cost & Performance

### How much does Agent-OS cost to run?

| AI Provider | Cost per Run | Notes |
|-------------|-------------|--------|
| **Foundation-Sec-8B** (default) | $0.00 | Local inference, no API calls |
| **Claude Sonnet** (optional) | $0.20-0.50 | Depends on findings count |

**GitHub Actions runner time**: ~3-5 minutes = $0.008-0.013 (on public repos, free)

### How long does a scan take?

| Repository Size | Typical Duration |
|----------------|------------------|
| Small (<1K files) | 1-2 minutes |
| Medium (1K-5K files) | 3-5 minutes |
| Large (5K-20K files) | 5-10 minutes |
| Monorepo (>20K files) | 10-20 minutes |

**Tips to speed up**:
- Use `only-changed: 'true'` for PR scans (only scan changed files)
- Set `max-files: '50'` to limit scope
- Use `exclude-paths` to skip generated code

### Will Agent-OS slow down my PR reviews?

**No!** Agent-OS runs asynchronously. Developers can continue working while the scan completes (~3-5 min).

**With noise reduction**, you get 3-5 actionable findings instead of 50+ raw alerts, which actually **speeds up** overall review time.

### What's the difference between Foundation-Sec and Claude?

| Aspect | Foundation-Sec-8B | Claude Sonnet |
|--------|------------------|---------------|
| **Cost** | $0 (local) | ~$0.35/run |
| **Speed** | 2-3 minutes | 1-2 minutes |
| **Accuracy** | ⭐⭐⭐⭐ (84% recall) | ⭐⭐⭐⭐⭐ (92% recall) |
| **Noise Reduction** | 60-70% | 70-80% |
| **Best For** | Most teams, cost-conscious | High-security, accuracy-critical |

**Recommendation**: Start with Foundation-Sec, upgrade to Claude if needed.

---

## Security & Privacy

### What data does Agent-OS send externally?

| Mode | Data Sent | Recipient |
|------|-----------|-----------|
| **Foundation-Sec** | ❌ Nothing | Local inference only |
| **Claude** | ✅ Code snippets (findings context, ~200 lines max) | Anthropic API |

**Never sent**: Full repository, commit history, secrets, credentials.

### Does Agent-OS store my data?

**No.** Agent-OS is stateless. All processing happens in your GitHub Actions runner and artifacts are stored in GitHub (controlled by you).

**Optional**: You can deploy Agent-OS with PostgreSQL for historical analysis (self-hosted, you control the data).

### Is Agent-OS safe to use on private repositories?

**Yes!** Agent-OS is designed for enterprise use:
- ✅ Open source (audit the code yourself)
- ✅ No telemetry or phone-home
- ✅ No credential storage
- ✅ Runs entirely in your infrastructure
- ✅ Optional: Use Foundation-Sec (no external API calls)

### Can I run Agent-OS in air-gapped environments?

**Yes, with Foundation-Sec-8B:**
1. Pre-download model (4GB): `huggingface-cli download fdtn-ai/Foundation-Sec-8B`
2. Set `HF_HOME` to your cache directory
3. Run Agent-OS (no internet required)

**No** with Claude (requires Anthropic API access).

---

## Findings & Triage

### Why are some findings suppressed?

Agent-OS auto-suppresses findings with high "noise scores" (>0.7 by default):

**Common suppression reasons**:
- Test files (`test/`, `spec/`, `__tests__/`)
- Documentation (`docs/`, `README.md`)
- Example/template files (`.example`, `sample_`)
- Unverified secrets (pattern match only, no API validation)
- Low-severity findings in non-production code

**You control this**: Adjust `NOISE_THRESHOLD` in your workflow or edit Rego policies.

### How do I suppress a false positive?

**Option 1: React to PR comment**  
React with 👎 and comment why. Agent-OS learns from feedback.

**Option 2: Add to allowlist**  
Create `.agent-os/allowlist.yml`:
```yaml
suppressions:
  - fingerprint: "abc123def456"  # From finding metadata
    reason: "False positive: test fixture"
    expires: "2025-12-31"
```

**Option 3: Custom Rego policy**  
Edit `policy/rego/pr.rego` to add suppression logic.

### What's the difference between "suppressed" and "ignored"?

- **Suppressed**: Finding is detected but auto-filtered (shown in "Suppressed" section of report)
- **Ignored**: Finding is never detected (via `exclude-paths` or tool config)

**Best practice**: Use suppression (shows why it's not actionable) rather than ignoring (hides it entirely).

### Can I customize what blocks a PR?

**Yes!** Edit `policy/rego/pr.rego`:

```rego
# Default: block on verified secrets + critical CVEs
block if {
    input.findings[_].severity == "critical"
    input.findings[_].verified == true
}

# Custom: also block on high SAST with exploitability "trivial"
block if {
    input.findings[_].severity == "high"
    input.findings[_].category == "SAST"
    input.findings[_].exploitability == "trivial"
}
```

Or use `fail-on` for simpler cases:
```yaml
with:
  fail-on: 'security:critical,security:high'
```

---

## Scanners & Tools

### Which security scanners does Agent-OS use?

| Scanner | Purpose | Enabled by Default |
|---------|---------|-------------------|
| **TruffleHog** | Verified secret detection | ✅ Yes |
| **Gitleaks** | Pattern-based secrets | ✅ Yes |
| **Semgrep** | SAST (2000+ rules) | ✅ Yes |
| **Trivy** | CVE scanning | ✅ Yes |
| **Checkov** | IaC security | ✅ Yes |
| **Syft** | SBOM generation | ⚙️ On-demand |
| **Cosign** | Artifact signing | ⚙️ On-demand |

### Can I disable specific scanners?

**Yes!** Use scanner-specific flags:

```yaml
with:
  semgrep-enabled: 'false'  # Disable Semgrep
  # Note: TruffleHog, Gitleaks, Trivy always run (core security)
```

Or use `exclude-paths` to skip scanning certain directories:
```yaml
with:
  exclude-paths: 'vendor/**,node_modules/**'
```

### How do I add custom Semgrep rules?

Create `.semgrep/rules.yml` in your repo:

```yaml
rules:
  - id: custom-sql-injection
    pattern: |
      db.query($QUERY)
    message: "Potential SQL injection"
    severity: ERROR
    languages: [javascript, typescript]
```

Agent-OS will automatically use your custom rules alongside the default `p/security-audit` ruleset.

### Does Agent-OS support language X?

**Yes, for most languages:**

| Language | Semgrep | Trivy | Gitleaks | TruffleHog | Checkov |
|----------|---------|-------|----------|------------|---------|
| JavaScript/TypeScript | ✅ | ✅ | ✅ | ✅ | ✅ |
| Python | ✅ | ✅ | ✅ | ✅ | ✅ |
| Java | ✅ | ✅ | ✅ | ✅ | ✅ |
| Go | ✅ | ✅ | ✅ | ✅ | ✅ |
| Ruby | ✅ | ✅ | ✅ | ✅ | ✅ |
| PHP | ✅ | ✅ | ✅ | ✅ | ⚠️ |
| C/C++ | ⚠️ | ✅ | ✅ | ✅ | ❌ |
| Rust | ⚠️ | ✅ | ✅ | ✅ | ❌ |
| Terraform/IaC | ✅ | ✅ | ✅ | ✅ | ✅ |

**Legend**: ✅ Full support, ⚠️ Partial support, ❌ Not supported

---

## Troubleshooting

### "Failed to download Foundation-Sec model"

**Cause**: Network timeout or insufficient disk space

**Solutions**:
1. **Increase timeout**: Model is ~4GB, first download takes 5-10 min
2. **Check disk space**: Ensure runner has 10GB+ free
3. **Use Claude instead**: `with: { ai-provider: 'anthropic' }`
4. **Pre-cache model**: See [caching guide](../PLATFORM.md#caching)

### "Cost limit exceeded"

**Cause**: Large repo or many findings triggered Claude API calls

**Solutions**:
1. **Use Foundation-Sec**: `with: { ai-provider: 'foundation-sec' }` (free)
2. **Increase limit**: `with: { cost-limit: '2.0' }`
3. **Scan fewer files**: `with: { max-files: '50', only-changed: 'true' }`

### "No blockers found but PR still fails"

**Cause**: Custom Rego policy or `fail-on` configuration

**Solutions**:
1. Check Rego policies in `policy/rego/pr.rego`
2. Check `fail-on` setting in workflow
3. Set `fail-on-blockers: 'false'` to disable blocking

### "Agent-OS is too slow"

**Optimizations**:
```yaml
with:
  only-changed: 'true'      # Only scan changed files (PRs)
  max-files: '50'            # Limit file count
  max-file-size: '50000'     # Skip large files (bytes)
  exclude-paths: 'vendor/**,node_modules/**'  # Skip dependencies
```

**Expected speedup**: 2-5x faster on large repos

### "Too many false positives"

**Adjustments**:
```yaml
env:
  NOISE_THRESHOLD: '0.6'     # Lower threshold = more suppression (default: 0.7)
```

Or create `.agent-os/allowlist.yml` to suppress specific patterns.

### "Important finding was suppressed"

**Review suppression reasons** in the report, then:

1. **If legitimately wrong**: React with 👎 on PR comment (teaches model)
2. **If test file but real risk**: Move to production code or adjust policy
3. **If need manual override**: Lower noise threshold: `NOISE_THRESHOLD: '0.8'`

---

## Advanced Usage

### Can I run Agent-OS on multiple repositories?

**Yes!** Use the multi-repo coordinator:

```bash
python3 scripts/multi_repo_coordinator.py \
  --config config/repos.json \
  --max-concurrent 3
```

Or create a GitHub Actions matrix:
```yaml
strategy:
  matrix:
    repo: [repo1, repo2, repo3]
steps:
  - uses: actions/checkout@v4
    with:
      repository: ${{ matrix.repo }}
  - uses: securedotcom/agent-os-action@v1
```

### Can I integrate Agent-OS with Slack/Teams/etc?

**Yes!** Agent-OS outputs JSON/SARIF that you can parse:

```yaml
- name: Notify Slack
  if: steps.security.outputs.blockers > 0
  run: |
    curl -X POST $SLACK_WEBHOOK \
      -d "{\"text\": \"🚨 ${{ steps.security.outputs.blockers }} security issues found\"}"
```

Or use `.agent-os/notifications.yml` (coming soon).

### Can I use Agent-OS in pre-commit hooks?

**Yes!** But not recommended (too slow for pre-commit).

**Better approach**: Use Agent-OS in CI/CD, and use faster tools locally:
- `pre-commit` with `gitleaks` for secrets
- `eslint` for JS linting
- Agent-OS for comprehensive PR review

### How do I generate SBOMs?

**In GitHub Action**:
```yaml
with:
  review-type: 'audit'
  # SBOM automatically generated
```

**Standalone**:
```bash
python3 scripts/sbom_generator.py \
  --repo-path /path/to/repo \
  --output sbom.json
```

**Sign SBOM**:
```bash
cosign sign-blob --key cosign.key sbom.json
```

See [PLATFORM.md#sbom](../PLATFORM.md#sbom-generation-and-signing) for details.

### Can I use custom AI models?

**Yes!** Agent-OS supports:
- **Foundation-Sec** (default, local)
- **Claude** (Anthropic API)
- **OpenAI** (GPT-4)
- **Ollama** (self-hosted, local)
- **SageMaker** (AWS-hosted)

Example with Ollama:
```yaml
with:
  ai-provider: 'ollama'
  ollama-endpoint: 'http://localhost:11434'
  model: 'llama3:70b'
```

---

## Compliance & Enterprise

### Does Agent-OS help with SOC 2 compliance?

**Yes!** Agent-OS includes a SOC 2 compliance pack:

- **CC6.1**: Access controls (no verified secrets)
- **CC6.6**: Encryption + SBOM requirements
- **CC7.2**: Vulnerability remediation SLA
- **CC7.3**: Incident response timeliness

Enable via:
```bash
opa eval -d policy/rego/compliance_soc2.rego \
  -i findings.json \
  "data.compliance.soc2.decision"
```

See [PLATFORM.md#soc2](../PLATFORM.md#soc-2-compliance-pack) for full documentation.

### Can I use Agent-OS for PCI-DSS compliance?

**Partially.** Agent-OS addresses:
- ✅ PCI-DSS 6.2: Patch vulnerabilities
- ✅ PCI-DSS 6.3: Secure development practices
- ✅ PCI-DSS 6.5: Common vulnerabilities (OWASP Top 10)
- ✅ PCI-DSS 8.2: No hardcoded credentials

But Agent-OS alone doesn't cover full PCI-DSS (network security, physical access, etc.).

### Can I get a report for auditors?

**Yes!** Agent-OS generates:
- **Markdown reports**: Human-readable for auditors
- **JSON**: Structured data for compliance tools
- **SARIF**: Standard format for security tools

Example audit workflow:
```yaml
- uses: securedotcom/agent-os-action@v1
  with:
    review-type: 'audit'
- uses: actions/upload-artifact@v4
  with:
    name: audit-report-${{ github.run_id }}
    path: .agent-os/reviews/
    retention-days: 365  # Keep for audit trail
```

### Does Agent-OS support role-based access control (RBAC)?

**Not directly.** Agent-OS inherits GitHub's RBAC:
- Who can trigger workflows (GitHub permissions)
- Who can view artifacts (GitHub permissions)
- Who can approve PRs (GitHub branch protection)

For enterprise deployments, see [PLATFORM.md#rbac](../PLATFORM.md#deployment) for custom RBAC.

---

## Comparison Questions

### Agent-OS vs Snyk?

| Feature | Snyk | Agent-OS |
|---------|------|----------|
| **Focus** | Dependency vulnerabilities | Multi-scanner (secrets, SAST, CVE, IaC) |
| **Pricing** | $0-$2,000+/month | Free (open source) |
| **AI Triage** | Limited | ✅ ML-powered (60-70% noise reduction) |
| **Policy Engine** | Yes (cloud) | ✅ Rego (self-hosted) |
| **SBOM** | Yes | ✅ Yes |
| **Self-Hosted** | Limited | ✅ Full control |

**Use both?** Yes! Snyk for dependency monitoring, Agent-OS for PR gates + AI triage.

### Agent-OS vs SonarQube?

| Feature | SonarQube | Agent-OS |
|---------|-----------|----------|
| **Focus** | Code quality + security | Security-first |
| **Deployment** | Self-hosted server | GitHub Action or self-hosted |
| **AI Triage** | No | ✅ Yes |
| **Secret Scanning** | Basic | ✅ Verified (API validation) |
| **Cost** | Free Community, $150+/month Enterprise | Free (open source) |

**Use both?** Yes! SonarQube for ongoing quality, Agent-OS for PR security gates.

### Agent-OS vs GitHub Advanced Security?

| Feature | GitHub Advanced Security | Agent-OS |
|---------|-------------------------|----------|
| **Secret Scanning** | Pattern-based | ✅ Pattern + API verification |
| **Code Scanning** | CodeQL | ✅ Semgrep + AI triage |
| **Dependency Review** | Dependabot | ✅ Trivy + reachability |
| **Noise Reduction** | Manual | ✅ 60-70% auto-suppression |
| **Cost** | $49/user/month | Free |

**Use both?** Absolutely! They complement each other.

---

## Contributing & Support

### How do I report a bug?

1. Check [existing issues](https://github.com/securedotcom/agent-os-action/issues)
2. If new, [open an issue](https://github.com/securedotcom/agent-os-action/issues/new) with:
   - Steps to reproduce
   - Expected vs actual behavior
   - Workflow file (sanitized)
   - Agent-OS version

### How do I request a feature?

1. Check [discussions](https://github.com/securedotcom/agent-os-action/discussions)
2. If new, start a discussion with:
   - Use case / problem
   - Proposed solution
   - Why it's valuable

### How do I contribute code?

See [CONTRIBUTING.md](../CONTRIBUTING.md) for:
- Development setup
- Testing requirements
- Pull request process
- Code style guide

### Is there enterprise support?

**Community support**: Free via GitHub Issues/Discussions

**Enterprise support**: [Contact us](mailto:enterprise@agent-os.io) for:
- SLA-backed support
- Custom integrations
- Professional services
- Dedicated Slack channel

---

## Still Have Questions?

- 📖 **Documentation**: [PLATFORM.md](../PLATFORM.md)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/securedotcom/agent-os-action/discussions)
- 🐛 **Issues**: [GitHub Issues](https://github.com/securedotcom/agent-os-action/issues)
- 📧 **Email**: support@agent-os.io

---

*Last updated: November 2025*  
*Agent-OS Version: v1.0.0*
