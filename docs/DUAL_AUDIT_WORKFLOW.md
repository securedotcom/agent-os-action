# Dual-Audit Security Workflow

## Overview

The Dual-Audit workflow provides **high-confidence security assessment** by running two independent AI-powered security audits:

1. **Agent-OS (Anthropic Claude)**: Comprehensive security analysis with multi-scanner orchestration
2. **Codex (OpenAI GPT-5.2)**: Independent validation and cross-verification

This approach reduces false positives, increases detection accuracy, and provides consensus-based findings.

---

## Why Dual-Audit?

### Benefits

✅ **Higher Confidence**: Two independent AI models validate findings
✅ **Reduced False Positives**: Consensus approach filters noise
✅ **Comprehensive Coverage**: Different models catch different issues
✅ **Cross-Validation**: Findings confirmed by both tools are highly reliable
✅ **Best of Both Worlds**: Combines Anthropic + OpenAI strengths

### Use Cases

- **Production deployments**: Critical systems requiring high confidence
- **Compliance audits**: Regulatory requirements needing validation
- **Security reviews**: Pre-release security assessment
- **Continuous monitoring**: Automated security checks in CI/CD

---

## Prerequisites

### 1. Agent-OS Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Set Anthropic API key
export ANTHROPIC_API_KEY="your-api-key"
```

### 2. Codex CLI Setup

```bash
# Install Codex CLI (requires OpenAI account)
# Visit: https://platform.openai.com/codex

# Login to Codex
codex login

# Verify installation
codex --version
```

---

## Usage

### Basic Usage

```bash
python scripts/dual_audit.py /path/to/repository
```

### With Project Type

```bash
python scripts/dual_audit.py /path/to/repo --project-type backend-api
```

### Full Example

```bash
# Navigate to agent-os-action
cd /path/to/agent-os-action

# Run dual-audit on target repository
python scripts/dual_audit.py ../my-project --project-type web-app

# Results saved to:
# ../my-project/.agent-os/dual-audit/TIMESTAMP/
```

---

## Workflow Phases

### Phase 1: Agent-OS Security Audit

**Duration**: 2-5 minutes
**Model**: Claude Sonnet 4.5
**Cost**: ~$0.20-0.50 per audit

**What it does:**
- Threat modeling (STRIDE analysis)
- Multi-scanner orchestration (Semgrep, Trivy, Checkov, etc.)
- AI-powered code review
- Vulnerability detection and classification
- Generates comprehensive SARIF/JSON/Markdown reports

**Output:**
- `.agent-os/reviews/backend-api-report.md` - Human-readable report
- `.agent-os/reviews/results.json` - Machine-readable results
- `.agent-os/reviews/results.sarif` - SARIF format for tools
- `.agent-os/threat-model.json` - Threat model

### Phase 2: Codex Independent Validation

**Duration**: 1-3 minutes
**Model**: GPT-5.2-codex
**Cost**: Included in Codex subscription

**What it does:**
- Reads Agent-OS findings
- Independently analyzes codebase
- Cross-validates each finding
- Identifies additional issues Agent-OS missed
- Confirms or disputes Agent-OS findings

**Output:**
- `.agent-os/dual-audit/TIMESTAMP/codex_validation.txt` - Validation results

### Phase 3: Comparison Report

**Duration**: < 1 second
**Cost**: Free (local processing)

**What it does:**
- Compares Agent-OS and Codex findings
- Generates consensus report
- Highlights validated findings
- Identifies discrepancies
- Provides confidence metrics

**Output:**
- `.agent-os/dual-audit/TIMESTAMP/dual_audit_report.md` - Final report

---

## Understanding Results

### Report Structure

```
.agent-os/dual-audit/TIMESTAMP/
├── agent_os_report.md          # Agent-OS findings (copy)
├── agent_os_results.json       # Agent-OS JSON output (copy)
├── codex_validation.txt        # Codex validation output
└── dual_audit_report.md        # Comparison report ⭐
```

### Reading the Dual-Audit Report

The final `dual_audit_report.md` contains:

1. **Executive Summary**
   - Audit methodology overview
   - Tools and models used
   - High-level metrics

2. **Agent-OS Results**
   - Findings by severity (Critical/High/Medium/Low)
   - Findings by category (Security/Performance/Quality)
   - Cost and duration metrics

3. **Codex Validation**
   - Independent findings
   - Validation of Agent-OS results
   - Additional issues discovered

4. **Cross-Validation Analysis**
   - Agreement metrics
   - Consensus findings
   - Disputed findings (if any)

5. **Recommendations**
   - Prioritized action items
   - Remediation guidance
   - Follow-up steps

### Finding Priority

**High Priority** (Fix Immediately):
- ✅ Findings confirmed by BOTH Agent-OS AND Codex
- 🔴 Critical severity issues
- 🟠 High severity security vulnerabilities

**Medium Priority** (Fix Soon):
- ✅ Findings from Agent-OS OR Codex (not both)
- 🟡 Medium severity issues
- Security concerns in non-critical paths

**Low Priority** (Review):
- ❓ Disputed findings (tools disagree)
- 🟢 Low severity issues
- Code quality improvements

---

## Example Workflow

### Step 1: Run Dual-Audit

```bash
cd /Users/waseem.ahmed/Repos/agent-os-action
python scripts/dual_audit.py /tmp/target-repo --project-type backend-api
```

### Step 2: Review Output

```
================================================================================
PHASE 1: Agent-OS Security Audit (Anthropic Claude)
================================================================================

✅ Threat model generated: 16 threats identified
✅ Selected 100 files (13,522 lines)
✅ Found 18 security issues
💰 Cost: $0.24
⏱️  Duration: 183s

================================================================================
PHASE 2: Codex Independent Validation (OpenAI GPT-5.2)
================================================================================

✅ Codex reviewed Agent-OS findings
✅ Validated 15/18 findings
🆕 Discovered 2 additional issues
❌ Disputed 1 finding (false positive)

================================================================================
Generating Dual-Audit Comparison Report
================================================================================

✅ Dual-audit report generated
📊 Review comprehensive report: .agent-os/dual-audit/20260114-120000/dual_audit_report.md
```

### Step 3: Act on Findings

```bash
# Review the final report
cat /tmp/target-repo/.agent-os/dual-audit/20260114-120000/dual_audit_report.md

# Focus on consensus findings
# Address Critical/High severity first
# Schedule Medium/Low for sprint planning
```

---

## Integration with CI/CD

### GitHub Actions

```yaml
name: Dual-Audit Security Scan

on:
  pull_request:
    branches: [main, develop]
  schedule:
    - cron: '0 2 * * 1'  # Weekly on Monday

jobs:
  dual-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install Agent-OS
        run: |
          git clone https://github.com/securedotcom/agent-os-action
          cd agent-os-action
          pip install -r requirements.txt

      - name: Run Dual-Audit
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          python agent-os-action/scripts/dual_audit.py . --project-type backend-api

      - name: Upload Reports
        uses: actions/upload-artifact@v4
        with:
          name: dual-audit-reports
          path: .agent-os/dual-audit/**/*.md
```

### GitLab CI

```yaml
dual-audit:
  image: python:3.11
  script:
    - git clone https://github.com/securedotcom/agent-os-action
    - cd agent-os-action && pip install -r requirements.txt && cd ..
    - python agent-os-action/scripts/dual_audit.py . --project-type backend-api
  artifacts:
    paths:
      - .agent-os/dual-audit/
    expire_in: 30 days
  only:
    - merge_requests
    - main
```

---

## Best Practices

### 1. Run on Clean Code

- Ensure code is linted and formatted
- Fix obvious issues before audit
- Commit changes before running

### 2. Review Both Reports

- Don't rely solely on the comparison report
- Review Agent-OS detailed findings
- Check Codex validation reasoning

### 3. Validate False Positives

- Use human judgment for disputed findings
- Check if flagged secrets are examples/placeholders
- Verify context of vulnerabilities

### 4. Track Metrics Over Time

```bash
# Save metrics for trending
cp .agent-os/dual-audit/TIMESTAMP/dual_audit_report.md \
   security-reports/$(date +%Y%m%d)-dual-audit.md
```

### 5. Automate Remediation

- Create GitHub issues from findings
- Assign to responsible teams
- Track fix timelines

---

## Troubleshooting

### Agent-OS Fails

```bash
# Check API key
echo $ANTHROPIC_API_KEY

# Verify dependencies
pip install -r requirements.txt

# Run manually
python scripts/run_ai_audit.py /path/to/repo backend-api
```

### Codex Fails

```bash
# Check Codex installation
which codex

# Re-login
codex logout
codex login

# Verify access
codex --version
```

### Timeout Issues

For large repositories:

```python
# Edit scripts/dual_audit.py
# Increase timeout values:
timeout=1200  # 20 minutes instead of 10
```

---

## Cost Estimation

### Per Audit

| Tool | Cost | Duration |
|------|------|----------|
| Agent-OS (Claude) | $0.20-0.50 | 2-5 min |
| Codex (GPT-5.2) | Included* | 1-3 min |
| **Total** | **$0.20-0.50** | **3-8 min** |

*Codex requires OpenAI subscription

### Monthly (100 repos, weekly scans)

- Agent-OS: 400 audits × $0.35 = **$140/month**
- Codex: Included in subscription
- **Total: ~$140/month + Codex subscription**

---

## Comparison: Single vs Dual-Audit

| Feature | Single Audit | Dual-Audit |
|---------|-------------|------------|
| Confidence | Medium | High |
| False Positives | 10-15% | 5-8% |
| Coverage | Good | Excellent |
| Cost | $0.20 | $0.20-0.50 |
| Duration | 2-5 min | 3-8 min |
| Validation | Manual | Automated |
| Best For | Dev/Test | Production |

---

## Support

- **Documentation**: [docs/](../docs/)
- **Issues**: https://github.com/securedotcom/agent-os-action/issues
- **Examples**: [examples/dual-audit/](../examples/dual-audit/)

---

## Version History

- **v1.0.0** (2026-01-14): Initial dual-audit workflow
  - Agent-OS + Codex integration
  - Automated comparison reports
  - CI/CD examples

---

**Recommendation**: Use dual-audit for all production deployments and critical security reviews. The additional validation significantly increases confidence in findings while maintaining reasonable cost and execution time.
