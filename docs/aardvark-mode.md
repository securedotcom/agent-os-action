# Aardvark Mode: Exploit Analysis & Security Test Generation

> **✅ PRODUCTION STATUS**: Aardvark mode is fully working in multi-agent sequential mode.
> All features described below are operational and production-ready.

Agent OS includes **Aardvark mode**, inspired by OpenAI's Aardvark, which provides comprehensive exploit chain analysis and automatic security test generation for discovered vulnerabilities.

## Current Status

| Feature | Implementation | Integration | User-Facing |
|---------|---------------|-------------|-------------|
| Exploit Chain Analysis | ✅ Complete | ✅ Complete | ✅ Working |
| Exploitability Classification | ✅ Complete | ✅ Complete | ✅ Working |
| Security Test Generation | ✅ Complete | ✅ Complete | ✅ Working |
| Strategic Remediation Guidance | ✅ Complete | ✅ Complete | ✅ Working |

**How to Use**: Enable `multi-agent-mode: 'sequential'` in your GitHub Actions workflow. The exploit-analyst and security-test-generator agents are automatically included.

## Overview

Traditional security scanners find vulnerabilities. **Aardvark mode goes further** by:

1. ✅ **Finding Vulnerabilities** (traditional security scanning)
2. **Analyzing Exploitability** (how easily can this be exploited?)
3. **Mapping Exploit Chains** (how can multiple vulns be combined?)
4. **Generating Security Tests** (automated test generation)
5. **Providing Strategic Fixes** (which fixes provide maximum security ROI?)

## Key Features

### 1. Exploitability Classification

Every vulnerability is classified by real-world exploitability:

| Classification | Timeline | Description |
|---------------|----------|-------------|
| ⚠️ **Trivial** | Fix within 24-48 hours | Exploitable in <10 minutes with basic tools |
| 🟨 **Moderate** | Fix within 1 week | Requires 1-4 hours and some technical knowledge |
| 🟦 **Complex** | Fix within 1 month | Requires days/weeks and advanced expertise |
| ⬜ **Theoretical** | Fix in next release | No known practical exploitation path |

### 2. Exploit Chain Analysis

Identifies how multiple vulnerabilities can be combined for greater impact:

```
[CHAIN-001] Authentication Bypass → Full System Compromise

Step 1: SQL Injection (VULN-001) → Bypass auth (⚠️ Trivial, 5 min)
Step 2: Extract admin token (VULN-002) → Get credentials (⚠️ Trivial, 5 min)
Step 3: IDOR (VULN-005) → Access admin profile (⚠️ Trivial, 5 min)
Step 4: Privilege escalation (VULN-008) → Full admin (🟨 Moderate, 10 min)
Step 5: Data exfiltration (VULN-012) → Download DB (⚠️ Trivial, 5 min)

Overall Exploitability: ⚠️ Trivial (30 minutes for skilled attacker)
Impact: Critical (full system compromise)

Strategic Fix: Fixing VULN-001 blocks this ENTIRE chain at step 1
```

### 3. Automatic Security Test Generation

Generates comprehensive test suites for discovered vulnerabilities:

- **Unit Tests**: Verify vulnerability is fixed
- **Integration Tests**: Test exploit chain prevention
- **Fuzz Tests**: Discover additional input validation issues
- **PoC Exploits**: Validate fixes work (authorized testing only)

**Example Generated Tests**:
```
tests/security/
├── vuln_001_sql_injection_test.py (5 test cases)
├── vuln_002_hardcoded_creds_test.py (3 test cases)
└── vuln_005_idor_test.py (4 test cases)

tests/integration/security/
└── exploit_chain_001_test.py

tests/fuzz/
└── search_input_fuzz.py (10,000 test cases)

tests/exploits/  ⚠️ For authorized testing only!
├── poc_vuln_001_sql_injection.py
└── poc_chain_001.py
```

### 4. Strategic Remediation Guidance

Instead of just listing vulnerabilities, Aardvark mode provides **strategic fix recommendations**:

**Traditional Report**:
```
- VULN-001: SQL Injection (Critical)
- VULN-002: Hardcoded Credentials (Critical)
- VULN-005: IDOR (High)
- VULN-008: Privilege Escalation (High)
- VULN-012: Missing Rate Limiting (Medium)
```

**Aardvark Report**:
```
Strategic Fix: Fixing VULN-001 (SQL Injection) will:
- Block CHAIN-001 (Auth Bypass → Data Exfiltration) at step 1
- Block CHAIN-003 (Credential Theft → Privilege Escalation) at step 1
- Eliminate 2 Critical exploit chains
- Exploitability: Trivial ⚠️ (10 minutes to exploit)
- Priority: IMMEDIATE (fix within 24 hours)

Fixing this ONE vulnerability blocks 2 complete exploit chains.
This should be your immediate priority.
```

## How to Enable

### Quick Start: Enable Everything

```yaml
- name: Agent OS Aardvark Security Review
  uses: securedotcom/agent-os-action@v2.2.0
  with:
    ai-provider: anthropic
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}

    # Enable Aardvark mode
    multi-agent-mode: 'sequential'
    enable-exploit-analysis: 'true'
    generate-security-tests: 'true'
```

### Configuration Options

#### enable-exploit-analysis
**Default**: `true`

Enables the `exploit-analyst` agent which:
- Classifies vulnerabilities by exploitability
- Identifies exploit chains
- Generates proof-of-concept exploit scenarios
- Assesses real-world risk

```yaml
enable-exploit-analysis: 'true'
```

#### generate-security-tests
**Default**: `true`

Enables the `security-test-generator` agent which:
- Generates unit tests for vulnerabilities
- Creates integration tests for exploit chains
- Generates fuzz tests for input validation
- Creates PoC exploits for validation

```yaml
generate-security-tests: 'true'
```

#### exploitability-threshold
**Default**: `trivial`

Blocks merge if exploitability meets or exceeds this threshold.

Options:
- `trivial` - Block on any trivial exploitability (recommended)
- `moderate` - Block on moderate or higher
- `complex` - Block on complex or higher
- `theoretical` - Block on any exploitability
- `none` - Never block based on exploitability

```yaml
exploitability-threshold: 'trivial'
```

## Usage Examples

### Example 1: Comprehensive Security Review (Recommended)

```yaml
name: Comprehensive Security Review

on:
  pull_request:
  push:
    branches: [ main ]

jobs:
  security-review:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      pull-requests: write

    steps:
      - uses: actions/checkout@v4

      - name: Agent OS Aardvark Review
        uses: securedotcom/agent-os-action@v2.2.0
        with:
          ai-provider: anthropic
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}

          # Full Aardvark mode
          multi-agent-mode: 'sequential'
          enable-exploit-analysis: 'true'
          generate-security-tests: 'true'
          exploitability-threshold: 'trivial'

          # Fail on high-risk vulnerabilities
          fail-on-blockers: 'true'
          fail-on: 'security:critical,security:high'

          # GitHub integration
          upload-reports: 'true'
          comment-on-pr: 'true'
```

### Example 2: Weekly Deep Security Audit

```yaml
name: Weekly Security Audit

on:
  schedule:
    - cron: '0 9 * * 1'  # Monday 9 AM

jobs:
  weekly-audit:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history

      - name: Deep Security Audit
        uses: securedotcom/agent-os-action@v2.2.0
        with:
          ai-provider: anthropic
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}

          # Full analysis, higher budget
          multi-agent-mode: 'sequential'
          enable-exploit-analysis: 'true'
          generate-security-tests: 'true'
          max-cost-usd: '5.00'
          max-files: 200

          # Don't fail, just report
          fail-on-blockers: 'false'

          upload-reports: 'true'

      - name: Upload Generated Tests
        uses: actions/upload-artifact@v4
        with:
          name: security-tests
          path: tests/security/
```

### Example 3: Fast PR Security Check (Changed Files Only)

```yaml
name: PR Security Check

on:
  pull_request:

jobs:
  pr-security:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Need full history for git diff

      - name: Fast Security Check
        uses: securedotcom/agent-os-action@v2.2.0
        with:
          ai-provider: anthropic
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}

          # Analyze only changed files (faster)
          only-changed: 'true'

          # Enable exploit analysis, skip test generation (faster)
          multi-agent-mode: 'sequential'
          enable-exploit-analysis: 'true'
          generate-security-tests: 'false'

          # Lower budget for faster execution
          max-cost-usd: '1.00'

          comment-on-pr: 'true'
```

## Outputs

Aardvark mode provides additional outputs you can use in subsequent steps:

```yaml
- name: Agent OS Review
  id: review
  uses: securedotcom/agent-os-action@v2.2.0
  with: ...

- name: Check Results
  run: |
    echo "Trivial exploitability: ${{ steps.review.outputs.exploitability-trivial }}"
    echo "Moderate exploitability: ${{ steps.review.outputs.exploitability-moderate }}"
    echo "Exploit chains: ${{ steps.review.outputs.exploit-chains-found }}"
    echo "Tests generated: ${{ steps.review.outputs.tests-generated }}"
```

**Available Outputs**:
- `exploitability-trivial` - Number of trivially exploitable vulnerabilities
- `exploitability-moderate` - Number of moderately exploitable vulnerabilities
- `exploitability-complex` - Number of complex exploitability vulnerabilities
- `exploit-chains-found` - Number of exploit chains identified
- `tests-generated` - Number of security test files generated

## Cost Estimates

Aardvark mode includes additional agents, which increases cost:

| Mode | Agents | Est. Cost | Duration |
|------|--------|-----------|----------|
| **Single Agent** | 1 | $0.15-0.20 | 1-2 min |
| **Multi-Agent (Standard)** | 5 | $0.75 | 5-7 min |
| **Multi-Agent (Aardvark)** | 7 | $1.00 | 8-10 min |

**Cost Breakdown**:
- security-reviewer: $0.10
- exploit-analyst: $0.05
- security-test-generator: $0.05
- performance-reviewer: $0.08
- test-coverage-reviewer: $0.08
- code-quality-reviewer: $0.08
- review-orchestrator: $0.06

**Cost Optimization Tips**:
1. Use `only-changed: 'true'` for PR reviews (saves ~94%)
2. Disable test generation for faster checks (`generate-security-tests: 'false'`)
3. Use scheduled workflows instead of on every push
4. Set `max-cost-usd` to enforce budget limits

## Understanding the Report

### Exploitability Matrix

```
                 Exploitability →
           Trivial | Moderate | Complex | Theoretical
         ---------|----------|---------|-------------
Critical |  🔥🔥   |    🔥    |   ⚠️    |     ⚠️
High     |   🔥    |    ⚠️    |   ℹ️    |     ℹ️
Medium   |   ⚠️    |    ℹ️    |   ✓    |     ✓
Low      |   ℹ️    |    ✓    |   ✓    |     ✓

Legend:
🔥 = IMMEDIATE (24-48 hours)
⚠️ = URGENT (1 week)
ℹ️ = HIGH (1 month)
✓ = MEDIUM (next release)
```

### Exploit Chain Format

```markdown
[CHAIN-001] Attack Chain Title

Attack Scenario: High-level description

Steps:
1. [VULN-ID] Initial Access (⚠️ Trivial, 5 min)
2. [VULN-ID] Privilege Escalation (🟨 Moderate, 15 min)
3. [VULN-ID] Data Exfiltration (⚠️ Trivial, 5 min)

Overall Exploitability: ⚠️ Trivial (25 minutes total)
Detection Likelihood: Low (no logging)
Impact: Critical (full database compromise)

Strategic Fix: Fixing VULN-001 blocks entire chain at step 1
```

### Generated Test Structure

```
tests/
├── security/           # Unit tests for vulnerabilities
│   ├── vuln_001_sql_injection_test.py
│   └── vuln_002_auth_bypass_test.py
├── integration/        # End-to-end security tests
│   └── security/
│       └── exploit_chain_001_test.py
├── fuzz/              # Fuzzing tests
│   └── input_validation_fuzz.py
└── exploits/          # PoC exploits (⚠️ authorized testing only!)
    ├── poc_vuln_001.py
    └── README.md
```

## Best Practices

### 1. Use Exploit Analysis on Every PR

Enable exploit analysis for all pull requests to catch vulnerabilities before they reach production:

```yaml
on:
  pull_request:
    branches: [ main ]
```

### 2. Set Appropriate Exploitability Thresholds

For high-security applications (finance, healthcare, infrastructure):
```yaml
exploitability-threshold: 'trivial'
fail-on-blockers: 'true'
```

For standard applications:
```yaml
exploitability-threshold: 'moderate'
fail-on: 'security:critical'
```

### 3. Integrate Generated Tests into CI

```yaml
- name: Run Generated Security Tests
  run: |
    pytest tests/security/
    pytest tests/integration/security/
```

### 4. Review Exploit Chains Weekly

Schedule weekly deep audits to identify new exploit chains:

```yaml
on:
  schedule:
    - cron: '0 9 * * 1'  # Monday 9 AM
```

### 5. Use PoC Exploits Responsibly

⚠️ **WARNING**: PoC exploits are for authorized testing only!

```bash
# Safe mode: Just verify vulnerability exists
python tests/exploits/poc_vuln_001.py http://localhost:3000 --verify

# Full exploit (authorized environments only!)
python tests/exploits/poc_vuln_001.py https://staging.example.com
```

## Comparison: Traditional vs. Aardvark Mode

### Traditional Security Scanning

```
✅ Finds SQL injection vulnerability
✅ Severity: Critical (CVSS 9.8)
✅ Recommendation: Use parameterized queries
```

### Aardvark Mode

```
✅ Finds SQL injection vulnerability
✅ Severity: Critical (CVSS 9.8)
 Exploitability: ⚠️ Trivial (<10 minutes to exploit)
 Part of exploit chains: CHAIN-001, CHAIN-003
 Attack prerequisites: None (unauthenticated endpoint)
 Real-world impact: Full database access, GDPR violation ($20M fine)
 Strategic priority: FIX IMMEDIATELY (blocks 2 exploit chains)
 Tests generated:
   - tests/security/vuln_001_sql_injection_test.py (5 test cases)
   - tests/exploits/poc_vuln_001.py (PoC validation)
 Fix validation: Run `pytest tests/security/vuln_001*` to verify fix
✅ Recommendation: Use parameterized queries
```

## Troubleshooting

### Issue: No exploit chains found

**Cause**: May be legitimate (no chainable vulnerabilities) or insufficient context

**Solution**:
```yaml
# Ensure full codebase analysis
only-changed: 'false'
max-files: 200

# Increase budget for deeper analysis
max-cost-usd: '2.00'
```

### Issue: Too many tests generated

**Cause**: Generating tests for all vulnerabilities

**Solution**:
```yaml
# Only generate tests for critical/high severity
generate-security-tests: 'true'
# Configure in agent settings to filter by severity
```

### Issue: High cost

**Cause**: Aardvark mode runs 7 agents vs 5 in standard mode

**Solutions**:
1. Use `only-changed: 'true'` for PR reviews
2. Disable test generation: `generate-security-tests: 'false'`
3. Run comprehensive audits weekly instead of on every push
4. Set strict budget: `max-cost-usd: '1.00'`

## FAQ

**Q: Is Aardvark mode enabled by default?**
A: Yes, if `multi-agent-mode: 'sequential'` is set. You can disable with `enable-exploit-analysis: 'false'`.

**Q: How accurate is the exploitability classification?**
A: The exploit-analyst agent uses LLM reasoning + CVSS metrics to assess exploitability. It's highly accurate but should be reviewed by security experts for critical systems.

**Q: Can I use the generated PoC exploits?**
A: ⚠️ Only in authorized testing environments! Using PoC exploits against systems without permission is illegal.

**Q: Do generated tests replace manual testing?**
A: No. Generated tests provide baseline coverage but should be reviewed and enhanced by developers.

**Q: What's the difference from traditional SAST tools?**
A: Traditional SAST finds vulnerabilities. Aardvark mode adds:
  - Real-world exploitability assessment
  - Exploit chain analysis
  - Automated test generation
  - Strategic remediation guidance

**Q: Does this work with other AI providers?**
A: Yes! Supports Anthropic Claude (recommended), OpenAI GPT-4, and local Ollama models.

## Further Reading

- [Agent OS Documentation](https://github.com/securedotcom/agent-os-action)
- [Security Review Standards](../profiles/default/standards/review/)
- [Exploit Analysis Standards](../profiles/default/standards/exploit-analysis/)
- [Test Generation Standards](../profiles/default/standards/test-generation/)
- [OpenAI Aardvark Announcement](https://openai.com/index/introducing-aardvark/)

## Workflow Examples

Ready-to-use workflow examples are available in [.github/workflows/examples/](../.github/workflows/examples/):

- **[aardvark-mode.yml](../.github/workflows/examples/aardvark-mode.yml)** - Comprehensive security analysis with exploit chains and test generation
- **[security-test-generation.yml](../.github/workflows/examples/security-test-generation.yml)** - Auto-generate security tests only
- **[exploit-analysis-only.yml](../.github/workflows/examples/exploit-analysis-only.yml)** - Daily exploit chain analysis without test generation

## Support

For issues or questions:
- GitHub Issues: https://github.com/securedotcom/agent-os-action/issues
- Documentation: https://github.com/securedotcom/agent-os-action/docs
- Email: support@secured.com
