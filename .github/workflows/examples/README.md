# Agent OS Aardvark Mode Workflow Examples

This directory contains ready-to-use workflow examples for Agent OS Aardvark mode - advanced exploit analysis and security test generation.

## Available Workflows

### 1. [aardvark-mode.yml](aardvark-mode.yml)
**Comprehensive Security Analysis with Exploit Chains**

Full Aardvark mode with:
- Exploit chain analysis
- Exploitability classification (trivial, moderate, complex)
- Automatic security test generation
- SARIF upload to Security tab
- PR comments on trivial exploitability

**Best for**: Complete security analysis on PRs and scheduled audits

**Triggers**:
- Pull requests
- Push to main
- Manual workflow dispatch
- Weekly schedule (Monday 9 AM)

**Cost**: ~$2.00 per run

```bash
# Copy to your repository
cp aardvark-mode.yml ../../aardvark-security-review.yml
```

---

### 2. [security-test-generation.yml](security-test-generation.yml)
**Auto-Generate Security Tests Only**

Focuses solely on security test generation:
- Generates unit tests for vulnerabilities
- Creates integration tests for exploit chains
- Fuzz tests for input validation
- Commits generated tests to the repository

**Best for**: Label-triggered test generation, automated test enhancement

**Triggers**:
- When `needs-security-tests` label is applied
- Manual workflow dispatch

**Cost**: ~$1.00 per run

```bash
# Copy to your repository
cp security-test-generation.yml ../../auto-generate-tests.yml
```

---

### 3. [exploit-analysis-only.yml](exploit-analysis-only.yml)
**Daily Exploit Chain Analysis**

Analyzes exploitability without generating tests:
- Daily scheduled security analysis
- Creates issues for trivial exploitability
- Uploads SARIF to Security tab
- Doesn't fail builds (reporting only)

**Best for**: Continuous security monitoring, daily security reports

**Triggers**:
- Daily schedule (2 AM)
- Manual workflow dispatch

**Cost**: ~$1.50 per run

```bash
# Copy to your repository
cp exploit-analysis-only.yml ../../daily-exploit-analysis.yml
```

---

## Quick Start

### 1. Choose a Workflow

Pick the workflow that best matches your use case:
- **Full security** → `aardvark-mode.yml`
- **Test generation only** → `security-test-generation.yml`
- **Daily monitoring** → `exploit-analysis-only.yml`

### 2. Copy to Your Repository

```bash
# From the examples directory
cp aardvark-mode.yml ../../aardvark-security-review.yml
```

### 3. Configure API Key

Add your Anthropic API key as a GitHub secret:

```bash
# Go to: Repository → Settings → Secrets → Actions
# Add: ANTHROPIC_API_KEY = sk-ant-xxxxx
```

### 4. Customize (Optional)

Edit the workflow to match your needs:
- Adjust `exploitability-threshold`
- Change `max-cost-usd` budget
- Modify trigger conditions
- Update file paths

### 5. Commit and Run

```bash
git add .github/workflows/aardvark-security-review.yml
git commit -m "Add Aardvark security analysis"
git push
```

---

## Configuration Options

### Aardvark Mode Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `enable-exploit-analysis` | `true` | Enable exploit chain analysis |
| `generate-security-tests` | `true` | Auto-generate security tests |
| `exploitability-threshold` | `trivial` | Block merge threshold |

### Exploitability Thresholds

| Threshold | When to Use | Description |
|-----------|-------------|-------------|
| `trivial` | High security apps | Block on <10 min exploits |
| `moderate` | Standard apps | Block on <4 hour exploits |
| `complex` | Low security apps | Block on complex exploits |
| `none` | Reporting only | Never block |

### Cost Optimization

| Setting | Cost Impact | When to Use |
|---------|-------------|-------------|
| `only-changed: 'true'` | -94% | PR reviews |
| `generate-security-tests: 'false'` | -5% | Skip test generation |
| `max-cost-usd: '1.00'` | Cap spending | Budget enforcement |

---

## Outputs

All workflows provide these outputs:

```yaml
steps:
  - id: review
    uses: securedotcom/agent-os-action@v2.2.0

  - name: Use Outputs
    run: |
      echo "Trivial: ${{ steps.review.outputs.exploitability-trivial }}"
      echo "Chains: ${{ steps.review.outputs.exploit-chains-found }}"
      echo "Tests: ${{ steps.review.outputs.tests-generated }}"
```

**Available Outputs**:
- `exploitability-trivial` - Trivially exploitable count
- `exploitability-moderate` - Moderately exploitable count
- `exploitability-complex` - Complex exploitability count
- `exploit-chains-found` - Exploit chains identified
- `tests-generated` - Security tests generated

---

## Examples by Use Case

### For Startups (Cost-Conscious)
```yaml
# Use aardvark-mode.yml with:
only-changed: 'true'
max-cost-usd: '0.50'
generate-security-tests: 'false'
```

### For Enterprise (High Security)
```yaml
# Use aardvark-mode.yml with:
exploitability-threshold: 'trivial'
fail-on: 'security:critical,security:high'
max-cost-usd: '5.00'
```

### For Open Source (Scheduled Only)
```yaml
# Use exploit-analysis-only.yml
# Run weekly instead of daily
schedule:
  - cron: '0 9 * * 1'  # Monday 9 AM
```

---

## Further Reading

- [Aardvark Mode Documentation](../../../docs/aardvark-mode.md) - Complete guide
- [Agent OS README](../../../README.md) - Main documentation
- [Action Inputs](../../../action.yml) - All configuration options

---

## Support

Questions or issues?
- [GitHub Issues](https://github.com/securedotcom/agent-os-action/issues)
- [Documentation](https://github.com/securedotcom/agent-os-action/docs)
- Email: support@secured.com
