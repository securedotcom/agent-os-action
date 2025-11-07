---
title: GitHub Action Deployment Runbook
sidebar_position: 1
ai_generated: true
service: agent-os-action
on_call_priority: high
tags: [runbook, deployment, github-actions]
---

> ⚠️ **AI-Generated Documentation**
> Please test all procedures in a test repository before using in production.

# GitHub Action Deployment Runbook

## Service Overview

**Purpose**: Deploy and maintain the Agent OS Code Reviewer GitHub Action

**Owner**: Platform Engineering Team

**Repository**: https://github.com/securedotcom/agent-os-action

**Status Page**: GitHub Actions Status

## Quick Links

- 📊 [GitHub Actions Usage](https://github.com/securedotcom/agent-os-action/actions)
- 🐛 [Issues](https://github.com/securedotcom/agent-os-action/issues)
- 📖 [Main Documentation](../../README.md)
- 🔐 [Security Policy](../../SECURITY.md)

## Health Checks

### Verify Action is Working

```bash
# Check recent workflow runs
gh run list --repo securedotcom/agent-os-action --limit 10

# View specific run details
gh run view <run-id> --repo securedotcom/agent-os-action --log

# Check action marketplace status
gh api /repos/securedotcom/agent-os-action
```

### Expected Behavior

✅ **Healthy indicators**:
- Action completes in 2-3 minutes (single-agent mode)
- Cost estimate: ~$0.30 per run
- Generates reports in `.agent-os/reviews/`
- Uploads SARIF to Code Scanning (if enabled)
- Posts PR comments with findings

❌ **Unhealthy indicators**:
- Runs taking >10 minutes
- Cost exceeding $2 per run
- API authentication failures
- SARIF upload failures
- No reports generated

## Deployment

### Publishing a New Version

```bash
# 1. Ensure you're on main branch and up to date
git checkout main
git pull origin main

# 2. Update version in action.yml
vim action.yml
# Update version number in metadata

# 3. Update CHANGELOG.md
vim CHANGELOG.md
# Add release notes for new version

# 4. Update version in pyproject.toml
vim pyproject.toml
# Update version = "X.Y.Z"

# 5. Commit changes
git add action.yml CHANGELOG.md pyproject.toml
git commit -m "Release v3.2.0"

# 6. Create and push tag
git tag v3.2.0
git push origin v3.2.0

# 7. Update major version tag (for users using @v3)
git tag -f v3
git push origin v3 --force

# 8. Create GitHub Release
gh release create v3.2.0 \
  --title "v3.2.0 - Feature Release" \
  --notes-file CHANGELOG.md \
  --latest

# 9. Verify release
gh release view v3.2.0
```

### Rollback Procedure

```bash
# 1. Identify last known good version
gh release list --limit 5

# 2. Revert major version tag to previous version
git tag -f v3 v3.1.0
git push origin v3 --force

# 3. Create rollback notice
gh issue create \
  --title "Rolled back v3 to v3.1.0" \
  --body "Due to issues with v3.2.0, rolled back to v3.1.0. See #123 for details." \
  --label "rollback"

# 4. Notify users (if critical)
# Post in GitHub Discussions or create announcement issue

# 5. Fix issues and prepare new release
git checkout -b fix/critical-issue
# Make fixes
# Follow release process above
```

### Hotfix Process

```bash
# 1. Create hotfix branch from tag
git checkout -b hotfix/v3.1.1 v3.1.0

# 2. Make critical fix
# Edit files
git add .
git commit -m "Fix critical security issue"

# 3. Tag hotfix
git tag v3.1.1
git push origin v3.1.1

# 4. Update major version tag
git tag -f v3
git push origin v3 --force

# 5. Create release
gh release create v3.1.1 \
  --title "v3.1.1 - Security Hotfix" \
  --notes "Critical security fix. All users should upgrade immediately."

# 6. Merge back to main
git checkout main
git merge hotfix/v3.1.1
git push origin main
```

## Common Operations

### Testing Changes Locally

```bash
# 1. Clone repository
git clone https://github.com/securedotcom/agent-os-action
cd agent-os-action

# 2. Set up Python environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -e ".[dev]"

# 4. Set up environment variables
cp .env.example .env
vim .env
# Add: ANTHROPIC_API_KEY=sk-ant-...

# 5. Run tests
pytest tests/ -v

# 6. Run audit on sample code
python3 scripts/run_ai_audit.py . audit

# 7. Check generated reports
ls -la .agent-os/reviews/
cat .agent-os/reviews/audit-report.md
```

### Testing in a Test Repository

```yaml
# .github/workflows/test-agent-os.yml
name: Test Agent OS Action

on:
  workflow_dispatch:

jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
      security-events: write
    
    steps:
      - uses: actions/checkout@v4
      
      # Test local action (before publishing)
      - uses: ./
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          review-type: 'audit'
          max-files: 10
          cost-limit: '0.50'
      
      - name: Check outputs
        run: |
          ls -la .agent-os/reviews/
          cat .agent-os/reviews/metrics.json
```

### Updating Dependencies

```bash
# 1. Update Python dependencies
pip install --upgrade anthropic openai tenacity
pip freeze > requirements.txt

# 2. Update pyproject.toml with new versions
vim pyproject.toml

# 3. Run tests
pytest tests/ -v --cov

# 4. Check for breaking changes
# Review changelogs of updated packages

# 5. Commit changes
git add pyproject.toml requirements.txt
git commit -m "Update dependencies: anthropic 0.19.0, openai 1.5.0"

# 6. Create PR
gh pr create \
  --title "Update dependencies" \
  --body "Updates anthropic and openai libraries. All tests passing."
```

## Troubleshooting

### High Cost Issues

**Symptoms**: Cost exceeding $1 per run, unexpected charges

**Investigation Steps**:
```bash
# 1. Check metrics from recent run
cat .agent-os/reviews/metrics.json | jq '.cost_usd, .files_reviewed, .tokens_input, .tokens_output'

# 2. Check configuration
cat .github/workflows/code-review.yml | grep -A 5 "agent-os-action"

# 3. Check file count being analyzed
find . -name "*.py" -o -name "*.js" | wc -l
```

**Common Causes**:
- Multi-agent mode enabled (`multi-agent-mode: sequential`)
- No file limits set (`max-files` not configured)
- Analyzing large files or many files
- No path exclusions (`exclude-paths` not set)

**Resolution**:
```yaml
# Add cost controls to workflow
- uses: securedotcom/agent-os-action@v3
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    multi-agent-mode: 'single'  # Use single-agent (recommended)
    max-files: 50                # Limit files analyzed
    cost-limit: '1.0'            # Hard cap at $1
    exclude-paths: 'tests/**,*.test.*,node_modules/**'
```

### SARIF Upload Failures

**Symptoms**: "Code scanning is not enabled" or SARIF upload errors

**Investigation Steps**:
```bash
# 1. Check if Code Scanning is enabled
gh api /repos/OWNER/REPO/code-scanning/alerts

# 2. Check SARIF file was generated
ls -la .agent-os/reviews/results.sarif

# 3. Validate SARIF format
cat .agent-os/reviews/results.sarif | jq '.'
```

**Resolution**:
1. **Enable Code Scanning**:
   - Go to repository Settings → Security → Code scanning
   - Click "Set up code scanning"
   - Choose "GitHub Actions" or "Default setup"

2. **Check Permissions**:
```yaml
permissions:
  security-events: write  # Required for SARIF upload
```

3. **Add continue-on-error** (if Code Scanning not needed):
```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: .agent-os/reviews/results.sarif
  continue-on-error: true  # Don't fail if upload fails
```

### API Rate Limiting

**Symptoms**: "Rate limit exceeded" errors, 429 responses

**Investigation Steps**:
```bash
# Check error logs
gh run view <run-id> --log | grep -i "rate limit"

# Check recent run frequency
gh run list --limit 20 | head -10
```

**Resolution**:
1. **Reduce Frequency**: Space out workflow runs
2. **Use Retry Logic**: Already implemented with `tenacity`
3. **Contact Anthropic**: Request rate limit increase if needed
4. **Use Different API Key**: Rotate between multiple keys (enterprise)

### No Reports Generated

**Symptoms**: `.agent-os/reviews/` directory empty or missing

**Investigation Steps**:
```bash
# 1. Check workflow logs
gh run view <run-id> --log

# 2. Check for Python errors
gh run view <run-id> --log | grep -i "error\|exception\|traceback"

# 3. Check API key is set
gh secret list | grep ANTHROPIC
```

**Common Causes**:
- API key not set or invalid
- Python script crashed before generating reports
- File selection resulted in 0 files
- Cost limit reached before analysis

**Resolution**:
```bash
# 1. Verify API key
gh secret set ANTHROPIC_API_KEY --body "sk-ant-..."

# 2. Test locally
export ANTHROPIC_API_KEY="sk-ant-..."
python3 scripts/run_ai_audit.py . audit

# 3. Check file selection
python3 scripts/run_ai_audit.py . audit --dry-run
```

## Configuration

### Required Secrets

| Secret | Purpose | How to Get | Rotation Frequency |
|--------|---------|------------|-------------------|
| `ANTHROPIC_API_KEY` | Claude API access | [Anthropic Console](https://console.anthropic.com/) | Every 90 days |

### Optional Secrets

| Secret | Purpose | When Needed |
|--------|---------|-------------|
| `OPENAI_API_KEY` | GPT-4 access | When using OpenAI provider |
| `GITHUB_TOKEN` | GitHub API access | Auto-provided by Actions |

### Action Configuration

Key inputs (see [action.yml](../../action.yml) for full list):

```yaml
inputs:
  # Required
  anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
  
  # Review settings
  review-type: 'audit'              # audit | security | review
  project-type: 'backend-api'       # auto | backend-api | dashboard-ui | data-pipeline
  
  # Cost controls
  multi-agent-mode: 'single'        # single (recommended) | sequential
  max-files: 50
  cost-limit: '1.0'
  
  # Quality gates
  fail-on-blockers: 'true'
  fail-on: 'security:critical,security:high'
  
  # Outputs
  comment-on-pr: 'true'
  upload-reports: 'true'
```

## Monitoring

### Key Metrics

Track these metrics from `metrics.json`:

| Metric | Target | Alert Threshold |
|--------|--------|-----------------|
| Cost per run | ~$0.30 | > $2.00 |
| Duration | 2-3 min | > 10 min |
| Files reviewed | 20-50 | < 5 or > 100 |
| Critical findings | Varies | > 10 |
| Success rate | > 95% | < 90% |

### Dashboards

**TODO**: Set up monitoring dashboard with:
- Run success rate over time
- Average cost per run
- Average duration
- Findings by severity
- Most common failure reasons

## Security

### API Key Rotation

```bash
# 1. Generate new key at https://console.anthropic.com/
# 2. Test new key locally
export ANTHROPIC_API_KEY="sk-ant-new-key..."
python3 scripts/run_ai_audit.py . audit

# 3. Update GitHub secret
gh secret set ANTHROPIC_API_KEY --body "sk-ant-new-key..."

# 4. Trigger test workflow
gh workflow run code-review.yml

# 5. Verify success
gh run list --limit 1

# 6. Revoke old key in Anthropic console
```

### Permissions Audit

Regularly review action permissions:

```yaml
permissions:
  contents: write          # Create branches/PRs
  pull-requests: write     # Comment on PRs
  security-events: write   # Upload SARIF
```

**Principle of Least Privilege**: Only grant permissions actually needed.

## Related Documentation

- [Architecture Overview](../architecture/overview.md)
- [ADR-0001: Use Anthropic Claude](../adrs/0001-use-anthropic-claude.md)
- [Troubleshooting Guide](../TROUBLESHOOTING.md)
- [Security Policy](../../SECURITY.md)

## Contacts

- **Repository**: https://github.com/securedotcom/agent-os-action
- **Issues**: https://github.com/securedotcom/agent-os-action/issues
- **Security**: See [SECURITY.md](../../SECURITY.md)

