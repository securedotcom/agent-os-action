---
title: Deployment Runbook
sidebar_position: 1
ai_generated: true
service: agent-os-action
on_call_priority: high
tags: [runbook, deployment, github-actions]
---

> ⚠️ **AI-Generated Documentation** - Please test all procedures in a test repository before using in production.

# Deployment Runbook

## Quick Links

- 📊 [GitHub Actions](https://github.com/securedotcom/agent-os-action/actions)
- 🐛 [Issues](https://github.com/securedotcom/agent-os-action/issues)
- 📖 [Main Documentation](../../README.md)

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
- Action completes in 2-5 minutes
- Cost estimate: ~$0.30 per run (Claude) or $0.00 (Foundation-Sec)
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

**Symptoms**: Cost exceeding $1 per run

**Investigation**:
```bash
# Check metrics from recent run
cat .agent-os/reviews/metrics.json | jq '.cost_usd, .files_reviewed, .tokens_input, .tokens_output'

# Check configuration
cat .github/workflows/code-review.yml | grep -A 5 "agent-os-action"
```

**Common Causes**:
- Multi-agent mode enabled (`multi-agent-mode: sequential`)
- No file limits set (`max-files` not configured)
- Analyzing large files or many files

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

**Resolution**:
1. **Reduce Frequency**: Space out workflow runs
2. **Use Retry Logic**: Already implemented with `tenacity`
3. **Contact Anthropic**: Request rate limit increase if needed
4. **Use Different API Key**: Rotate between multiple keys (enterprise)

## Configuration

### Required Secrets

| Secret | Purpose | How to Get |
|--------|---------|------------|
| `ANTHROPIC_API_KEY` | Claude API access | [Anthropic Console](https://console.anthropic.com/) |

### Optional Secrets

| Secret | Purpose | When Needed |
|--------|---------|-------------|
| `OPENAI_API_KEY` | GPT-4 access | When using OpenAI provider |
| `GITHUB_TOKEN` | GitHub API access | Auto-provided by Actions |

## Monitoring

### Key Metrics

Track these metrics from `metrics.json`:

| Metric | Target | Alert Threshold |
|--------|--------|-----------------|
| Cost per run | ~$0.30 | > $2.00 |
| Duration | 2-5 min | > 10 min |
| Files reviewed | 20-50 | < 5 or > 100 |
| Success rate | > 95% | < 90% |

## Related Documentation

- [Architecture Overview](../architecture/overview.md)
- [ADR-0001: Use Anthropic Claude](../adrs/0001-use-anthropic-claude.md)
- [Troubleshooting Guide](../../docs/TROUBLESHOOTING.md)
- [Security Policy](../../SECURITY.md)

