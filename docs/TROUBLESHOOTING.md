# Troubleshooting Guide

Common issues and their solutions for Agent OS Code Reviewer.

---

## 🔍 Quick Diagnosis

**Start here if you're not sure what's wrong:**

```bash
# Check workflow status
gh run list --workflow=code-review.yml --limit 5

# View latest run logs
gh run view --log

# Check secrets
gh secret list

# Verify workflow file
cat .github/workflows/code-review.yml
```

---

## 🔑 API Key Issues

### Issue: "invalid x-api-key" or "authentication_error"

**Symptoms:**
- Workflow fails with 401 error
- Logs show "invalid x-api-key"
- Falls back to mock reports

**Causes:**
1. API key not set in GitHub Secrets
2. API key is incorrect or expired
3. Secret name is wrong
4. Using Cursor key instead of Anthropic key

**Solutions:**

**1. Verify Secret Exists:**
```bash
gh secret list --repo owner/repo
```
Should show `ANTHROPIC_API_KEY`

**2. Check Secret Name:**
Must be exactly `ANTHROPIC_API_KEY` (case-sensitive)

**3. Verify API Key Format:**
- Anthropic keys start with: `sk-ant-`
- Cursor keys start with: `key_` (won't work directly)

**4. Regenerate API Key:**
1. Go to https://console.anthropic.com/settings/keys
2. Delete old key
3. Create new key
4. Update GitHub Secret

**5. Update Secret:**
```bash
gh secret set ANTHROPIC_API_KEY --repo owner/repo
# Paste new key when prompted
```

---

## 🚫 Workflow Not Running

### Issue: Scheduled workflow doesn't trigger

**Symptoms:**
- No automatic runs on schedule
- Manual trigger works fine

**Causes:**
1. Cron syntax error
2. Repository not active enough
3. GitHub Actions disabled

**Solutions:**

**1. Verify Cron Syntax:**
```yaml
# ✅ Correct
schedule:
  - cron: '0 2 * * 0'  # Sundays at 2 AM UTC

# ❌ Wrong
schedule:
  - cron: '0 2 * * 7'  # Invalid day (use 0 for Sunday)
```

**2. Test Cron Expression:**
Visit: https://crontab.guru/

**3. Check Repository Activity:**
GitHub may not trigger scheduled workflows for inactive repos.
Solution: Make a commit or trigger manually once.

**4. Verify Actions Enabled:**
Repository → Settings → Actions → General → Allow all actions

---

## 📝 No Pull Request Created

### Issue: Workflow completes but no PR appears

**Symptoms:**
- Workflow shows success
- No PR in repository
- Logs show "No issues found" or similar

**Causes:**
1. No issues found (clean codebase!)
2. PR creation disabled
3. Insufficient permissions
4. Branch protection rules

**Solutions:**

**1. Check Workflow Logs:**
```bash
gh run view --log | grep -i "PR\|pull request\|blocker"
```

**2. Verify PR Creation Setting:**
```yaml
with:
  comment-on-pr: 'true'  # Must be 'true' as string
```

**3. Check Permissions:**
```yaml
permissions:
  contents: write
  pull-requests: write
```

**4. Review Branch Protection:**
Repository → Settings → Branches → Check if PRs are allowed

**5. Look for Existing PR:**
```bash
gh pr list --label "automated-review"
```
Agent OS updates existing PRs instead of creating duplicates.

---

## 🤖 Mock Reports Instead of Real Analysis

### Issue: Getting template reports, not AI analysis

**Symptoms:**
- Reports look generic
- Same issues every time
- No file-specific findings

**Causes:**
1. API key not configured
2. API key invalid
3. Fallback to mock reports

**Solutions:**

**1. Verify API Key:**
```bash
gh secret list | grep ANTHROPIC
```

**2. Check Workflow Logs:**
```bash
gh run view --log | grep -i "anthropic\|cursor\|api key"
```

Look for:
- "🔑 Using Anthropic API" (good)
- "⚠️ Cursor API keys cannot be used" (need Anthropic key)
- "❌ Error: ANTHROPIC_API_KEY not set" (add secret)

**3. Test API Key Manually:**
```bash
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: $YOUR_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{"model":"claude-3-5-sonnet-20240620","max_tokens":100,"messages":[{"role":"user","content":"Hello"}]}'
```

---

## 📦 Workflow Fails During Installation

### Issue: "Agent OS installation failed"

**Symptoms:**
- Workflow fails early
- Error about missing files
- Installation step fails

**Causes:**
1. Action version mismatch
2. Missing files in action repository
3. Network issues

**Solutions:**

**1. Use Latest Version:**
```yaml
uses: securedotcom/agent-os-action@v1.0.14  # Current latest
```

**2. Check Action Repository:**
Visit: https://github.com/securedotcom/agent-os-action
Verify it exists and is public.

**3. Clear Actions Cache:**
Repository → Actions → Caches → Delete all

**4. Retry Workflow:**
```bash
gh run rerun <run-id>
```

---

## 🐌 Workflow Takes Too Long

### Issue: Workflow runs for 10+ minutes

**Symptoms:**
- Workflow doesn't complete
- Times out after 6 hours
- Very slow analysis

**Causes:**
1. Large codebase (>1000 files)
2. API rate limiting
3. Network issues

**Solutions:**

**1. Limit File Count:**
The script already limits to 50 files, but you can adjust in `run-ai-audit.py`:
```python
return important_files[:30]  # Reduce to 30 files
```

**2. Focus on Specific Directories:**
```yaml
with:
  project-path: './src'  # Only analyze src directory
```

**3. Check API Limits:**
Visit: https://console.anthropic.com/settings/limits

**4. Split into Multiple Jobs:**
```yaml
jobs:
  review-frontend:
    steps:
      - uses: securedotcom/agent-os-action@v1.0.14
        with:
          project-path: './frontend'
  
  review-backend:
    steps:
      - uses: securedotcom/agent-os-action@v1.0.14
        with:
          project-path: './backend'
```

---

## 💸 Unexpected API Costs

### Issue: Higher than expected Anthropic bills

**Symptoms:**
- Bill higher than $10/month
- Many API calls
- Large token usage

**Causes:**
1. Running too frequently
2. Analyzing too many files
3. Large file sizes

**Solutions:**

**1. Reduce Frequency:**
```yaml
schedule:
  - cron: '0 2 * * 0'  # Weekly instead of daily
```

**2. Monitor Usage:**
Visit: https://console.anthropic.com/settings/usage

**3. Set Billing Alerts:**
Anthropic Console → Settings → Billing → Set alert at $10

**4. Optimize File Selection:**
Edit `run-ai-audit.py` to skip large files:
```python
if len(content) < 10000:  # Skip files >10KB
    important_files.append(...)
```

---

## 🔒 Permission Errors

### Issue: "Permission denied" or "403 Forbidden"

**Symptoms:**
- Can't create PR
- Can't push to branch
- Can't add labels

**Causes:**
1. Insufficient GITHUB_TOKEN permissions
2. Branch protection rules
3. Organization restrictions

**Solutions:**

**1. Add Permissions:**
```yaml
permissions:
  contents: write
  pull-requests: write
  issues: write
```

**2. Use Personal Access Token:**
```yaml
env:
  GITHUB_TOKEN: ${{ secrets.PAT_TOKEN }}
```

**3. Check Organization Settings:**
Organization → Settings → Actions → General → Workflow permissions

---

## 📱 Slack Notifications Not Working

### Issue: No Slack notifications

**Symptoms:**
- Workflow completes
- No Slack message
- No errors in logs

**Causes:**
1. GitHub App not installed
2. Not subscribed to repository
3. Wrong channel

**Solutions:**

**1. Install GitHub App:**
Visit: https://slack.github.com/

**2. Subscribe to Repository:**
In Slack channel:
```
/github subscribe owner/repo pulls reviews comments
```

**3. Verify Subscription:**
```
/github subscribe list
```

**4. Check App Permissions:**
Slack → Apps → GitHub → Settings → Permissions

**Detailed Guide:** [docs/templates/slack-setup.md](templates/slack-setup.md)

---

## 🔄 Duplicate PRs Created

### Issue: Multiple PRs with same findings

**Symptoms:**
- New PR created each run
- Old PRs not updated
- Many open audit PRs

**Causes:**
1. Duplicate detection not working
2. Branch name conflicts
3. Different PR titles

**Solutions:**

**1. Check for Existing PRs:**
```bash
gh pr list --label "automated-review"
```

**2. Close Duplicate PRs:**
```bash
gh pr close <pr-number> --comment "Duplicate, see #<latest-pr>"
```

**3. Verify Action Version:**
Ensure using v1.0.14 or later (has duplicate detection).

---

## 📊 Empty or Incomplete Reports

### Issue: Report has no findings or is incomplete

**Symptoms:**
- Report exists but empty
- Only partial analysis
- Missing sections

**Causes:**
1. API timeout
2. File parsing errors
3. Unsupported language

**Solutions:**

**1. Check Workflow Logs:**
```bash
gh run view --log | grep -i "error\|warning\|failed"
```

**2. Verify File Types:**
Supported: `.js`, `.ts`, `.py`, `.java`, `.go`, `.rs`, `.rb`, `.php`, `.cs`

**3. Check File Encoding:**
Ensure files are UTF-8 encoded.

**4. Review File Sizes:**
Very large files (>50KB) may be skipped.

---

## 🆘 Still Need Help?

### Debugging Steps

1. **Enable Debug Logging:**
```yaml
env:
  ACTIONS_STEP_DEBUG: true
```

2. **Download Logs:**
```bash
gh run view <run-id> --log > debug.log
```

3. **Check Artifacts:**
```bash
gh run download <run-id>
```

### Get Support

- **GitHub Issues**: https://github.com/securedotcom/agent-os-action/issues
- **Discussions**: https://github.com/securedotcom/agent-os-action/discussions
- **Documentation**: Check other guides in `/docs`

### Provide This Information

When asking for help, include:
- Workflow run URL
- Relevant log excerpts
- Workflow file (sanitized)
- Error messages
- What you've tried

---

## 📚 Related Documentation

- **[Getting Started](GETTING_STARTED.md)** - Initial setup
- **[Setup Guide](SETUP_GUIDE.md)** - Complete configuration
- **[API Key Setup](API_KEY_SETUP.md)** - API key management
- **[FAQ](FAQ.md)** - Common questions

---

**Last Updated**: October 24, 2025

