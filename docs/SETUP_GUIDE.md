# Complete Setup Guide

This guide will walk you through setting up Agent OS Code Reviewer from scratch.

**Estimated Time**: 30 minutes

---

## 📋 Prerequisites

Before you begin, ensure you have:

- [ ] GitHub repository with Actions enabled
- [ ] Admin access to the repository
- [ ] GitHub CLI installed (`gh`) - [Install here](https://cli.github.com/)
- [ ] Anthropic account - [Sign up here](https://console.anthropic.com/)

---

## Step 1: Get Your Anthropic API Key (5 minutes)

### 1.1 Create Anthropic Account
1. Visit https://console.anthropic.com/
2. Click "Sign Up" and complete registration
3. Verify your email address

### 1.2 Generate API Key
1. Go to https://console.anthropic.com/settings/keys
2. Click "Create Key"
3. Name it: `Agent OS Code Reviewer`
4. Copy the key (starts with `sk-ant-`)
5. **Save it securely** - you won't see it again!

### 1.3 Set Up Billing (Optional but Recommended)
1. Go to https://console.anthropic.com/settings/billing
2. Add payment method
3. Set up billing alerts (recommended: $10/month)

**Cost Estimate**: ~$2-8/month for weekly audits per repository

---

## Step 2: Configure GitHub Secrets (3 minutes)

### 2.1 Add Anthropic API Key

**Via GitHub Web UI:**
1. Go to your repository on GitHub
2. Click **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**
4. Name: `ANTHROPIC_API_KEY`
5. Value: Paste your `sk-ant-...` key
6. Click **Add secret**

**Via GitHub CLI:**
```bash
gh secret set ANTHROPIC_API_KEY --repo owner/repo
# Paste your API key when prompted
```

### 2.2 Verify Secret
```bash
gh secret list --repo owner/repo
```

You should see `ANTHROPIC_API_KEY` in the list.

---

## Step 3: Install the GitHub Action (10 minutes)

### 3.1 Create Workflow File

Create `.github/workflows/code-review.yml`:

```yaml
name: Agent OS Code Review

on:
  # Weekly schedule - Sundays at 2 AM UTC
  schedule:
    - cron: '0 2 * * 0'
  
  # Manual trigger
  workflow_dispatch:
    inputs:
      review_type:
        description: 'Type of review'
        required: true
        default: 'audit'
        type: choice
        options:
        - audit
        - security
        - review
  
  # On pull requests (optional)
  # pull_request:
  #   branches: [ main, master ]

jobs:
  code-review:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      with:
        fetch-depth: 0
    
    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: '18'
        cache: 'npm'
    
    - name: Run Agent OS Code Review
      uses: securedotcom/agent-os-action@v1.0.14
      with:
        review-type: ${{ github.event.inputs.review_type || 'audit' }}
        project-path: '.'
        project-type: 'auto'  # auto-detect or specify: backend-api, dashboard-ui, etc.
        fail-on-blockers: 'false'
        comment-on-pr: 'true'
        upload-reports: 'true'
        anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
        cursor-api-key: ${{ secrets.CURSOR_API_KEY }}  # Optional
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    
    - name: Upload Review Reports
      if: always()
      uses: actions/upload-artifact@v4
      with:
        name: code-review-reports
        path: .agent-os/reviews/
        retention-days: 90
```

### 3.2 Commit and Push

```bash
git add .github/workflows/code-review.yml
git commit -m "Add Agent OS code reviewer"
git push
```

### 3.3 Verify Installation

```bash
gh workflow list
```

You should see "Agent OS Code Review" in the list.

---

## Step 4: Run Your First Review (5 minutes)

### 4.1 Trigger Manually

```bash
gh workflow run code-review.yml --field review_type=audit
```

### 4.2 Monitor Progress

```bash
gh run watch
```

Or visit: `https://github.com/owner/repo/actions`

### 4.3 Check Results

After completion (1-3 minutes):

1. **Pull Request**: Check for new PR with findings
2. **Artifacts**: Download audit report from Actions tab
3. **Logs**: Review workflow logs for details

---

## Step 5: Configure Slack Notifications (Optional, 10 minutes)

### 5.1 Install GitHub App for Slack

1. Visit: https://slack.github.com/
2. Click "Add to Slack"
3. Select your workspace
4. Authorize the app

### 5.2 Connect Repository

In your Slack channel:
```
/github subscribe owner/repo pulls reviews comments
```

### 5.3 Test Notification

Trigger a workflow run and check your Slack channel for notifications.

**Detailed Guide**: See [docs/templates/slack-setup.md](templates/slack-setup.md)

---

## Step 6: Customize Configuration (Optional)

### 6.1 Adjust Review Schedule

Edit `.github/workflows/code-review.yml`:

```yaml
schedule:
  # Daily at midnight
  - cron: '0 0 * * *'
  
  # Or twice weekly (Monday and Thursday)
  - cron: '0 2 * * 1,4'
```

### 6.2 Set Project Type

If auto-detection doesn't work:

```yaml
project-type: 'backend-api'  # or dashboard-ui, data-pipeline, infrastructure
```

### 6.3 Enable PR Reviews

Uncomment in workflow file:

```yaml
pull_request:
  branches: [ main, master ]
```

### 6.4 Fail on Blockers

For stricter enforcement:

```yaml
fail-on-blockers: 'true'  # Workflow fails if critical issues found
```

---

## Step 7: Deploy to Multiple Repositories (Optional)

### 7.1 Use Organization Secrets

For multiple repos in same organization:

1. Go to Organization → Settings → Secrets → Actions
2. Add `ANTHROPIC_API_KEY` as organization secret
3. Select repositories that can access it

### 7.2 Batch Deployment Script

```bash
#!/bin/bash
# deploy-to-repos.sh

REPOS=(
  "owner/repo1"
  "owner/repo2"
  "owner/repo3"
)

for repo in "${REPOS[@]}"; do
  echo "Deploying to $repo..."
  
  # Clone repo
  gh repo clone $repo temp-$repo
  cd temp-$repo
  
  # Copy workflow file
  mkdir -p .github/workflows
  cp ../code-review.yml .github/workflows/
  
  # Commit and push
  git add .github/workflows/code-review.yml
  git commit -m "Add Agent OS code reviewer"
  git push
  
  cd ..
  rm -rf temp-$repo
  
  echo "✅ Deployed to $repo"
done
```

---

## ✅ Verification Checklist

After setup, verify:

- [ ] Anthropic API key is set in GitHub Secrets
- [ ] Workflow file is committed and pushed
- [ ] First workflow run completed successfully
- [ ] Pull request created with findings
- [ ] Audit report available in artifacts
- [ ] No authentication errors in logs
- [ ] Slack notifications working (if configured)
- [ ] Billing alerts set up in Anthropic console

---

## 🔧 Troubleshooting

### Issue: "invalid x-api-key"
**Solution**: Verify API key in GitHub Secrets. Ensure it starts with `sk-ant-`

### Issue: "Workflow not triggering"
**Solution**: Check cron schedule syntax. Test with manual trigger first.

### Issue: "No PR created"
**Solution**: Check workflow logs. Verify `comment-on-pr` is set to `'true'`

### Issue: "Mock reports instead of real analysis"
**Solution**: Verify `ANTHROPIC_API_KEY` secret is set correctly

**More Help**: See [TROUBLESHOOTING.md](TROUBLESHOOTING.md)

---

## 📊 What Happens Next?

### Automated Weekly Reviews
- Every Sunday at 2 AM UTC (or your custom schedule)
- Agent OS analyzes your codebase
- Creates/updates PR with findings
- Sends Slack notification (if configured)
- Uploads detailed report as artifact

### On Pull Requests (if enabled)
- Runs on every PR
- Comments on PR with findings
- Fails workflow if critical issues found (optional)
- Helps catch issues before merge

---

## 🎯 Next Steps

1. **Review First Report**: Check the PR created by Agent OS
2. **Address Findings**: Fix critical issues (merge blockers)
3. **Adjust Configuration**: Tune settings based on your needs
4. **Deploy to More Repos**: Roll out to other repositories
5. **Monitor Trends**: Track code quality over time

---

## 📚 Additional Resources

- **[API Key Setup](API_KEY_SETUP.md)** - Detailed API key configuration
- **[Troubleshooting](TROUBLESHOOTING.md)** - Common issues and solutions
- **[FAQ](FAQ.md)** - Frequently asked questions
- **[Architecture](ARCHITECTURE.md)** - How the system works

---

## 🆘 Need Help?

- **Documentation**: Check other guides in `/docs`
- **GitHub Issues**: Report bugs or request features
- **GitHub Discussions**: Ask questions
- **Slack Template**: Use for org admin requests

---

**Congratulations!** 🎉 You've successfully set up Agent OS Code Reviewer!

Your code is now being monitored 24/7 by an AI-powered senior developer.

