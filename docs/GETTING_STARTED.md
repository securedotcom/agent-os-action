# Getting Started with Agent OS Code Reviewer

**Get up and running in 5 minutes!**

---

## 🎯 What You'll Accomplish

By the end of this guide, you'll have:
- ✅ Agent OS installed in your repository
- ✅ First automated code review completed
- ✅ Pull request with findings created
- ✅ Understanding of how to use the system

---

## 📋 Before You Start

You need:
1. **GitHub repository** with Actions enabled
2. **Anthropic API key** - [Get one here](https://console.anthropic.com/) (takes 2 minutes)
3. **5 minutes** of your time

---

## 🚀 Quick Setup

### Step 1: Get API Key (2 minutes)

1. Visit https://console.anthropic.com/
2. Sign up / Sign in
3. Go to Settings → API Keys
4. Click "Create Key"
5. Copy the key (starts with `sk-ant-`)

### Step 2: Add to GitHub (1 minute)

```bash
# Using GitHub CLI (recommended)
gh secret set ANTHROPIC_API_KEY --repo owner/your-repo
# Paste your API key when prompted

# Or via web: Repository → Settings → Secrets → Actions → New secret
```

### Step 3: Add Workflow File (1 minute)

Create `.github/workflows/code-review.yml`:

```yaml
name: Code Review

on:
  workflow_dispatch:  # Manual trigger for testing
  schedule:
    - cron: '0 2 * * 0'  # Weekly on Sundays

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - uses: securedotcom/agent-os-action@v1.0.14
      with:
        anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Step 4: Commit and Run (1 minute)

```bash
git add .github/workflows/code-review.yml
git commit -m "Add AI code reviewer"
git push

# Trigger first run
gh workflow run code-review.yml
```

### Step 5: Check Results (Wait 2-3 minutes)

```bash
# Watch progress
gh run watch

# Or visit: https://github.com/owner/repo/actions
```

---

## 🎉 Success!

You should now see:

1. **✅ Workflow completed** in GitHub Actions
2. **📋 New pull request** with code review findings
3. **📁 Audit report** available as artifact

---

## 📊 What Just Happened?

Agent OS:
1. ✅ Analyzed your codebase with Claude Sonnet 4
2. ✅ Checked for security vulnerabilities
3. ✅ Identified performance issues
4. ✅ Assessed test coverage
5. ✅ Evaluated code quality
6. ✅ Created PR with actionable findings

---

## 🔍 Understanding Your First Report

### Report Structure

```
📊 Code Review Report
├── Executive Summary
│   ├── Overall Status (APPROVED / REQUIRES FIXES / CRITICAL)
│   ├── Risk Level (LOW / MEDIUM / HIGH)
│   └── Issue Counts (Blockers, Suggestions, Nits)
│
├── 🔴 Merge Blockers (Must Fix)
│   ├── Security Issues
│   ├── Performance Issues
│   ├── Testing Issues
│   └── Code Quality Issues
│
├── 🟡 Suggestions (Recommended)
│   ├── Security Improvements
│   ├── Performance Optimizations
│   ├── Testing Enhancements
│   └── Code Quality Improvements
│
└── ✅ Action Items
    ├── Immediate (Critical)
    └── Follow-up (Nice to Have)
```

### Issue Severity Levels

- **[BLOCKER]** 🔴 - Must fix before merge
- **[SUGGESTION]** 🟡 - Recommended improvement
- **[NIT]** ⚪ - Minor issue, can ignore

---

## 🎯 Next Steps

### 1. Review the Findings
- Open the PR created by Agent OS
- Read through the issues found
- Prioritize critical (blocker) issues

### 2. Fix Critical Issues
- Address all `[BLOCKER]` items
- Test your fixes
- Commit changes

### 3. Configure for Your Needs

**Run more frequently:**
```yaml
schedule:
  - cron: '0 0 * * *'  # Daily
```

**Enable on pull requests:**
```yaml
on:
  pull_request:
    branches: [ main ]
```

**Customize project type:**
```yaml
with:
  project-type: 'backend-api'  # or dashboard-ui, data-pipeline, infrastructure
```

### 4. Set Up Slack Notifications (Optional)

1. Install GitHub App for Slack: https://slack.github.com/
2. In Slack: `/github subscribe owner/repo pulls reviews`
3. Get notified of code review results

---

## 💡 Pro Tips

### Tip 1: Start with Manual Triggers
Test with `workflow_dispatch` before enabling automatic schedules.

### Tip 2: Review in Batches
Fix all blockers at once, then suggestions in a follow-up PR.

### Tip 3: Learn from the AI
Read the explanations - they're educational!

### Tip 4: Adjust Frequency
Weekly is good for most teams. Daily for high-velocity teams.

### Tip 5: Use PR Reviews
Enable on pull requests to catch issues before merge.

---

## 🔧 Common First-Time Issues

### "Invalid API Key"
**Fix**: Double-check the secret name is exactly `ANTHROPIC_API_KEY`

### "No PR Created"
**Fix**: Check if there are any findings. PR only created if issues found.

### "Workflow Not Triggering"
**Fix**: Use manual trigger first (`gh workflow run code-review.yml`)

### "Mock Reports"
**Fix**: Verify API key is set correctly in GitHub Secrets

---

## 📚 Learn More

- **[Complete Setup Guide](SETUP_GUIDE.md)** - Detailed configuration
- **[API Key Setup](API_KEY_SETUP.md)** - API key management
- **[Troubleshooting](TROUBLESHOOTING.md)** - Common issues
- **[FAQ](FAQ.md)** - Frequently asked questions

---

## 🆘 Need Help?

**Quick Help:**
- Check [Troubleshooting Guide](TROUBLESHOOTING.md)
- Review [FAQ](FAQ.md)

**Still Stuck?**
- Open a [GitHub Issue](https://github.com/securedotcom/agent-os-action/issues)
- Ask in [GitHub Discussions](https://github.com/securedotcom/agent-os-action/discussions)

---

## ✅ Checklist

Before moving on, ensure:

- [ ] API key is set in GitHub Secrets
- [ ] Workflow file is committed
- [ ] First workflow run completed
- [ ] Pull request with findings created
- [ ] You understand the report structure
- [ ] You know how to fix issues

---

**Congratulations!** 🎉 You're now using AI-powered code reviews!

**What's Next?**
- Review and fix the findings
- Configure for your team's needs
- Deploy to more repositories
- Set up Slack notifications

---

<div align="center">
  <strong>Happy Coding!</strong> 💻
  <br>
  <sub>Powered by Claude Sonnet 4</sub>
</div>

