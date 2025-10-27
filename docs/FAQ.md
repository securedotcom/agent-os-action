# Frequently Asked Questions (FAQ)

Quick answers to common questions about Agent OS Code Reviewer.

---

## 🎯 General Questions

### What is Agent OS Code Reviewer?

An AI-powered automated code review system that analyzes your codebase for security vulnerabilities, performance issues, test coverage gaps, and code quality problems. It acts as a 24/7 virtual senior developer.

### How does it work?

1. Runs as a GitHub Action on a schedule or PR event
2. Analyzes your code using Claude Sonnet 4 (Anthropic AI)
3. Generates a comprehensive review report
4. Creates/updates a pull request with findings
5. Sends Slack notifications (optional)

### Is it free?

The Agent OS software is open source (MIT license), but you need an Anthropic API key which costs ~$2-8/month per repository for weekly audits.

### What languages are supported?

Best support for: JavaScript, TypeScript, Python, Java, Go, Rust, Ruby, PHP, C#

The AI can analyze any language, but has most training data for the above.

---

## 🔑 API Keys & Authentication

### Do I need an Anthropic account?

Yes, you need an Anthropic API key to enable real AI analysis. Without it, the system falls back to template-based mock reports.

**Get one here**: https://console.anthropic.com/

### Can I use OpenAI instead?

Currently, the system is optimized for Anthropic's Claude. OpenAI support is planned for v1.1.

### Can I use my Cursor API key?

No, Cursor API keys use a different authentication method and cannot be used directly with the Anthropic API. You need a separate Anthropic API key.

### How much does the API cost?

**Anthropic Claude Sonnet 4**:
- ~$3 per 1M input tokens
- ~$15 per 1M output tokens
- **Per audit**: $0.10 - $0.50
- **Monthly** (weekly audits): ~$2 - $8 per repo

### Is my API key secure?

Yes, when stored in GitHub Secrets, your API key is encrypted and never exposed in logs or artifacts.

---

## 🚀 Setup & Configuration

### How long does setup take?

- **Quick start**: 5 minutes
- **Full setup with Slack**: 30 minutes
- **Multi-repo deployment**: 1-2 hours

### Can I use it on private repositories?

Yes! Agent OS works with both public and private repositories.

### Do I need admin access?

You need permission to:
- Add GitHub Secrets
- Create workflow files
- Enable GitHub Actions

### Can I use it without GitHub Actions?

Not currently. The system is designed as a GitHub Action. Local/CLI support is planned for future versions.

---

## 📊 Usage & Features

### How often should I run audits?

**Recommended**:
- **Weekly** for most teams
- **Daily** for high-velocity teams
- **On every PR** for strict quality control

### What gets analyzed?

- Security vulnerabilities
- Performance bottlenecks
- Test coverage gaps
- Code quality issues
- Architecture concerns
- Documentation quality

### How long does an audit take?

- **Small repos** (<100 files): 1-2 minutes
- **Medium repos** (100-500 files): 2-3 minutes
- **Large repos** (500+ files): 3-5 minutes

The system analyzes up to 50 files per run by default.

### Can I customize what gets checked?

Currently, the system uses predefined standards. Custom rules engine is planned for v1.2.

### Does it fix issues automatically?

No, Agent OS identifies issues and provides recommendations. You implement the fixes. Auto-fix is planned for v2.0.

---

## 📝 Pull Requests & Reports

### Why was a PR created?

Agent OS creates PRs when it finds issues (blockers or suggestions). This makes findings visible and trackable.

### Can I disable PR creation?

Yes, set `comment-on-pr: 'false'` in your workflow file. Reports will still be available as artifacts.

### Why are multiple PRs being created?

This shouldn't happen - Agent OS has duplicate detection. If it does:
1. Verify you're using v1.0.14 or later
2. Check for existing PRs with label "automated-review"
3. Close duplicates manually

### How do I interpret the report?

Reports have three severity levels:
- **[BLOCKER]** 🔴 - Must fix before merge
- **[SUGGESTION]** 🟡 - Recommended improvement
- **[NIT]** ⚪ - Minor issue, can ignore

### Where can I download reports?

GitHub Actions → Workflow Run → Artifacts → Download "code-review-reports"

---

## 🔧 Troubleshooting

### Why am I getting mock reports?

Mock reports appear when:
1. API key not set in GitHub Secrets
2. API key is invalid
3. API authentication fails

**Solution**: Verify `ANTHROPIC_API_KEY` secret is set correctly.

### Workflow isn't triggering automatically

**Common causes**:
1. Cron syntax error
2. Repository inactive
3. GitHub Actions disabled

**Solution**: Test with manual trigger first (`gh workflow run code-review.yml`)

### Getting "invalid x-api-key" error

**Causes**:
1. API key incorrect
2. Using Cursor key instead of Anthropic key
3. Secret name wrong

**Solution**: Regenerate Anthropic API key and update GitHub Secret.

### No Slack notifications

**Causes**:
1. GitHub App not installed
2. Not subscribed to repository
3. Wrong channel

**Solution**: Install GitHub App and run `/github subscribe owner/repo pulls reviews`

**More help**: See [TROUBLESHOOTING.md](TROUBLESHOOTING.md)

---

## 💰 Costs & Billing

### How much will this cost me?

**Typical costs per repository**:
- Weekly audits: $2-8/month
- Daily audits: $10-30/month
- Per-PR audits: $20-50/month (depends on PR frequency)

### Can I set spending limits?

Yes, in Anthropic Console → Settings → Billing → Set usage limits and alerts.

### What if I exceed my budget?

Set up billing alerts in Anthropic console. The API will stop working if you hit your limit (falls back to mock reports).

### Are there free alternatives?

You could:
1. Use mock reports (free, but not AI-powered)
2. Wait for OpenAI support (may have free tier)
3. Use local LLM (planned for future)

---

## 🔒 Security & Privacy

### Is my code sent to Anthropic?

Yes, up to 50 files are sent to Anthropic's API for analysis. Review Anthropic's privacy policy: https://www.anthropic.com/privacy

### Can I use a self-hosted AI?

Not currently. Local LLM support (Ollama) is planned for v2.0.

### Is my code stored by Anthropic?

According to Anthropic's policy, API requests are not used to train models and are not retained long-term. Check their current policy for details.

### Can I audit what's being sent?

Yes, enable debug logging in your workflow:
```yaml
env:
  ACTIONS_STEP_DEBUG: true
```

---

## 🚀 Advanced Usage

### Can I run it locally?

Not currently. CLI support is planned for v1.1.

### Can I integrate with other CI/CD systems?

Currently GitHub Actions only. GitLab CI, CircleCI support planned for future.

### Can I use it for monorepos?

Yes! You can:
1. Run on entire monorepo
2. Split into multiple jobs for different packages
3. Use `project-path` to target specific directories

### Can I customize the AI prompts?

Not currently. This feature is planned for v1.2.

### Can I add custom rules?

Custom rules engine is planned for v1.2. Currently uses predefined standards.

---

## 📚 Documentation & Support

### Where can I find more documentation?

- **[Getting Started](GETTING_STARTED.md)** - Quick start guide
- **[Setup Guide](SETUP_GUIDE.md)** - Complete setup
- **[Troubleshooting](TROUBLESHOOTING.md)** - Common issues
- **[API Key Setup](API_KEY_SETUP.md)** - API configuration
- **[Project Overview](../PROJECT_OVERVIEW.md)** - Comprehensive analysis

### How do I report bugs?

Open an issue: https://github.com/securedotcom/agent-os-action/issues

### How do I request features?

Start a discussion: https://github.com/securedotcom/agent-os-action/discussions

### Can I contribute?

Yes! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 🔮 Future Plans

### What's coming in v1.1?

- OpenAI API support
- Improved error messages
- One-command setup script
- Docker image

### What's coming in v1.2?

- Web dashboard
- IDE extensions
- Custom rules engine
- Batch processing

### What's coming in v2.0?

- Local LLM support
- Real-time analysis
- Auto-fix suggestions
- Team analytics

---

## 📞 Still Have Questions?

- **Check**: [Troubleshooting Guide](TROUBLESHOOTING.md)
- **Ask**: [GitHub Discussions](https://github.com/securedotcom/agent-os-action/discussions)
- **Report**: [GitHub Issues](https://github.com/securedotcom/agent-os-action/issues)

---

**Last Updated**: October 24, 2025

