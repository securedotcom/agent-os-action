---
title: Introduction
sidebar_position: 1
slug: /
---

# Agent OS Code Reviewer Documentation

Welcome to the comprehensive documentation for **Agent OS Code Reviewer** - an AI-powered automated code review system that provides security analysis, performance optimization, quality assessment, and test coverage insights.

## 🎯 What is Agent OS Code Reviewer?

Agent OS Code Reviewer is a GitHub Action that uses advanced AI models (Claude, GPT-4, or local LLMs) to analyze your codebase and provide:

- **Security Analysis**: Identify vulnerabilities, exploits, and security risks
- **Performance Review**: Find bottlenecks and optimization opportunities
- **Quality Assessment**: Evaluate code quality and best practices
- **Test Coverage**: Identify testing gaps and generate test suggestions
- **Exploit Analysis**: Aardvark mode for deep exploit chain analysis

## 🚀 Quick Start

### 1. Add to Your Workflow

```yaml
name: AI Code Review
on: [pull_request]

jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
      security-events: write
    
    steps:
      - uses: actions/checkout@v4
      - uses: securedotcom/agent-os-action@v3
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          review-type: 'audit'
          max-files: 50
          cost-limit: '1.0'
```

### 2. Configure Secrets

Add your API key to GitHub Secrets:
- Go to Settings → Secrets and variables → Actions
- Add `ANTHROPIC_API_KEY` with your Anthropic API key

### 3. Run Your First Review

- Create a pull request or push to trigger the workflow
- Review the generated report in `.agent-os/reviews/`
- Check the PR comment for findings summary

## 📚 Documentation Structure

### Architecture
Understand the system design and components:
- [Architecture Overview](./architecture/overview.md) - System design and data flow
- Component documentation for each specialized agent

### ADRs (Architecture Decision Records)
Learn about key technical decisions:
- [ADR-0001: Use Anthropic Claude](./adrs/0001-use-anthropic-claude.md)
- [ADR-0002: Multi-Agent Architecture](./adrs/001-multi-agent-architecture.md)

### Runbooks
Operational guides for deployment and maintenance:
- [GitHub Action Deployment](./playbooks/github-action-deployment.md)
- Troubleshooting and incident response guides

### References
Complete configuration and API references:
- [Action Inputs Reference](./references/action-inputs.md)
- Environment variables and configuration

## 🎨 Key Features

### 🔒 Security First
- OWASP Top 10 vulnerability detection
- Exploit chain analysis (Aardvark mode)
- SARIF report generation for GitHub Code Scanning
- Security test case generation

### 💰 Cost Effective
- **Single-agent mode**: ~$0.30 per run (recommended)
- **Multi-agent mode**: ~$2-3 per run (not recommended)
- Built-in cost estimation and guardrails
- Configurable cost limits

### ⚡ Fast & Efficient
- 2-3 minute analysis time (single-agent)
- Smart file selection and filtering
- Incremental analysis for PRs
- Parallel processing where possible

### 🎯 Actionable Insights
- Clear severity ratings (critical/high/medium/low)
- Exploitability scoring (trivial/moderate/complex/theoretical)
- Detailed remediation guidance
- Code examples and references

### 🔧 Flexible Configuration
- Multiple AI providers (Anthropic, OpenAI, Ollama)
- Customizable review types (audit, security, review)
- Project-type aware analysis
- Path inclusion/exclusion patterns

## 📊 Example Output

### Metrics
```json
{
  "version": "1.0.16",
  "files_reviewed": 25,
  "lines_analyzed": 3500,
  "cost_usd": 0.285,
  "duration_seconds": 145,
  "findings": {
    "critical": 2,
    "high": 5,
    "medium": 12,
    "low": 8
  }
}
```

### Finding Example
```markdown
## 🔴 CRITICAL: SQL Injection Vulnerability

**File**: `api/users.py:45`  
**Category**: Security  
**Exploitability**: Trivial

### Issue
User input directly concatenated into SQL query without sanitization.

### Impact
Attacker can execute arbitrary SQL commands, potentially accessing or modifying all database data.

### Remediation
Use parameterized queries or ORM methods:

\`\`\`python
# Before (vulnerable)
query = f"SELECT * FROM users WHERE id = {user_id}"

# After (secure)
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))
\`\`\`

### References
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
```

## 🛠️ Common Use Cases

### PR Reviews
```yaml
on:
  pull_request:
    branches: [main]

with:
  only-changed: true
  comment-on-pr: true
  fail-on: 'security:critical,security:high'
```

### Scheduled Security Audits
```yaml
on:
  schedule:
    - cron: '0 2 * * 1'  # Weekly Monday 2am

with:
  review-type: 'security'
  aardvark-mode: true
  max-files: 100
```

### Pre-Release Quality Gate
```yaml
on:
  push:
    tags:
      - 'v*'

with:
  review-type: 'audit'
  fail-on-blockers: true
  upload-reports: true
```

## 🔗 External Resources

- **GitHub Repository**: [securedotcom/agent-os-action](https://github.com/securedotcom/agent-os-action)
- **Anthropic Claude**: [anthropic.com](https://www.anthropic.com/)
- **SARIF Format**: [SARIF Spec](https://sarifweb.azurewebsites.net/)
- **GitHub Code Scanning**: [Docs](https://docs.github.com/en/code-security/code-scanning)

## 🤝 Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines on:
- Reporting issues
- Submitting pull requests
- Development setup
- Testing procedures

## 📄 License

MIT License - see [LICENSE](../LICENSE) for details.

## 🆘 Need Help?

- **Documentation**: Browse the sections in the sidebar
- **Issues**: [GitHub Issues](https://github.com/securedotcom/agent-os-action/issues)
- **FAQ**: [Frequently Asked Questions](../docs/FAQ.md)
- **Troubleshooting**: [Troubleshooting Guide](../docs/TROUBLESHOOTING.md)

---

> ⚠️ **AI-Generated Documentation Notice**
> 
> Parts of this documentation were generated using AI agents from the Agent Doc Creator system. All AI-generated content is marked with disclaimers and should be reviewed by humans before being treated as canonical documentation.

