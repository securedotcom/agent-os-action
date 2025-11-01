# Agent OS Code Reviewer - GitHub Action

> **AI-Powered Code Review GitHub Action**
> Automated security, performance, testing, and quality analysis for your pull requests

[![Version](https://img.shields.io/badge/version-2.2.0-blue.svg)](CHANGELOG.md)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/securedotcom/agent-os-action/badge)](https://securityscorecards.dev/viewer/?uri=github.com/securedotcom/agent-os-action)

---

## 🎯 What Is This?

This GitHub Action provides automated AI-powered code review using the **Agent OS Code Reviewer** system. It analyzes your code for:

- 🔒 **Security Vulnerabilities** - SQL injection, XSS, hardcoded secrets
- ⚡ **Performance Issues** - N+1 queries, memory leaks, inefficient algorithms
- 🧪 **Test Coverage Gaps** - Missing tests for critical paths
- 📝 **Code Quality** - Maintainability, documentation, best practices

### ✨ Key Features

✅ **Multi-Agent Analysis** - 7 specialized AI agents for deep review
✅ **Aardvark Mode** - Exploit chain analysis & automatic security test generation
✅ **SARIF Output** - Integrates with GitHub Code Scanning
✅ **Multiple AI Providers** - Anthropic Claude, OpenAI, or local Ollama
✅ **Cost Controls** - Built-in limits and optimization options
✅ **PR Integration** - Automated comments and reports

---

## 🚀 Quick Start

### Prerequisites
- GitHub repository with Actions enabled
- API key for Anthropic Claude ([Get one](https://console.anthropic.com/))

### Installation

1. **Add API key to GitHub Secrets**:
   ```bash
   # Go to: Repository → Settings → Secrets → Actions
   # Add secret: ANTHROPIC_API_KEY
   ```

2. **Create workflow file** `.github/workflows/code-review.yml`:
   ```yaml
   name: AI Code Review

   on:
     pull_request:
       branches: [ main ]
     schedule:
       - cron: '0 9 * * 1'  # Weekly Monday 9 AM

   permissions:
     contents: read
     pull-requests: write
     security-events: write

   jobs:
     review:
       runs-on: ubuntu-latest
       timeout-minutes: 30

       steps:
         - uses: actions/checkout@v4
           with:
             fetch-depth: 0

         - name: Run AI Code Review
           uses: securedotcom/agent-os-action@v2
           with:
             anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
             multi-agent-mode: 'sequential'
             fail-on-blockers: 'true'
             upload-reports: 'true'

         - name: Upload SARIF to Security Tab
           if: always()
           uses: github/codeql-action/upload-sarif@v3
           with:
             sarif_file: .agent-os/reviews/results.sarif
   ```

3. **Commit and push**:
   ```bash
   git add .github/workflows/code-review.yml
   git commit -m "Add AI code reviewer"
   git push
   ```

---

## 📥 Inputs

### AI Provider Configuration

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `anthropic-api-key` | No | `''` | Anthropic API key for Claude |
| `openai-api-key` | No | `''` | OpenAI API key for GPT-4 |
| `ollama-endpoint` | No | `''` | Ollama endpoint (e.g., `http://localhost:11434`) |
| `ai-provider` | No | `'auto'` | AI provider: `anthropic`, `openai`, `ollama`, or `auto` |
| `model` | No | `'auto'` | Specific model to use (auto-detects by default) |

### Review Configuration

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `review-type` | No | `'audit'` | Type: `audit`, `security`, or `review` |
| `project-type` | No | `'auto'` | Project type: `backend-api`, `dashboard-ui`, `data-pipeline`, `infrastructure`, or `auto` |
| `multi-agent-mode` | No | `'single'` | `single` (1 agent, fast) or `sequential` (7 agents, deep) |
| `enable-exploit-analysis` | No | `'true'` | Enable Aardvark mode exploit chain analysis |
| `generate-security-tests` | No | `'true'` | Auto-generate security tests for vulnerabilities |
| `exploitability-threshold` | No | `'trivial'` | Block merge threshold: `trivial`, `moderate`, `complex`, `theoretical`, `none` |

### File Filtering

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `only-changed` | No | `'false'` | Only analyze changed files (PR optimization) |
| `include-paths` | No | `''` | Glob patterns to include: `src/**,lib/**` |
| `exclude-paths` | No | `''` | Glob patterns to exclude: `test/**,docs/**` |
| `max-file-size` | No | `'50000'` | Max file size in bytes |
| `max-files` | No | `'50'` | Max number of files to analyze |

### Workflow Controls

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `fail-on-blockers` | No | `'true'` | Fail workflow if blockers found |
| `fail-on` | No | `''` | Granular conditions: `security:high,test:critical` |
| `comment-on-pr` | No | `'true'` | Post results as PR comment |
| `upload-reports` | No | `'true'` | Upload reports as artifacts |
| `cost-limit` | No | `'1.0'` | Max cost in USD per run |

---

## 📤 Outputs

| Output | Description | Example |
|--------|-------------|---------|
| `review-completed` | Whether review completed | `true` |
| `blockers-found` | Number of blocking issues | `3` |
| `suggestions-found` | Number of suggestions | `12` |
| `report-path` | Path to markdown report | `.agent-os/reviews/audit-report.md` |
| `sarif-path` | Path to SARIF file | `.agent-os/reviews/results.sarif` |
| `json-path` | Path to JSON results | `.agent-os/reviews/results.json` |
| `cost-estimate` | Estimated cost in USD | `0.42` |
| `files-analyzed` | Number of files analyzed | `42` |
| `duration-seconds` | Analysis duration | `127` |
| `exploitability-trivial` | Trivially exploitable vulns | `2` |
| `exploitability-moderate` | Moderately exploitable vulns | `3` |
| `exploit-chains-found` | Exploit chains identified | `2` |
| `tests-generated` | Security tests generated | `8` |

---

## 💡 Usage Examples

### Basic PR Review

```yaml
name: PR Code Review

on:
  pull_request:
    branches: [ main ]

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: securedotcom/agent-os-action@v2
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          only-changed: 'true'
          fail-on-blockers: 'true'
```

### Deep Security Audit (Weekly)

```yaml
name: Weekly Security Audit

on:
  schedule:
    - cron: '0 9 * * 1'  # Monday 9 AM

jobs:
  audit:
    runs-on: ubuntu-latest
    timeout-minutes: 30

    steps:
      - uses: actions/checkout@v4

      - uses: securedotcom/agent-os-action@v2
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          multi-agent-mode: 'sequential'  # All 7 agents
          enable-exploit-analysis: 'true'
          generate-security-tests: 'true'
          cost-limit: '5.0'
```

### Cost-Optimized Review

```yaml
- uses: securedotcom/agent-os-action@v2
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    only-changed: 'true'
    include-paths: 'src/**,lib/**'
    exclude-paths: 'test/**,docs/**'
    max-files: 30
    cost-limit: '0.50'
```

### With OpenAI GPT-4

```yaml
- uses: securedotcom/agent-os-action@v2
  with:
    ai-provider: 'openai'
    openai-api-key: ${{ secrets.OPENAI_API_KEY }}
```

### With Local Ollama

```yaml
- uses: securedotcom/agent-os-action@v2
  with:
    ai-provider: 'ollama'
    ollama-endpoint: 'http://localhost:11434'
    model: 'llama3:70b'
```

---

## 🤖 Multi-Agent Mode

### Single-Agent Mode (Default)
- **Duration**: 1-2 minutes
- **Cost**: ~$0.15-0.20
- **Best for**: PR reviews, daily CI

### Multi-Agent Sequential Mode
- **Agents**: 7 specialized agents
- **Duration**: 8-10 minutes
- **Cost**: ~$1.00
- **Best for**: Weekly audits, security reviews

#### The 7 Specialized Agents:
1. **Security Reviewer** - Vulnerabilities, auth flaws, secrets
2. **Exploit Analyst** - Exploitability, attack chains (Aardvark)
3. **Security Test Generator** - Automated test generation (Aardvark)
4. **Performance Reviewer** - N+1 queries, memory leaks
5. **Testing Reviewer** - Coverage gaps, missing tests
6. **Code Quality Reviewer** - Maintainability, documentation
7. **Review Orchestrator** - Deduplicates and prioritizes findings

---

## 📊 Reports

The action generates multiple report formats:

```
.agent-os/reviews/
├── audit-report.md          # Main comprehensive report
├── results.sarif            # GitHub Code Scanning format
├── results.json             # Structured findings
├── metrics.json             # Cost/time metrics
└── agents/                  # Individual agent reports (multi-agent mode)
    ├── security-report.md
    ├── exploit-analyst-report.md
    ├── performance-report.md
    ├── testing-report.md
    └── quality-report.md
```

---

## 💰 Pricing

### Per Review Cost

| Mode | Duration | Cost | Use Case |
|------|----------|------|----------|
| Single Agent | 1-2 min | $0.15-0.20 | PR reviews |
| Multi-Agent | 8-10 min | $1.00 | Security audits |

### Monthly Estimates
- **PR Reviews** (5/week): ~$3-4/month
- **Weekly Audits**: ~$4-5/month
- **Combined**: ~$7-9/month per repository

---

## 🔒 Security & Privacy

### What Gets Analyzed
- ✅ File paths and code content
- ✅ Up to 100 files per run (configurable)

### What's Protected
- 🔒 Secrets automatically redacted
- 🔒 Git history not sent
- 🔒 Binary files excluded
- 🔒 API requests not used for training (Anthropic)

### For Maximum Privacy
Use local Ollama for air-gapped analysis:
```yaml
with:
  ai-provider: 'ollama'
  ollama-endpoint: 'http://localhost:11434'
```

---

## 🐛 Troubleshooting

### "No AI provider configured"
**Solution**: Add API key as GitHub secret and reference it in the workflow:
```yaml
anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

### "Code Scanning not enabled"
**Solution**: Enable Code Scanning in repository settings:
- Settings → Code security and analysis → Set up Code scanning

### "Resource not accessible by integration"
**Solution**: Add required permissions to workflow:
```yaml
permissions:
  contents: read
  security-events: write  # Required for SARIF upload
  pull-requests: write    # Required for PR comments
```

---

## 📚 Documentation

- **[Complete Documentation](https://github.com/securedotcom/agent-os)** - Main repository with full docs
- **[Aardvark Mode Guide](https://github.com/securedotcom/agent-os/blob/main/docs/aardvark-mode.md)** - Exploit analysis
- **[API Key Setup](https://github.com/securedotcom/agent-os/blob/main/docs/secure-api-key-setup.md)** - Secure configuration

---

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🔗 Links

- **Main Repository**: https://github.com/securedotcom/agent-os
- **GitHub Action**: https://github.com/securedotcom/agent-os-action
- **Issues**: https://github.com/securedotcom/agent-os/issues
- **Releases**: https://github.com/securedotcom/agent-os-action/releases

---

<div align="center">
  <strong>Powered by Agent OS</strong>
  <br>
  <sub>AI-Powered Code Review System using Claude Sonnet 4.5</sub>
</div>
