# Agent OS Code Reviewer

> **AI-Powered Automated Code Review System**  
> Comprehensive security, performance, testing, and quality analysis powered by Claude Sonnet 4

[![Version](https://img.shields.io/badge/version-1.0.14-blue.svg)](CHANGELOG.md)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![GitHub Action](https://img.shields.io/badge/GitHub%20Action-Ready-success.svg)](https://github.com/securedotcom/agent-os-action)

---

## 🎯 What Is Agent OS Code Reviewer?

Agent OS is an **intelligent code review system** that acts as your 24/7 virtual senior developer. It automatically analyzes your codebase for:

- 🔒 **Security Vulnerabilities** - SQL injection, hardcoded secrets, auth flaws
- ⚡ **Performance Issues** - N+1 queries, memory leaks, inefficient algorithms
- 🧪 **Test Coverage Gaps** - Missing tests for critical business logic
- 📝 **Code Quality Problems** - Maintainability, documentation, architecture

### Key Features

✅ **Automated GitHub Actions Integration** - Runs on schedule or PR events  
✅ **Smart PR Management** - Creates/updates PRs with findings, avoids duplicates  
✅ **Multi-Agent AI Architecture** - Specialized reviewers for each concern  
✅ **Project-Type Awareness** - Adapts standards for Backend, Frontend, Data, Infrastructure  
✅ **Slack Notifications** - Real-time alerts for critical issues  
✅ **Comprehensive Reports** - Downloadable audit artifacts  

---

## 🚀 Quick Start (5 Minutes)

### Prerequisites
- GitHub repository
- GitHub Actions enabled
- Anthropic API key ([Get one here](https://console.anthropic.com/))

### Installation

1. **Get Your API Key**
   ```bash
   # Visit https://console.anthropic.com/ and create an API key
   ```

2. **Add GitHub Secret**
   ```bash
   # Go to: Repository → Settings → Secrets → Actions
   # Add: ANTHROPIC_API_KEY = sk-ant-xxxxx
   ```

3. **Add Workflow File**
   ```bash
   mkdir -p .github/workflows
   curl -o .github/workflows/code-review.yml \
     https://raw.githubusercontent.com/securedotcom/agent-os-action/main/example-workflow.yml
   ```

4. **Commit and Push**
   ```bash
   git add .github/workflows/code-review.yml
   git commit -m "Add Agent OS code reviewer"
   git push
   ```

5. **Run Your First Review**
   ```bash
   gh workflow run code-review.yml
   ```

That's it! Check your repository's Actions tab to see the review in progress.

---

## 📥 Action Inputs & Outputs

### Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| **AI Provider** | | | |
| `ai-provider` | No | `'auto'` | AI provider: `anthropic`, `openai`, `ollama`, or `auto` |
| `anthropic-api-key` | No | `''` | Anthropic API key for Claude AI ([Get one](https://console.anthropic.com/)) |
| `openai-api-key` | No | `''` | OpenAI API key for GPT-4 ([Get one](https://platform.openai.com/api-keys)) |
| `ollama-endpoint` | No | `''` | Ollama endpoint for local LLM (e.g., `http://localhost:11434`) |
| `model` | No | `'auto'` | AI model: `claude-sonnet-4`, `gpt-4-turbo-preview`, `llama3`, or `auto` |
| `cursor-api-key` | No | `''` | Cursor API key (deprecated, use `anthropic-api-key`) |
| `review-type` | No | `'audit'` | Type of review: `audit`, `security`, `review` |
| `project-path` | No | `'.'` | Path to project directory to review |
| `project-type` | No | `'auto'` | Project type: `auto`, `backend-api`, `dashboard-ui`, `data-pipeline`, `infrastructure` |
| `fail-on-blockers` | No | `'true'` | Fail workflow if merge blockers are found |
| `fail-on` | No | `''` | Granular fail conditions: `security:high,test:critical,any:critical` |
| `comment-on-pr` | No | `'true'` | Post review results as PR comment |
| `upload-reports` | No | `'true'` | Upload review reports as workflow artifacts |
| **Cost/Latency Guardrails** | | | |
| `only-changed` | No | `'false'` | Only analyze changed files (PR mode) |
| `include-paths` | No | `''` | Glob patterns to include: `src/**,lib/**` |
| `exclude-paths` | No | `''` | Glob patterns to exclude: `test/**,docs/**` |
| `max-file-size` | No | `'50000'` | Max file size in bytes (50KB) |
| `max-files` | No | `'50'` | Max number of files to analyze |
| `max-tokens` | No | `'8000'` | Max tokens per LLM call |
| `cost-limit` | No | `'1.0'` | Max cost in USD per run |

### Outputs

| Output | Description | Example Value |
|--------|-------------|---------------|
| `review-completed` | Whether the review completed successfully | `true` |
| `blockers-found` | Number of merge blocker issues found | `3` |
| `suggestions-found` | Number of suggestion issues found | `12` |
| `report-path` | Path to the generated markdown report | `.agent-os/reviews/audit-report.md` |
| `sarif-path` | Path to SARIF file for Code Scanning | `.agent-os/reviews/results.sarif` |
| `json-path` | Path to structured JSON results | `.agent-os/reviews/results.json` |
| `cost-estimate` | Estimated cost in USD | `0.42` |
| `files-analyzed` | Number of files analyzed | `42` |
| `duration-seconds` | Analysis duration in seconds | `127` |

### Uploading SARIF to Security Tab

To surface findings in GitHub's Security tab, upload the SARIF output:

```yaml
- name: Run Code Review
  id: agent
  uses: securedotcom/agent-os-action@v1
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}

- name: Upload SARIF to Code Scanning
  if: always()
  uses: github/codeql-action/upload-sarif@afb54ba388a7dca6ecae48f608c4ff05ff4cc77a  # v3.25.15
  with:
    sarif_file: ${{ steps.agent.outputs.sarif-path }}
    category: agent-os-code-review
```

This makes findings visible in:
- **Security** → **Code scanning** tab
- Pull request checks
- Security overview dashboard

### Exit Codes

| Code | Meaning | When It Occurs |
|------|---------|----------------|
| `0` | Success | No blockers found, or blockers found but `fail-on-blockers: false` |
| `1` | Failure | Blockers found and `fail-on-blockers: true` |
| `2` | Error | Configuration error, API failure, or system error |

**CI Gating Examples**:
```yaml
# Simple: Fail on any blockers
- name: Run Code Review
  uses: securedotcom/agent-os-action@v1
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    fail-on-blockers: 'true'

# Granular: Fail on specific severity/category
- name: Run Code Review  
  uses: securedotcom/agent-os-action@v1
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    fail-on: 'security:high,security:critical,test:critical'

# Strict: Fail on any critical issue
- name: Run Code Review
  uses: securedotcom/agent-os-action@v1
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    fail-on: 'any:critical'
```

**Cost-Optimized Example**:
```yaml
- name: Run Code Review (Cost-Optimized)
  uses: securedotcom/agent-os-action@v1
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    only-changed: 'true'              # Only review changed files
    include-paths: 'src/**,lib/**'    # Only source code
    exclude-paths: 'test/**,docs/**'  # Skip tests and docs
    max-files: 30                     # Limit file count
    cost-limit: '0.50'                # Cap at $0.50
```

---

## 🤖 AI Provider Options

Agent OS supports **3 AI providers** to reduce dependency on any single API:

### 1. Anthropic Claude (Recommended)
- **Model**: Claude Sonnet 4
- **Quality**: ⭐⭐⭐⭐⭐ (Best)
- **Cost**: $3/1M input, $15/1M output (~$0.05/KLOC)
- **Setup**: Get API key from [console.anthropic.com](https://console.anthropic.com/)

```yaml
with:
  anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

### 2. OpenAI GPT-4
- **Model**: GPT-4 Turbo
- **Quality**: ⭐⭐⭐⭐ (Excellent)
- **Cost**: $10/1M input, $30/1M output (~$0.15/KLOC)
- **Setup**: Get API key from [platform.openai.com](https://platform.openai.com/api-keys)

```yaml
with:
  ai-provider: 'openai'
  openai-api-key: ${{ secrets.OPENAI_API_KEY }}
```

### 3. Ollama (Local, Free)
- **Model**: Llama 3, CodeLlama, etc.
- **Quality**: ⭐⭐⭐ (Good)
- **Cost**: $0 (runs locally)
- **Setup**: Install [Ollama](https://ollama.ai/) locally

```yaml
with:
  ai-provider: 'ollama'
  ollama-endpoint: 'http://localhost:11434'
```

### Provider Comparison

| Provider | Quality | Cost/KLOC | Speed | Privacy | Setup |
|----------|---------|-----------|-------|---------|-------|
| **Anthropic** | ⭐⭐⭐⭐⭐ | $0.05 | Fast | Cloud | Easy |
| **OpenAI** | ⭐⭐⭐⭐ | $0.15 | Fast | Cloud | Easy |
| **Ollama** | ⭐⭐⭐ | $0.00 | Medium | Local | Medium |

## 💰 Cost Estimation

### Expected Cost per 1000 Lines of Code (KLOC)

| Provider | Language | Avg Cost | Range |
|----------|----------|----------|-------|
| **Anthropic** | JavaScript/TypeScript | $0.05 | $0.03-$0.08 |
| **Anthropic** | Python | $0.04 | $0.02-$0.06 |
| **Anthropic** | Java | $0.06 | $0.04-$0.10 |
| **Anthropic** | Go | $0.03 | $0.02-$0.05 |
| **OpenAI** | All Languages | $0.15 | $0.10-$0.20 |
| **Ollama** | All Languages | $0.00 | Free |

### Cost Optimization Tips

**Reduce costs by**:
- ✅ Enable `only-changed: true` for PR reviews (~90% cost reduction)
- ✅ Use `include-paths` to focus on source code only
- ✅ Set `exclude-paths` to skip tests, docs, and config files
- ✅ Reduce `max-files` from 50 to 25-30
- ✅ Set `cost-limit` to cap spending (e.g., `'0.50'`)

**Example Costs**:
- 10K LOC full audit: ~$0.50
- PR review (100 changed lines): ~$0.05
- Weekly audits (4x/month): ~$2.00/month

---

## 🏢 Enterprise Features

### API Gateway Support

For organizations using API gateways or proxies:

```yaml
- uses: securedotcom/agent-os-action@v1
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
  env:
    ANTHROPIC_BASE_URL: 'https://your-gateway.company.com/v1'
```

**Benefits**:
- Route through corporate proxy
- Add additional security layers
- Monitor and log API usage
- Implement rate limiting

### Data Security & Privacy

**What Gets Analyzed**:
- ✅ File paths and names
- ✅ Code content (up to 100 files)
- ✅ File structure

**What's Protected**:
- 🔒 Secrets automatically redacted (API keys, tokens, passwords)
- 🔒 PII detection and redaction available
- 🔒 Git history not sent
- 🔒 Binary files excluded
- 🔒 Large files (>50KB) skipped

**Data Retention** (Anthropic):
- API requests not used for training
- Not retained long-term
- See: [Anthropic Privacy Policy](https://www.anthropic.com/privacy)

**For Maximum Privacy**:
```yaml
# Use Ollama for local, air-gapped analysis
- uses: securedotcom/agent-os-action@v1
  with:
    ai-provider: 'ollama'
    ollama-endpoint: 'http://localhost:11434'
```

### Secret & PII Redaction

Built-in redaction for common patterns:
- API keys and tokens
- Passwords and secrets
- Email addresses
- Credit card numbers
- Social security numbers

**Enable explicit redaction**:
```yaml
with:
  redact-secrets: 'true'  # Default: true
  redact-pii: 'true'      # Default: true
```

### Compliance & Audit Trail

**Audit Logging**:
- All reviews logged with timestamps
- Cost tracking per review
- SARIF reports for compliance
- JSON artifacts for auditing

**Compliance Support**:
- SOC 2 compatible (with Anthropic/OpenAI)
- GDPR compliant (PII redaction)
- HIPAA considerations (use local Ollama)
- ISO 27001 alignment

### Enterprise Support

For enterprise deployments:
- Custom SLAs available
- Dedicated support channel
- Custom rule development
- On-premise deployment options
- Training and onboarding

Contact: [enterprise@agent-os.dev](mailto:enterprise@agent-os.dev)

---

## 📚 Documentation

### Getting Started
- **[Quick Start Guide](docs/GETTING_STARTED.md)** - Get up and running in 5 minutes
- **[Complete Setup Guide](docs/SETUP_GUIDE.md)** - Detailed installation and configuration
- **[API Key Setup](docs/API_KEY_SETUP.md)** - How to get and configure your API key

### Understanding the System
- **[Project Overview](PROJECT_OVERVIEW.md)** - Comprehensive project analysis
- **[Executive Summary](EXECUTIVE_SUMMARY.md)** - Quick overview for stakeholders
- **[Architecture](docs/ARCHITECTURE.md)** - System design and components

### Using Agent OS
- **[Troubleshooting Guide](docs/TROUBLESHOOTING.md)** - Common issues and solutions
- **[FAQ](docs/FAQ.md)** - Frequently asked questions
- **[Contributing](docs/CONTRIBUTING.md)** - How to contribute to the project

### Templates
- **[GitHub App Request](docs/templates/github-app-request.md)** - Request Slack integration from org admin
- **[Slack Setup](docs/templates/slack-setup.md)** - Configure Slack notifications

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     GitHub Actions                          │
│  ┌──────────────────────────────────────────────────────┐  │
│  │         Agent OS Code Reviewer (v1.0.14)             │  │
│  │                                                       │  │
│  │  ┌──────────────────────────────────────────────┐   │  │
│  │  │        Review Orchestrator                   │   │  │
│  │  │  (Coordinates multi-agent analysis)          │   │  │
│  │  └──────────────────────────────────────────────┘   │  │
│  │                      │                               │  │
│  │         ┌────────────┼────────────┬─────────┐       │  │
│  │         │            │            │         │       │  │
│  │    ┌────▼───┐   ┌───▼────┐  ┌───▼────┐ ┌──▼────┐  │  │
│  │    │Security│   │Perform-│  │Testing │ │Quality│  │  │
│  │    │Reviewer│   │ance    │  │Reviewer│ │Review │  │  │
│  │    └────────┘   └────────┘  └────────┘ └───────┘  │  │
│  │                                                       │  │
│  │  ┌──────────────────────────────────────────────┐   │  │
│  │  │         Claude Sonnet 4 (Anthropic)          │   │  │
│  │  └──────────────────────────────────────────────┘   │  │
│  └──────────────────────────────────────────────────────┘  │
│                      │                                      │
│         ┌────────────┼────────────┬──────────┐            │
│         │            │            │          │            │
│    ┌────▼───┐   ┌───▼────┐  ┌───▼────┐ ┌──▼────┐        │
│    │Create  │   │Upload  │  │Slack   │ │Metrics│        │
│    │PR      │   │Reports │  │Notify  │ │Track  │        │
│    └────────┘   └────────┘  └────────┘ └───────┘        │
└─────────────────────────────────────────────────────────────┘
```

---

## 💡 Use Cases

### For Individual Developers
- **Learn from AI** - Get expert-level feedback on your code
- **Catch Bugs Early** - Before they reach production
- **Improve Skills** - Understand best practices through examples

### For Teams
- **Consistent Standards** - Enforce coding standards across all PRs
- **Reduce Review Burden** - Let AI handle routine checks
- **Faster Onboarding** - New developers learn standards quickly

### For Organizations
- **Security** - Catch vulnerabilities before deployment
- **Compliance** - Maintain audit trails of all reviews
- **Cost Savings** - Reduce production bugs and incidents
- **Quality Metrics** - Track code quality trends over time

---

## 📊 What Gets Analyzed?

### Security Analysis
- Hardcoded secrets and credentials
- SQL/NoSQL injection vulnerabilities
- Authentication and authorization flaws
- Cryptographic security issues
- Dependency vulnerabilities
- Input/output sanitization

### Performance Analysis
- N+1 query patterns
- Memory leaks and resource management
- Algorithm efficiency
- I/O performance
- Connection pooling
- Scalability concerns

### Testing Analysis
- Test coverage for critical paths
- Regression test gaps
- Test quality and organization
- Critical user workflow testing
- Test performance

### Code Quality Analysis
- Linting and style compliance
- Code maintainability
- Documentation quality
- Architecture and design patterns
- Error handling
- Configuration management

---

## 🎯 Current Status

| Component | Status | Notes |
|-----------|--------|-------|
| GitHub Action | ✅ Working | v1.0.14 deployed |
| PR Automation | ✅ Working | Creates/updates PRs |
| Slack Integration | ✅ Working | Via GitHub App |
| Scheduling | ✅ Working | Weekly/on-demand |
| **AI Analysis** | ⚠️ **Setup Required** | **Needs Anthropic API key** |
| Documentation | ✅ Complete | Consolidated guides |

---

## 🚧 Known Limitations

### Current Limitations
- **API Key Required**: Needs Anthropic API key for real analysis (falls back to mock reports)
- **File Limit**: Analyzes up to 50 files per run (configurable)
- **Language Support**: Best for JavaScript, TypeScript, Python, Java, Go, Rust, Ruby, PHP, C#
- **Cost**: ~$0.10-$0.50 per audit (depending on codebase size)

### Planned Improvements
- OpenAI API support (GPT-4 alternative)
- Local LLM support (Ollama)
- IDE extensions (VS Code, Cursor)
- Custom rules engine
- Real-time dashboard
- More language support

---

## 💰 Pricing

### Anthropic API Costs
- **Claude Sonnet 4**: ~$3 per 1M input tokens, ~$15 per 1M output tokens
- **Per Audit**: $0.10 - $0.50 (typical codebase)
- **Monthly** (weekly audits): ~$2 - $8 per repository

### Cost Optimization
- Run weekly instead of daily
- Focus on changed files only (PR reviews)
- Limit file count (already implemented)
- Use smaller context windows

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines.

### Ways to Contribute
- 🐛 Report bugs and issues
- 💡 Suggest new features
- 📝 Improve documentation
- 🔧 Submit pull requests
- ⭐ Star the repository

---

## 📞 Support

### Documentation
- **[Troubleshooting Guide](docs/TROUBLESHOOTING.md)** - Common issues
- **[FAQ](docs/FAQ.md)** - Frequently asked questions
- **[API Key Setup](docs/API_KEY_SETUP.md)** - Configuration help

### Community
- **GitHub Issues** - Report bugs or request features
- **GitHub Discussions** - Ask questions and share ideas

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Anthropic** - For Claude Sonnet 4 AI model
- **GitHub** - For Actions platform
- **Contributors** - Everyone who has contributed to this project

---

## 📈 Roadmap

### v1.1 (Next Release)
- [ ] OpenAI API support
- [ ] Improved error messages
- [ ] One-command setup script
- [ ] Docker image

### v1.2 (Future)
- [ ] Web dashboard
- [ ] IDE extensions
- [ ] Custom rules engine
- [ ] Batch processing

### v2.0 (Vision)
- [ ] Local LLM support
- [ ] Real-time analysis
- [ ] Auto-fix suggestions
- [ ] Team analytics

---

**Ready to get started?** Check out the [Quick Start Guide](docs/GETTING_STARTED.md)!

---

<div align="center">
  <strong>Made with ❤️ by the Agent OS Team</strong>
  <br>
  <sub>Powered by Claude Sonnet 4</sub>
</div>
