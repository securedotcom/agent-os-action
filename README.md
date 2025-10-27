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
