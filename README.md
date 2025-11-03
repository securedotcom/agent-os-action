# Agent OS Code Reviewer

AI-powered code review system with security analysis, exploit detection, and automated test generation.

## Quick Start

```yaml
name: Code Review

on:
  push:
    branches: [main, master]
  pull_request:
  workflow_dispatch:

permissions:
  contents: write
  pull-requests: write
  security-events: write

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: securedotcom/agent-os-action@main
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          review-type: 'audit'
          fail-on-blockers: 'true'
```

## Features

### 🔍 Comprehensive Analysis
- **Security vulnerabilities** with exploitability scoring
- **Performance issues** and optimization opportunities  
- **Code quality** and best practices
- **Test coverage** gaps and suggestions

### 🛡️ Aardvark Mode (Exploit Analysis)
- Analyzes exploitability of vulnerabilities (trivial/moderate/complex)
- Identifies exploit chains linking multiple vulnerabilities
- Auto-generates security test cases
- Prioritizes fixes by exploitability

### 📊 Smart Outputs
- **Markdown reports** with actionable findings
- **SARIF files** for GitHub Code Scanning integration
- **JSON data** for programmatic analysis
- **PR comments** with inline feedback

## Configuration

### Basic Configuration

```yaml
- uses: securedotcom/agent-os-action@main
  with:
    # Required
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    
    # Review settings
    review-type: 'audit'              # audit | security | review
    project-type: 'backend-api'       # auto | backend-api | dashboard-ui | data-pipeline | infrastructure
    
    # Quality gates
    fail-on-blockers: 'true'          # Fail workflow if critical issues found
    
    # Outputs
    comment-on-pr: 'true'             # Post findings as PR comment
    upload-reports: 'true'            # Upload reports as artifacts
```

### Advanced Configuration

```yaml
- uses: securedotcom/agent-os-action@main
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    
    # AI Configuration
    ai-provider: 'anthropic'
    model: 'claude-sonnet-4-20250514'  # Recommended for best quality
    
    # Analysis mode
    multi-agent-mode: 'single'         # single (recommended) | sequential (7x cost)
    
    # Aardvark exploit analysis
    enable-exploit-analysis: 'true'
    generate-security-tests: 'true'
    exploitability-threshold: 'moderate'
    
    # Cost controls
    max-files: 100                     # Max files to analyze
    max-tokens: 8000                   # Auto-capped based on model
    cost-limit: '1.0'                  # Max cost in USD per run
    
    # Path filters
    include-paths: 'src/**,lib/**'
    exclude-paths: 'node_modules/**,dist/**,*.test.*'
    
    # Granular failure conditions
    fail-on: 'security:critical,security:high,exploitability:trivial'
```

## Inputs Reference

| Input | Description | Default | Required |
|-------|-------------|---------|----------|
| `anthropic-api-key` | Anthropic API key | - | ✅ |
| `review-type` | Type of review (audit/security/review) | `audit` | |
| `project-type` | Project type for context | `auto` | |
| `model` | AI model to use | `claude-sonnet-4-20250514` | |
| `multi-agent-mode` | Analysis mode | `single` | |
| `fail-on-blockers` | Fail on critical issues | `true` | |
| `comment-on-pr` | Comment on PRs | `true` | |
| `upload-reports` | Upload artifacts | `true` | |
| `max-files` | Max files to analyze | `50` | |
| `cost-limit` | Max cost in USD | `1.0` | |

[See all inputs in action.yml](./action.yml)

## Outputs

| Output | Description |
|--------|-------------|
| `review-completed` | Whether review completed |
| `blockers-found` | Number of critical/high issues |
| `suggestions-found` | Number of medium/low issues |
| `cost-estimate` | Estimated cost in USD |
| `files-analyzed` | Number of files analyzed |
| `exploitability-trivial` | Trivially exploitable issues |
| `exploitability-moderate` | Moderately exploitable issues |
| `exploit-chains-found` | Number of exploit chains |
| `tests-generated` | Security tests generated |

## Generated Files

The action creates files in `.agent-os/reviews/`:

```
.agent-os/reviews/
├── audit-report.md      # Main findings report
├── results.sarif        # For GitHub Code Scanning
├── results.json         # Structured data
└── metrics.json         # Cost and performance metrics
```

## Cost Optimization

### Recommended Configuration (Single-Agent)
- **Cost**: ~$0.30 per run
- **Speed**: 2-3 minutes
- **Quality**: Excellent with Claude Sonnet 4

```yaml
multi-agent-mode: 'single'
model: 'claude-sonnet-4-20250514'
cost-limit: '1.0'
```

### Multi-Agent Mode (Not Recommended)
- **Cost**: ~$2-3 per run (7x more expensive)
- **Speed**: 10-15 minutes
- **Quality**: Similar to single-agent

**⚠️ Use single-agent mode unless you have specific research needs**

## Security Best Practices

### API Key Setup

```bash
# Add to GitHub repository secrets
gh secret set ANTHROPIC_API_KEY --body "sk-ant-..."
```

### Permissions

```yaml
permissions:
  contents: write          # Create branches/PRs
  pull-requests: write     # Comment on PRs  
  security-events: write   # Upload SARIF
```

## Examples

### Basic Workflow

```yaml
name: Code Review

on: [push, pull_request]

jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
      security-events: write
      
    steps:
      - uses: actions/checkout@v4
      - uses: securedotcom/agent-os-action@main
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

### Security-Focused Review

```yaml
- uses: securedotcom/agent-os-action@main
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    review-type: 'security'
    enable-exploit-analysis: 'true'
    generate-security-tests: 'true'
    fail-on: 'security:critical,security:high,exploitability:trivial'
```

### PR-Only Analysis (Cost Optimized)

```yaml
- uses: securedotcom/agent-os-action@main
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    only-changed: ${{ github.event_name == 'pull_request' }}
    max-files: 25
    cost-limit: '0.25'
```

## Troubleshooting

### Common Issues

**Token Limit Errors**
- The action automatically caps `max_tokens` based on model capabilities
- Claude Haiku: 4096 max
- Claude Sonnet 4: 8192 max

**Cost Overruns**
- Use `cost-limit` to cap spending
- Use `single` agent mode (not `sequential`)
- Filter with `include-paths` and `exclude-paths`

**No Reports Generated**
- Check workflow artifacts for `code-review-reports-*`
- Reports are in `.agent-os/reviews/` (not committed to git)

**SARIF Upload Fails**
- Enable Code Scanning in repository settings
- Check `security-events: write` permission
- Has `continue-on-error: true` by default

## Documentation

- [Getting Started Guide](./docs/GETTING_STARTED.md)
- [Architecture Overview](./docs/ARCHITECTURE.md)
- [Aardvark Mode](./docs/aardvark-mode.md)
- [API Key Setup](./docs/API_KEY_SETUP.md)
- [FAQ](./docs/FAQ.md)
- [Troubleshooting](./docs/TROUBLESHOOTING.md)

## Support

- **Issues**: [GitHub Issues](https://github.com/securedotcom/agent-os-action/issues)
- **Security**: [SECURITY.md](./SECURITY.md)
- **Contributing**: [CONTRIBUTING.md](./docs/CONTRIBUTING.md)

## License

[View License](./LICENSE)

---

**Cost Estimate**: ~$0.30 per run with recommended configuration  
**Speed**: 2-3 minutes typical execution time  
**Models**: Supports Claude Sonnet 4, Claude 3.5 Sonnet, GPT-4, and more
