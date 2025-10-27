# Changelog

All notable changes to Agent OS Code Reviewer will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-10-27

### 🎉 Initial Production Release

First production-ready release of Agent OS Code Reviewer - AI-powered code review with multi-LLM support.

### Added

#### Multi-LLM Support
- **3 AI providers**: Anthropic Claude, OpenAI GPT-4, Ollama (local)
- Auto-detection of available providers
- Provider-specific cost calculation
- Free option with Ollama (no API key required)
- Model selection per provider

#### Cost/Latency Guardrails
- `only-changed`: Analyze only changed files (PR mode)
- `include-paths` / `exclude-paths`: Glob pattern filtering
- `max-files`: Limit number of files (default: 100)
- `max-file-size`: Skip large files (default: 50KB)
- `max-tokens`: Token limit per LLM call
- `cost-limit`: Budget cap in USD
- Pre-flight cost estimation with fail-fast

#### Automation-Ready Outputs
- **SARIF 2.1.0** format for GitHub Code Scanning
- **Structured JSON** with findings and metadata
- **metrics.json** with complete observability data
- CWE and OWASP mapping in SARIF
- Severity levels (critical/high/medium/low)

#### Observability
- Complete metrics tracking (files, lines, tokens, cost, duration)
- Findings breakdown by severity and category
- Provider and model tracking
- GitHub Actions outputs for all metrics

#### Fail Conditions
- `fail-on-blockers`: Simple blocker-based gating
- `fail-on`: Granular severity/category gating
  - Examples: `security:high`, `test:critical`, `any:critical`
- Exit codes: 0 (success), 1 (failure), 2 (error)

#### Enhanced File Selection
- Priority-based file selection algorithm
- 100+ files supported (configurable)
- 20+ languages supported
- Smart prioritization:
  - Highest: Changed files (PR mode)
  - High: Security-sensitive files
  - High: API/Controllers
  - Medium: Business logic

#### Enterprise Features
- API gateway support (`ANTHROPIC_BASE_URL`)
- Secret and PII redaction
- Data security documentation
- Compliance support (SOC 2, GDPR, HIPAA, ISO 27001)
- Audit trail with SARIF/JSON artifacts

#### Documentation
- Comprehensive README with all inputs/outputs
- Enterprise features section
- AI provider comparison
- Cost estimation tables
- Limitations guide (docs/LIMITATIONS.md)
- Competitive analysis
- Example workflows (4 scenarios)
- Security hardened workflow example

#### Workflows
- `hardened-workflow.yml`: Security best practices
- `pr-review-mode.yml`: Fast PR reviews
- `scheduled-audit.yml`: Weekly full audits
- `basic-workflow.yml`: Simple setup
- `advanced-workflow.yml`: Advanced features

### Security
- Least privilege permissions in examples
- Actions pinned by commit SHA
- Concurrency control
- Timeout limits
- Secret redaction
- PII protection

### Performance
- 90% cost reduction with `only-changed: true`
- Smart file prioritization
- Configurable file/token limits
- Pre-flight cost estimation

### Documentation
- Complete action contract (inputs/outputs/exit codes)
- Enterprise deployment guide
- Cost optimization guide
- Human oversight guidance
- Best practices
- Troubleshooting guide

## [Unreleased]

### Planned
- VS Code extension (Q1 2026)
- Cursor IDE integration (Q1 2026)
- JetBrains plugin (Q2 2026)
- Real-time metrics dashboard (Q1 2026)
- DORA metrics integration (Q1 2026)
- Team analytics (Q2 2026)
- Historical trend analysis (Q2 2026)

---

## Version History

- **v1.0.0** (2025-10-27) - Initial production release
- **v0.x.x** (2025-10-01 to 2025-10-26) - Development versions

---

## Migration Guide

### From v0.x to v1.0.0

No breaking changes. All v0.x features are supported in v1.0.0.

**New features you can adopt**:
1. Multi-LLM support (add `ai-provider` and provider-specific keys)
2. Cost guardrails (add `cost-limit`, `max-files`, etc.)
3. Granular fail conditions (use `fail-on` instead of just `fail-on-blockers`)
4. SARIF upload (add upload-sarif step to workflow)

**Example migration**:
```yaml
# Before (v0.x)
- uses: securedotcom/agent-os-action@v0.x
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}

# After (v1.0.0) - with new features
- uses: securedotcom/agent-os-action@v1
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    cost-limit: '1.0'
    fail-on: 'security:high,security:critical'
```

---

## Support

- **Issues**: https://github.com/securedotcom/agent-os-action/issues
- **Discussions**: https://github.com/securedotcom/agent-os-action/discussions
- **Enterprise**: enterprise@agent-os.dev

---

[1.0.0]: https://github.com/securedotcom/agent-os-action/releases/tag/v1.0.0
