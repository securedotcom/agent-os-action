# Changelog

All notable changes to Agent OS Code Reviewer will be documented in this file.

## [Unreleased]

### Fixed
- **CRITICAL**: Fixed model token limits - automatically cap tokens based on model capabilities
  - Claude Haiku: 4096 max (was trying 8000, causing 400 errors)
  - Claude Sonnet 4: 8192 max
  - Prevents "max_tokens exceeds limit" errors from Anthropic API
- Fixed UnboundLocalError in orchestrator exception handling
- Improved error handling with properly named exception variables

### Changed
- **MAJOR**: Prioritized Sonnet models over Haiku in fallback chain
  - Sonnet 4 and 4.5 now tried before Haiku
  - Haiku moved to last resort (limited token capacity)
  - Better quality analysis, fewer errors
- Removed Slack webhook notification functionality
  - Removed `slack-webhook-url` and `notify-on` inputs
  - Simplified action interface
  - Removed 72 lines of Slack integration code
- Updated documentation to focus on single-agent mode (recommended)
- Removed outdated improvement plans and competitive analysis docs

### Removed
- Slack notification features (deprecated)
- Old audit scripts (audit_spring_attack_surface.py, heuristic_audit_spring.py)
- Outdated documentation files
- Multi-agent workflow examples (to prevent confusion - use single-agent)

## [v2.1.6] - 2024-10-30

### Added
- Multi-agent sequential mode with 7 specialized agents
- Aardvark mode exploit analysis
- Security test generation
- Exploitability scoring (trivial/moderate/complex)

### Known Issues
- Multi-agent mode is 7x more expensive than single-agent
- Token limits cause errors with Claude Haiku in multi-agent mode
- **Recommendation**: Use single-agent mode for production

## [v2.0.0] - 2024-10-15

### Added
- Organization-level deployment support
- Cost circuit breakers and guardrails
- SARIF output for GitHub Code Scanning
- Automated PR creation for audit findings
- File selection with priority-based filtering

### Changed
- Improved cost estimation and tracking
- Better error handling and retry logic
- Enhanced reporting with structured JSON output

## [v1.0.15] - 2024-09-20

### Added
- Initial public release
- Basic code review functionality
- Support for multiple AI providers (Anthropic, OpenAI, Ollama)
- Security, performance, and quality analysis

---

## Migration Guide

### From v2.1.6 to Latest

**Critical Changes:**

1. **Model Configuration** (Required)
   ```yaml
   # Old (causes errors)
   uses: securedotcom/agent-os-action@v2.1.6
   
   # New (works reliably)
   uses: securedotcom/agent-os-action@main
   with:
     model: 'claude-sonnet-4-20250514'
     multi-agent-mode: 'single'
   ```

2. **Slack Removed**
   ```yaml
   # Remove these inputs (no longer supported)
   # slack-webhook-url: ${{ secrets.SLACK_WEBHOOK_URL }}
   # notify-on: 'on-blockers'
   ```

3. **Cost Savings**
   ```yaml
   # Change from expensive multi-agent
   multi-agent-mode: 'sequential'  # ❌ $2-3 per run
   
   # To efficient single-agent
   multi-agent-mode: 'single'      # ✅ $0.30 per run (90% savings)
   ```

### Benefits of Upgrading

- ✅ **90% cost reduction** with single-agent mode
- ✅ **No token limit errors** with automatic capping
- ✅ **Faster execution** (2-3 minutes vs 10-15 minutes)
- ✅ **Better reliability** with improved error handling
- ✅ **Simpler configuration** with Slack removed

### Breaking Changes

- `slack-webhook-url` input removed
- `notify-on` input removed  
- Multi-agent mode no longer default (single-agent is default)
- Requires explicit model specification for best results

## Support

- Report issues: [GitHub Issues](https://github.com/securedotcom/agent-os-action/issues)
- Security issues: See [SECURITY.md](./SECURITY.md)
