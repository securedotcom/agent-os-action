---
title: Action Inputs Reference
sidebar_position: 1
ai_generated: true
last_updated: 2024-11-07
---

> ⚠️ **AI-Generated Documentation** - Generated from action.yml. Please verify against actual action.yml for accuracy.

# Action Inputs Reference

Complete reference for all inputs supported by the Agent OS Security Action.

## Quick Reference

```yaml
- uses: securedotcom/agent-os-action@v3
  with:
    # Required
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    
    # Common options
    review-type: 'audit'
    multi-agent-mode: 'single'
    max-files: 50
    cost-limit: '1.0'
    fail-on-blockers: 'true'
```

## Authentication

### `anthropic-api-key`

**Type**: `string` | **Required**: `false` | **Default**: `''`

Anthropic API key for Claude AI analysis.

**Usage**:
```yaml
anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

### `openai-api-key`

**Type**: `string` | **Required**: `false` | **Default**: `''`

OpenAI API key for GPT-4 analysis (alternative to Anthropic).

**Usage**:
```yaml
openai-api-key: ${{ secrets.OPENAI_API_KEY }}
ai-provider: 'openai'
model: 'gpt-4-turbo-preview'
```

## AI Configuration

### `ai-provider`

**Type**: `string` | **Required**: `false` | **Default**: `'auto'`  
**Options**: `'anthropic'` | `'openai'` | `'foundation-sec'` | `'ollama'` | `'auto'`

Which AI provider to use for analysis.

| Provider | Cost | Quality | Status |
|----------|------|---------|--------|
| `anthropic` | $0.30/run | Excellent | ✅ Recommended |
| `openai` | $0.90/run | Good | ⚠️ 3x cost |
| `foundation-sec` | $0.00 | Security-optimized | 🧪 Beta |
| `ollama` | $0.00 | Fair | 🧪 Dev only |
| `auto` | Varies | Best available | 🔄 Auto-select |

### `model`

**Type**: `string` | **Required**: `false` | **Default**: `'claude-sonnet-4-20250514'`

AI model to use for analysis.

**Common Models**:
- **Anthropic**: `claude-sonnet-4-20250514`, `claude-3-5-sonnet-20241022`
- **OpenAI**: `gpt-4-turbo-preview`, `gpt-4`
- **Ollama**: `llama3`, `codellama`, `mixtral`

### `multi-agent-mode`

**Type**: `string` | **Required**: `false` | **Default**: `'single'`  
**Options**: `'single'` | `'sequential'`

Whether to use single-agent or multi-agent analysis.

| Mode | Cost | Time | Quality | Recommendation |
|------|------|------|---------|----------------|
| `single` | ~$0.30 | 2-3 min | Excellent | ✅ Recommended |
| `sequential` | ~$2-3 | 10-15 min | Similar | ❌ Not recommended |

## Review Configuration

### `review-type`

**Type**: `string` | **Required**: `false` | **Default**: `'audit'`  
**Options**: `'audit'` | `'security'` | `'review'`

Type of review to perform.

| Type | Focus | Use Case |
|------|-------|----------|
| `audit` | Security + Performance + Quality + Testing | Comprehensive analysis |
| `security` | Security vulnerabilities only | Security-focused reviews |
| `review` | Quality + Best practices | General code review |

### `project-type`

**Type**: `string` | **Required**: `false` | **Default**: `'auto'`

Project type for context-aware analysis.

**Options**: `auto`, `backend-api`, `dashboard-ui`, `data-pipeline`, `infrastructure`

## File Selection

### `include-paths`

**Type**: `string` | **Required**: `false` | **Default**: `''`

Comma-separated list of paths to include (glob patterns supported).

**Examples**:
```yaml
# Only analyze src directory
include-paths: 'src/**'

# Multiple paths
include-paths: 'src/**,lib/**,api/**'
```

### `exclude-paths`

**Type**: `string` | **Required**: `false` | **Default**: `''`

Comma-separated list of paths to exclude (glob patterns supported).

**Recommended**:
```yaml
exclude-paths: 'tests/**,*.test.*,node_modules/**,dist/**,build/**,vendor/**'
```

### `max-files`

**Type**: `number` | **Required**: `false` | **Default**: `50`

Maximum number of files to analyze.

**Recommendations**:
- Small repos: `20-30`
- Medium repos: `50` (default)
- Large repos: `100` (may increase cost)

## Cost Controls

### `cost-limit`

**Type**: `string` | **Required**: `false` | **Default**: `'5.0'`

Maximum cost in USD before aborting analysis.

**Recommendations**:
- Single-agent mode: `1.0` (typical: $0.30)
- Multi-agent mode: `5.0` (typical: $2-3)
- Large repos: `10.0`

## Quality Gates

### `fail-on-blockers`

**Type**: `boolean` | **Required**: `false` | **Default**: `true`

Fail the workflow if blocking issues are found.

### `fail-on`

**Type**: `string` | **Required**: `false` | **Default**: `''`

Comma-separated list of finding types that should fail the workflow.

**Format**: `category:severity`

**Examples**:
```yaml
# Fail on critical and high security issues
fail-on: 'security:critical,security:high'

# Fail on any critical issue
fail-on: 'security:critical,performance:critical,quality:critical'
```

**Categories**: `security`, `performance`, `quality`, `testing`  
**Severities**: `critical`, `high`, `medium`, `low`

## Output Configuration

### `comment-on-pr`

**Type**: `boolean` | **Required**: `false` | **Default**: `true`

Post review findings as a PR comment.

**Requires**: `pull-requests: write` permission

### `upload-reports`

**Type**: `boolean` | **Required**: `false` | **Default**: `true`

Upload reports as workflow artifacts.

**Artifacts uploaded**:
- `audit-report.md`: Markdown report
- `results.json`: JSON findings
- `results.sarif`: SARIF report
- `metrics.json`: Cost and metrics

## Complete Example

```yaml
name: AI Code Review

on:
  pull_request:
    branches: [main]

jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
      security-events: write
    
    steps:
      - uses: actions/checkout@v4
      
      - name: AI Code Review
        uses: securedotcom/agent-os-action@v3
        with:
          # Authentication
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          
          # AI Configuration
          ai-provider: 'anthropic'
          model: 'claude-sonnet-4-20250514'
          multi-agent-mode: 'single'
          
          # Review Configuration
          review-type: 'audit'
          project-type: 'auto'
          
          # File Selection
          include-paths: 'src/**,lib/**'
          exclude-paths: 'tests/**,*.test.*,node_modules/**'
          max-files: 50
          
          # Cost Controls
          cost-limit: '1.0'
          
          # Quality Gates
          fail-on-blockers: true
          fail-on: 'security:critical,security:high'
          
          # Output Configuration
          comment-on-pr: true
          upload-reports: true
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: .agent-os/reviews/results.sarif
        continue-on-error: true
```

## Related Documentation

- [Architecture Overview](../architecture/overview.md)
- [Deployment Runbook](../playbooks/deployment-runbook.md)
- [action.yml](../../action.yml) (source of truth)

