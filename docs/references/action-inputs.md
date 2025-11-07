---
title: GitHub Action Inputs Reference
sidebar_position: 1
ai_generated: true
last_updated: 2024-11-07
---

> ⚠️ **AI-Generated Documentation**
> Generated from action.yml. Please verify against actual action.yml for accuracy.

# GitHub Action Inputs Reference

Complete reference for all inputs supported by the Agent OS Code Reviewer GitHub Action.

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

**Type**: `string`  
**Required**: `false` (but required if not using OpenAI/Ollama)  
**Default**: `''`

Anthropic API key for Claude AI analysis.

**How to get**:
1. Sign up at [Anthropic Console](https://console.anthropic.com/)
2. Create an API key
3. Add to GitHub Secrets as `ANTHROPIC_API_KEY`

**Usage**:
```yaml
anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

### `openai-api-key`

**Type**: `string`  
**Required**: `false`  
**Default**: `''`

OpenAI API key for GPT-4 analysis (alternative to Anthropic).

**Usage**:
```yaml
openai-api-key: ${{ secrets.OPENAI_API_KEY }}
ai-provider: 'openai'
model: 'gpt-4-turbo-preview'
```

### `ollama-base-url`

**Type**: `string`  
**Required**: `false`  
**Default**: `''`

Base URL for Ollama API (for local/self-hosted LLM).

**Usage**:
```yaml
ollama-base-url: 'http://localhost:11434'
ai-provider: 'ollama'
model: 'llama3'
```

## AI Configuration

### `ai-provider`

**Type**: `string`  
**Required**: `false`  
**Default**: `'anthropic'`  
**Options**: `'anthropic'` | `'openai'` | `'ollama'`

Which AI provider to use for analysis.

**Recommendations**:
- `anthropic`: Best quality and cost (recommended)
- `openai`: Good quality but 3x more expensive
- `ollama`: Free but lower quality, requires local setup

### `model`

**Type**: `string`  
**Required**: `false`  
**Default**: `'claude-sonnet-4-20250514'`

AI model to use for analysis.

**Common Models**:
- **Anthropic**: `claude-sonnet-4-20250514`, `claude-3-5-sonnet-20241022`
- **OpenAI**: `gpt-4-turbo-preview`, `gpt-4`
- **Ollama**: `llama3`, `codellama`, `mixtral`

### `multi-agent-mode`

**Type**: `string`  
**Required**: `false`  
**Default**: `'single'`  
**Options**: `'single'` | `'sequential'`

Whether to use single-agent or multi-agent analysis.

**Comparison**:

| Mode | Cost | Time | Quality | Recommendation |
|------|------|------|---------|----------------|
| `single` | ~$0.30 | 2-3 min | Excellent | ✅ Recommended |
| `sequential` | ~$2-3 | 10-15 min | Similar | ❌ Not recommended |

**Usage**:
```yaml
multi-agent-mode: 'single'  # Use this (recommended)
```

## Review Configuration

### `review-type`

**Type**: `string`  
**Required**: `false`  
**Default**: `'audit'`  
**Options**: `'audit'` | `'security'` | `'review'`

Type of review to perform.

**Options**:
- `audit`: Comprehensive analysis (security + performance + quality + testing)
- `security`: Focus on security vulnerabilities only
- `review`: General code review (quality + best practices)

### `project-type`

**Type**: `string`  
**Required**: `false`  
**Default**: `'auto'`

Project type for context-aware analysis.

**Options**:
- `auto`: Auto-detect from codebase
- `backend-api`: REST/GraphQL API service
- `dashboard-ui`: Frontend dashboard application
- `data-pipeline`: ETL/data processing pipeline
- `ml-service`: Machine learning service
- `cli-tool`: Command-line tool

### `aardvark-mode`

**Type**: `boolean`  
**Required**: `false`  
**Default**: `false`

Enable Aardvark mode for exploit chain analysis.

**What it does**:
- Analyzes exploitability of vulnerabilities
- Identifies exploit chains
- Generates security test cases
- Scores exploits (trivial/moderate/complex/theoretical)

**Usage**:
```yaml
aardvark-mode: true
review-type: 'security'
```

**Cost Impact**: Adds ~$0.10-0.20 per run

## File Selection

### `include-paths`

**Type**: `string`  
**Required**: `false`  
**Default**: `''`

Comma-separated list of paths to include (glob patterns supported).

**Examples**:
```yaml
# Only analyze src directory
include-paths: 'src/**'

# Multiple paths
include-paths: 'src/**,lib/**,api/**'

# Specific file types
include-paths: '**/*.py,**/*.js'
```

### `exclude-paths`

**Type**: `string`  
**Required**: `false`  
**Default**: `''`

Comma-separated list of paths to exclude (glob patterns supported).

**Examples**:
```yaml
# Exclude tests and node_modules
exclude-paths: 'tests/**,node_modules/**'

# Exclude generated code
exclude-paths: '**/*.generated.*,**/dist/**,**/build/**'
```

**Recommended Exclusions**:
```yaml
exclude-paths: 'tests/**,*.test.*,node_modules/**,dist/**,build/**,vendor/**'
```

### `max-files`

**Type**: `number`  
**Required**: `false`  
**Default**: `50`

Maximum number of files to analyze.

**Recommendations**:
- Small repos: `20-30`
- Medium repos: `50` (default)
- Large repos: `100` (may increase cost)

**Usage**:
```yaml
max-files: 50
```

### `only-changed`

**Type**: `boolean`  
**Required**: `false`  
**Default**: `false`

Only analyze files changed in the PR/commit.

**Usage**:
```yaml
# For PR reviews
only-changed: true

# For full audits
only-changed: false
```

**Recommended**: Set to `true` for PR workflows, `false` for scheduled audits.

## Cost Controls

### `cost-limit`

**Type**: `string`  
**Required**: `false`  
**Default**: `'5.0'`

Maximum cost in USD before aborting analysis.

**Recommendations**:
- Single-agent mode: `1.0` (typical: $0.30)
- Multi-agent mode: `5.0` (typical: $2-3)
- Large repos: `10.0`

**Usage**:
```yaml
cost-limit: '1.0'  # Hard cap at $1
```

### `estimate-only`

**Type**: `boolean`  
**Required**: `false`  
**Default**: `false`

Only estimate cost without performing analysis.

**Usage**:
```yaml
estimate-only: true
```

**Output**: Prints estimated cost and exits.

## Quality Gates

### `fail-on-blockers`

**Type**: `boolean`  
**Required**: `false`  
**Default**: `false`

Fail the workflow if blocking issues are found.

**Usage**:
```yaml
fail-on-blockers: true
```

**What counts as a blocker**: Critical security vulnerabilities, high-severity security issues.

### `fail-on`

**Type**: `string`  
**Required**: `false`  
**Default**: `''`

Comma-separated list of finding types that should fail the workflow.

**Format**: `category:severity`

**Examples**:
```yaml
# Fail on critical and high security issues
fail-on: 'security:critical,security:high'

# Fail on any critical issue
fail-on: 'security:critical,performance:critical,quality:critical'

# Fail on all security issues
fail-on: 'security:critical,security:high,security:medium,security:low'
```

**Categories**: `security`, `performance`, `quality`, `testing`  
**Severities**: `critical`, `high`, `medium`, `low`

## Output Configuration

### `comment-on-pr`

**Type**: `boolean`  
**Required**: `false`  
**Default**: `true`

Post review findings as a PR comment.

**Usage**:
```yaml
comment-on-pr: true
```

**Requires**: `pull-requests: write` permission

### `upload-reports`

**Type**: `boolean`  
**Required**: `false`  
**Default**: `true`

Upload reports as workflow artifacts.

**Usage**:
```yaml
upload-reports: true
```

**Artifacts uploaded**:
- `audit-report.md`: Markdown report
- `results.json`: JSON findings
- `results.sarif`: SARIF report
- `metrics.json`: Cost and metrics

### `sarif-file`

**Type**: `string`  
**Required**: `false`  
**Default**: `'.agent-os/reviews/results.sarif'`

Path to SARIF output file.

**Usage**:
```yaml
sarif-file: './reports/security.sarif'
```

### `output-dir`

**Type**: `string`  
**Required**: `false`  
**Default**: `'.agent-os/reviews'`

Directory for all output files.

**Usage**:
```yaml
output-dir: './reports'
```

## Complete Example

```yaml
name: AI Code Review

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]
  schedule:
    - cron: '0 2 * * 1'  # Weekly on Monday 2am

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
          aardvark-mode: true
          
          # File Selection
          include-paths: 'src/**,lib/**'
          exclude-paths: 'tests/**,*.test.*,node_modules/**'
          max-files: 50
          only-changed: ${{ github.event_name == 'pull_request' }}
          
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

## Environment Variables

The action also respects these environment variables:

| Variable | Purpose | Default |
|----------|---------|---------|
| `ANTHROPIC_API_KEY` | Anthropic API key | None |
| `OPENAI_API_KEY` | OpenAI API key | None |
| `GITHUB_TOKEN` | GitHub API token | Auto-provided |
| `LOG_LEVEL` | Logging verbosity | `INFO` |

## Related Documentation

- [Architecture Overview](../architecture/overview.md)
- [GitHub Action Deployment Runbook](../playbooks/github-action-deployment.md)
- [Cost Optimization Guide](../playbooks/cost-optimization.md)
- [action.yml](../../action.yml) (source of truth)

