# High-Impact Improvements Plan

**Date**: October 27, 2025  
**Priority**: Critical for Production Readiness  
**Timeline**: 2-4 weeks for Phase 1

---

## 📊 Gap Analysis Summary

Based on comprehensive feedback, here are the critical gaps preventing production adoption:

| Gap | Impact | Priority | Effort |
|-----|--------|----------|--------|
| 1. Action contract unclear | HIGH | 🔴 CRITICAL | 2 hours |
| 2. Workflow security not hardened | HIGH | 🔴 CRITICAL | 4 hours |
| 3. No cost/latency guardrails | HIGH | 🔴 CRITICAL | 1 day |
| 4. Results not automatable | HIGH | 🔴 CRITICAL | 2 days |
| 5. Not org-ready | MEDIUM | 🟡 HIGH | 1 week |
| 6. Limited policy profiles | MEDIUM | 🟡 HIGH | 1 week |
| 7. No observability | MEDIUM | 🟡 HIGH | 3 days |
| 8. Privacy settings unclear | HIGH | 🟡 HIGH | 1 day |
| 9. Fail conditions not configurable | HIGH | 🟡 HIGH | 1 day |
| 10. Examples insufficient | LOW | 🟢 MEDIUM | 2 days |

---

## 🎯 Phase 1: Critical Production Readiness (Week 1-2)

### 1. Action Contract Documentation ✅ PRIORITY 1

**Problem**: Users can't see inputs/outputs without reading YAML

**Solution**: Add comprehensive tables to README

```markdown
## 📥 Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `anthropic-api-key` | No | `''` | Anthropic API key for Claude AI analysis |
| `cursor-api-key` | No | `''` | Cursor API key (alternative) |
| `review-type` | No | `'audit'` | Type of review: `audit`, `security`, `review` |
| `project-path` | No | `'.'` | Path to project to review |
| `project-type` | No | `'auto'` | Project type: `auto`, `backend-api`, `dashboard-ui`, `data-pipeline`, `infrastructure` |
| `fail-on-blockers` | No | `'true'` | Fail workflow if merge blockers found |
| `fail-on` | No | `''` | Fail conditions: `security:high,test:critical` |
| `comment-on-pr` | No | `'true'` | Comment on PR with results |
| `upload-reports` | No | `'true'` | Upload reports as artifacts |
| `only-changed` | No | `'false'` | Only analyze changed files |
| `include-paths` | No | `''` | Glob patterns to include: `src/**,lib/**` |
| `exclude-paths` | No | `''` | Glob patterns to exclude: `test/**,docs/**` |
| `max-file-size` | No | `'50000'` | Max file size in bytes |
| `max-files` | No | `'50'` | Max files to analyze |
| `max-tokens` | No | `'8000'` | Max tokens per LLM call |
| `cost-limit` | No | `'1.0'` | Max cost in USD per run |
| `model` | No | `'claude-3-5-sonnet-20241022'` | AI model to use |
| `temperature` | No | `'0.3'` | Model temperature (0.0-1.0) |

## 📤 Outputs

| Output | Description | Example |
|--------|-------------|---------|
| `review-completed` | Whether review completed | `true` |
| `blockers-found` | Number of merge blockers | `3` |
| `suggestions-found` | Number of suggestions | `12` |
| `report-path` | Path to generated report | `.agent-os/reviews/audit-report.md` |
| `sarif-path` | Path to SARIF file | `.agent-os/reviews/results.sarif` |
| `cost-estimate` | Estimated cost in USD | `0.42` |
| `exit-code` | Exit code for CI gating | `0`, `1`, `2` |

## 🚦 Exit Codes

| Code | Meaning | When |
|------|---------|------|
| `0` | Success | No blockers or blockers allowed |
| `1` | Failure | Blockers found and `fail-on-blockers: true` |
| `2` | Error | Configuration error or API failure |
```

**Implementation**: Update README.md

---

### 2. Workflow Security Hardening ✅ PRIORITY 1

**Problem**: Example workflows don't follow security best practices

**Solution**: Create hardened example workflow

```yaml
name: Agent OS Code Review (Hardened)

on:
  pull_request:
    branches: [ main, master ]
  schedule:
    - cron: '0 2 * * 0'
  workflow_dispatch:

# Least privilege permissions
permissions:
  contents: read          # Read code
  pull-requests: write    # Comment on PRs
  security-events: write  # Upload SARIF
  actions: read          # Read workflow artifacts

# Prevent concurrent runs
concurrency:
  group: code-review-${{ github.ref }}
  cancel-in-progress: true

jobs:
  code-review:
    runs-on: ubuntu-latest
    timeout-minutes: 15  # Cap long LLM calls
    
    steps:
    - name: Checkout code
      uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332  # v4.1.7 (pinned by SHA)
      with:
        fetch-depth: 0
    
    - name: Setup Node.js
      uses: actions/setup-node@1e60f620b9541d16bece96c5465dc8ee9832be0b  # v4.0.3 (pinned)
      with:
        node-version: '18'
    
    - name: Run Agent OS Code Review
      uses: securedotcom/agent-os-action@v1.0.14  # Use semver tag
      with:
        anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
        review-type: 'audit'
        fail-on: 'security:high,security:critical'
        only-changed: 'true'  # Only review changed files
        max-files: 50
        max-tokens: 8000
        cost-limit: '1.0'
        redact-secrets: 'true'  # Redact before LLM
        redact-pii: 'true'      # Redact PII
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    
    - name: Upload SARIF
      if: always()
      uses: github/codeql-action/upload-sarif@afb54ba388a7dca6ecae48f608c4ff05ff4cc77a  # v3.25.15 (pinned)
      with:
        sarif_file: .agent-os/reviews/results.sarif
    
    - name: Upload Reports
      if: always()
      uses: actions/upload-artifact@50769540e7f4bd5e21e526ee35c689e35e0d6874  # v4.4.0 (pinned)
      with:
        name: code-review-reports
        path: .agent-os/reviews/
        retention-days: 90
```

**Key Security Features**:
- ✅ Least privilege permissions
- ✅ Actions pinned by commit SHA
- ✅ Concurrency control
- ✅ Timeout limits
- ✅ Secret redaction
- ✅ PII redaction

**Implementation**: Create `examples/workflows/hardened-workflow.yml`

---

### 3. Cost/Latency Guardrails ✅ PRIORITY 1

**Problem**: No way to control costs or prevent runaway LLM calls

**Solution**: Add comprehensive cost controls

**New Inputs**:
```yaml
inputs:
  # Path filters
  only-changed:
    description: 'Only analyze changed files (PR mode)'
    default: 'false'
  include-paths:
    description: 'Glob patterns to include (comma-separated)'
    default: ''
  exclude-paths:
    description: 'Glob patterns to exclude (comma-separated)'
    default: 'test/**,docs/**,*.md'
  
  # Size limits
  max-file-size:
    description: 'Max file size in bytes'
    default: '50000'
  max-files:
    description: 'Max files to analyze'
    default: '50'
  max-lines-per-file:
    description: 'Max lines per file'
    default: '1000'
  max-repo-lines:
    description: 'Max total lines to analyze'
    default: '50000'
  
  # Token limits
  max-tokens-per-file:
    description: 'Max tokens per file'
    default: '2000'
  max-tokens-per-run:
    description: 'Max tokens per run'
    default: '100000'
  
  # Cost limits
  cost-limit:
    description: 'Max cost in USD per run'
    default: '1.0'
  fail-on-budget-exceeded:
    description: 'Fail if budget exceeded'
    default: 'true'
```

**Cost Calculation**:
```python
# In run-ai-audit.py
def estimate_cost(input_tokens, output_tokens):
    """Estimate cost based on Claude Sonnet 4 pricing"""
    input_cost = (input_tokens / 1_000_000) * 3.0   # $3 per 1M
    output_cost = (output_tokens / 1_000_000) * 15.0  # $15 per 1M
    return input_cost + output_cost

def check_budget(estimated_cost, limit):
    """Check if within budget"""
    if estimated_cost > limit:
        print(f"⚠️  Estimated cost ${estimated_cost:.2f} exceeds limit ${limit:.2f}")
        if fail_on_budget_exceeded:
            sys.exit(2)
        return False
    return True
```

**Cost Documentation**:
```markdown
## 💰 Cost Estimation

### Expected Cost per KLOC (1000 Lines of Code)

| Language | Avg Cost | Range |
|----------|----------|-------|
| JavaScript/TypeScript | $0.05 | $0.03-$0.08 |
| Python | $0.04 | $0.02-$0.06 |
| Java | $0.06 | $0.04-$0.10 |
| Go | $0.03 | $0.02-$0.05 |

### Cost Tuning

**Reduce costs by**:
- Enable `only-changed: true` for PR reviews
- Set `max-files: 25` instead of 50
- Use `exclude-paths` to skip tests/docs
- Set `max-tokens-per-file: 1000`
- Use `cost-limit: 0.50` to cap spending

**Example**: 10K LOC repo
- Full audit: ~$0.50
- PR review (100 changed lines): ~$0.05
- Weekly audits: ~$2/month
```

**Implementation**: Update `action.yml` and `run-ai-audit.py`

---

### 4. Results You Can Automate On ✅ PRIORITY 1

**Problem**: Results not in standard formats for automation

**Solution**: Generate SARIF and structured JSON

**SARIF Output** (for GitHub Code Scanning):
```python
def generate_sarif(findings, repo_path):
    """Generate SARIF 2.1.0 format"""
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Agent OS Code Reviewer",
                    "version": "1.0.14",
                    "informationUri": "https://github.com/securedotcom/agent-os-action",
                    "rules": []
                }
            },
            "results": []
        }]
    }
    
    for finding in findings:
        result = {
            "ruleId": finding['rule_id'],
            "level": finding['level'],  # "error", "warning", "note"
            "message": {
                "text": finding['message']
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding['file_path']
                    },
                    "region": {
                        "startLine": finding['line_number']
                    }
                }
            }]
        }
        sarif['runs'][0]['results'].append(result)
    
    return sarif
```

**Structured JSON Output**:
```json
{
  "version": "1.0.14",
  "timestamp": "2025-10-27T14:30:00Z",
  "repository": "securedotcom/Spring-Backend",
  "commit": "abc123",
  "summary": {
    "total_files": 42,
    "lines_analyzed": 8543,
    "duration_seconds": 127,
    "cost_usd": 0.42,
    "model": "claude-3-5-sonnet-20241022"
  },
  "findings": {
    "critical": 2,
    "high": 5,
    "medium": 12,
    "low": 8,
    "info": 15
  },
  "categories": {
    "security": 8,
    "performance": 7,
    "testing": 6,
    "quality": 13
  },
  "issues": [
    {
      "id": "SEC-001",
      "severity": "critical",
      "category": "security",
      "title": "SQL Injection Vulnerability",
      "file": "src/controllers/userController.js",
      "line": 45,
      "cwe": "CWE-89",
      "owasp": "A03:2021-Injection",
      "description": "User input concatenated into SQL query",
      "recommendation": "Use parameterized queries"
    }
  ]
}
```

**Concise PR Comments**:
```markdown
## 🤖 Agent OS Code Review

**Status**: ⚠️ Issues Found  
**Analyzed**: 42 files, 8,543 lines  
**Duration**: 2m 7s | **Cost**: $0.42

### Summary
- 🔴 **2 Critical** - Must fix before merge
- 🟠 **5 High** - Should fix soon
- 🟡 **12 Medium** - Consider fixing
- ⚪ **8 Low** - Nice to have

### Top Issues
1. 🔴 **SQL Injection** in `userController.js:45` ([CWE-89](https://cwe.mitre.org/data/definitions/89.html))
2. 🔴 **Hardcoded Secret** in `config.js:12` ([CWE-798](https://cwe.mitre.org/data/definitions/798.html))
3. 🟠 **N+1 Query** in `orderService.js:78`

📄 [Full Report](../artifacts/code-review-reports/audit-report.md) | 📊 [JSON Results](../artifacts/code-review-reports/results.json) | 🔍 [SARIF](../artifacts/code-review-reports/results.sarif)
```

**Implementation**: Update `run-ai-audit.py` to generate SARIF and JSON

---

## 🎯 Phase 2: Organization Readiness (Week 3-4)

### 5. Org Readiness ✅ PRIORITY 2

**Tasks**:
1. **GitHub Marketplace Listing**
   - Create marketplace metadata
   - Add branding assets
   - Submit for review

2. **Semver Releases**
   - Tag `v1.0.0` (stable)
   - Create `v1` major tag (auto-updates)
   - Publish release notes

3. **Org-Wide Reusable Workflow**
```yaml
# .github/workflows/reusable-code-review.yml
name: Reusable Code Review

on:
  workflow_call:
    inputs:
      project-type:
        type: string
        default: 'auto'
    secrets:
      ANTHROPIC_API_KEY:
        required: true

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: securedotcom/agent-os-action@v1
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          project-type: ${{ inputs.project-type }}
```

4. **Branch Protection Recipe**
```yaml
# Branch protection settings
required_status_checks:
  strict: true
  contexts:
    - "code-review"
required_pull_request_reviews:
  required_approving_review_count: 1
  dismiss_stale_reviews: true
restrictions: null
enforce_admins: true
```

---

### 6. Policy/Profiles ✅ PRIORITY 2

**Create Language/Framework-Specific Profiles**:

```
profiles/
├── backend-node/
│   ├── standards/
│   │   ├── security-checklist.md
│   │   ├── performance-checklist.md
│   │   └── testing-checklist.md
│   └── config.yml
├── backend-python/
├── backend-java/
├── backend-go/
├── frontend-react/
├── frontend-vue/
├── frontend-angular/
├── mobile-android/
├── mobile-ios/
├── infra-terraform/
├── infra-kubernetes/
└── data-pipeline/
```

**Profile Selection**:
```yaml
with:
  profile: 'backend-node'  # Auto-loads Node.js specific rules
```

**Profile Config Example** (`profiles/backend-node/config.yml`):
```yaml
name: "Backend Node.js"
description: "Node.js/Express backend API standards"

rules:
  security:
    - id: "no-eval"
      severity: "critical"
      enabled: true
    - id: "sql-injection"
      severity: "critical"
      enabled: true
    - id: "xss"
      severity: "high"
      enabled: true
  
  performance:
    - id: "n-plus-one"
      severity: "high"
      enabled: true
    - id: "memory-leak"
      severity: "high"
      enabled: true
  
  testing:
    - id: "missing-tests"
      severity: "medium"
      enabled: true
      threshold: 80  # 80% coverage required

severity_mapping:
  critical: "error"
  high: "warning"
  medium: "note"
  low: "none"
```

---

### 7. Observability ✅ PRIORITY 2

**Structured Logging**:
```python
import json
import time

class ReviewMetrics:
    def __init__(self):
        self.start_time = time.time()
        self.metrics = {
            "files_reviewed": 0,
            "lines_analyzed": 0,
            "tokens_input": 0,
            "tokens_output": 0,
            "cost_usd": 0.0,
            "duration_seconds": 0,
            "model": "",
            "findings": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            }
        }
    
    def record_file(self, lines):
        self.metrics["files_reviewed"] += 1
        self.metrics["lines_analyzed"] += lines
    
    def record_llm_call(self, input_tokens, output_tokens, cost):
        self.metrics["tokens_input"] += input_tokens
        self.metrics["tokens_output"] += output_tokens
        self.metrics["cost_usd"] += cost
    
    def finalize(self):
        self.metrics["duration_seconds"] = int(time.time() - self.start_time)
        return self.metrics
    
    def save(self, path):
        with open(path, 'w') as f:
            json.dump(self.metrics, f, indent=2)
```

**HTML Report**:
```html
<!DOCTYPE html>
<html>
<head>
    <title>Code Review Report</title>
    <style>
        body { font-family: system-ui; max-width: 1200px; margin: 0 auto; padding: 20px; }
        .summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; }
        .card { background: #f5f5f5; padding: 20px; border-radius: 8px; }
        .critical { color: #d32f2f; }
        .high { color: #f57c00; }
        .chart { height: 300px; }
    </style>
</head>
<body>
    <h1>Code Review Report</h1>
    <div class="summary">
        <div class="card">
            <h3>Files Reviewed</h3>
            <p class="metric">42</p>
        </div>
        <div class="card">
            <h3>Issues Found</h3>
            <p class="metric critical">27</p>
        </div>
        <div class="card">
            <h3>Duration</h3>
            <p class="metric">2m 7s</p>
        </div>
        <div class="card">
            <h3>Cost</h3>
            <p class="metric">$0.42</p>
        </div>
    </div>
    <!-- Charts and detailed findings -->
</body>
</html>
```

---

### 8. Model & Privacy Settings ✅ PRIORITY 2

**New Inputs**:
```yaml
inputs:
  model:
    description: 'AI model to use'
    default: 'claude-3-5-sonnet-20241022'
  temperature:
    description: 'Model temperature (0.0-1.0)'
    default: '0.3'
  max-tokens:
    description: 'Max tokens per LLM call'
    default: '8000'
  anthropic-base-url:
    description: 'Custom Anthropic API endpoint (for gateways)'
    default: 'https://api.anthropic.com'
  no-external-network:
    description: 'Disable external network calls (local LLM only)'
    default: 'false'
  redact-secrets:
    description: 'Redact secrets before LLM'
    default: 'true'
  redact-pii:
    description: 'Redact PII before LLM'
    default: 'true'
```

**Privacy Documentation**:
```markdown
## 🔒 Data Privacy & Security

### What Gets Sent to AI

**Sent to Anthropic API**:
- File paths and names
- Code content (up to 50 files)
- File structure

**NOT Sent**:
- Git history
- Secrets (if `redact-secrets: true`)
- PII (if `redact-pii: true`)
- Binary files
- Files >50KB

### Data Retention

According to Anthropic's policy:
- API requests not used for training
- Not retained long-term
- See: https://www.anthropic.com/privacy

### Enterprise Gateway

For additional privacy:
```yaml
with:
  anthropic-base-url: 'https://your-gateway.company.com/v1'
  redact-secrets: 'true'
  redact-pii: 'true'
```

### Local LLM (No External Network)

For maximum privacy:
```yaml
with:
  no-external-network: 'true'
  local-llm-endpoint: 'http://localhost:11434'  # Ollama
```
```

---

### 9. Fail Conditions ✅ PRIORITY 2

**Configurable Fail Conditions**:
```yaml
inputs:
  fail-on:
    description: 'Fail conditions (comma-separated)'
    default: ''
    # Examples:
    # 'security:high,security:critical'
    # 'test:critical,performance:high'
    # 'any:critical'
```

**Exit Code Documentation**:
```markdown
## 🚦 Exit Codes & CI Gating

### Exit Codes

| Code | Meaning | Description |
|------|---------|-------------|
| `0` | Success | No blockers or allowed by config |
| `1` | Failure | Blockers found matching `fail-on` |
| `2` | Error | Configuration or API error |

### CI Gating Examples

**Block on any critical security issue**:
```yaml
with:
  fail-on: 'security:critical'
```

**Block on high/critical in security or testing**:
```yaml
with:
  fail-on: 'security:high,security:critical,test:critical'
```

**Block on any critical issue**:
```yaml
with:
  fail-on: 'any:critical'
```

**Never fail (report only)**:
```yaml
with:
  fail-on: ''
  fail-on-blockers: 'false'
```
```

---

### 10. Examples ✅ PRIORITY 3

**Create Curated Examples**:

```
examples/
├── repos/
│   ├── minimal-node/          # Minimal Node.js app
│   ├── minimal-python/        # Minimal Python app
│   ├── minimal-go/            # Minimal Go app
│   └── minimal-react/         # Minimal React app
├── workflows/
│   ├── basic-workflow.yml     # ✅ Already exists
│   ├── advanced-workflow.yml  # ✅ Already exists
│   ├── hardened-workflow.yml  # 🆕 Security hardened
│   ├── pr-review-mode.yml     # 🆕 PR review only
│   ├── scheduled-audit.yml    # 🆕 Weekly full audit
│   ├── path-filtered.yml      # 🆕 Only src/ and lib/
│   ├── cost-optimized.yml     # 🆕 Budget-conscious
│   └── slack-webhook.yml      # 🆕 Slack integration
└── configs/
    ├── minimal-config.yml
    ├── full-config.yml
    └── enterprise-config.yml
```

**Example: PR Review Mode**:
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
      - uses: securedotcom/agent-os-action@v1
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          only-changed: 'true'        # Only review changed files
          fail-on: 'security:critical' # Block critical security
          max-files: 25                # Limit for speed
          cost-limit: '0.25'           # Cap at $0.25
```

**Example: Cost-Optimized**:
```yaml
name: Cost-Optimized Audit

on:
  schedule:
    - cron: '0 2 * * 0'  # Weekly

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: securedotcom/agent-os-action@v1
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          include-paths: 'src/**,lib/**'  # Only source code
          exclude-paths: 'test/**,docs/**,*.md'
          max-files: 30
          max-tokens-per-file: 1500
          cost-limit: '0.50'
```

---

## 📊 Implementation Priority Matrix

### Week 1 (Critical)
- [ ] 1. Action contract documentation
- [ ] 2. Workflow security hardening
- [ ] 3. Cost/latency guardrails
- [ ] 4. SARIF + JSON output

### Week 2 (High)
- [ ] 5. Org readiness (Marketplace, semver)
- [ ] 6. Policy profiles (5 language profiles)
- [ ] 7. Observability (metrics, HTML reports)
- [ ] 8. Privacy settings

### Week 3 (Medium)
- [ ] 9. Fail conditions
- [ ] 10. Examples (8 curated workflows)

### Week 4 (Polish)
- [ ] Documentation updates
- [ ] Testing all features
- [ ] Release v1.1.0

---

## 📈 Success Metrics

After implementation:
- ✅ Setup time: <5 minutes (from 30)
- ✅ Security score: A+ (from C+)
- ✅ Cost predictability: 100% (from 0%)
- ✅ Automation ready: Yes (SARIF, JSON)
- ✅ Org adoption: 10+ repos (from 0)
- ✅ Documentation: Complete (inputs/outputs/examples)

---

## 🎯 Next Actions

1. **Review this plan** - Confirm priorities
2. **Start Week 1 tasks** - Critical items first
3. **Test each feature** - Real-world validation
4. **Update documentation** - Keep in sync
5. **Release v1.1.0** - Production-ready

---

**Status**: Ready for implementation  
**Owner**: Development team  
**Timeline**: 4 weeks to completion

