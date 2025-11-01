# Agent OS Code Reviewer

> **AI-Powered Automated Code Review System**  
> Comprehensive security, performance, testing, and quality analysis powered by Claude Sonnet 4

[![Version](https://img.shields.io/badge/version-1.0.15-blue.svg)](CHANGELOG.md)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![GitHub Action](https://img.shields.io/badge/GitHub%20Action-Ready-success.svg)](https://github.com/securedotcom/agent-os-action)

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/securedotcom/agent-os-action/badge)](https://securityscorecards.dev/viewer/?uri=github.com/securedotcom/agent-os-action)
[![CodeQL](https://github.com/securedotcom/agent-os-action/workflows/CodeQL%20Analysis/badge.svg)](https://github.com/securedotcom/agent-os-action/actions/workflows/codeql.yml)
[![Gitleaks](https://github.com/securedotcom/agent-os-action/workflows/Gitleaks%20Secret%20Scanning/badge.svg)](https://github.com/securedotcom/agent-os-action/actions/workflows/gitleaks.yml)
[![Semgrep](https://github.com/securedotcom/agent-os-action/workflows/Semgrep%20Analysis/badge.svg)](https://github.com/securedotcom/agent-os-action/actions/workflows/semgrep.yml)

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
✅ **Aardvark Mode** - Exploit chain analysis & security test generation
✅ **Project-Type Awareness** - Adapts standards for Backend, Frontend, Data, Infrastructure
✅ **Layered Security Detection** - AI + SAST + Secret Scanning + Repo Hygiene
✅ **Supply Chain Integrity** - Signed attestations with SLSA provenance
✅ **Comprehensive Reports** - Downloadable audit artifacts  

### 🛡️ Security & Trust

Agent OS employs **defense-in-depth** with multiple security layers:

| Layer | Tool | Purpose | Frequency |
|-------|------|---------|-----------|
| **AI Analysis** | Claude Sonnet 4 | Complex security issues, logic flaws | On-demand |
| **SAST** | CodeQL | Common vulnerabilities (injection, XSS) | Every push |
| **Secret Scanning** | Gitleaks | Hardcoded secrets, API keys | Daily |
| **Repo Hygiene** | OpenSSF Scorecard | Security best practices | Weekly |
| **Supply Chain** | GitHub Attestations | Verifiable release integrity | Every release |

**View our security posture**: [SECURITY.md](SECURITY.md) | [Security Tab](https://github.com/securedotcom/agent-os-action/security)

#### 🔐 Verifying Release Integrity

All releases are signed with SLSA provenance. Verify before use:

```bash
# Download release
gh release download v1.0.0 --repo securedotcom/agent-os-action

# Verify attestation
gh attestation verify agent-os-action-v1.0.0.tar.gz \
  --owner securedotcom
```

#### 🛠️ Enable Security Scanning for Your Repository

**Adopt these security tools by default** for comprehensive protection:

1. **CodeQL (SAST)** - [Enable in 2 clicks](https://docs.github.com/en/code-security/code-scanning/enabling-code-scanning/configuring-default-setup-for-code-scanning)
   - Go to: Repository → Settings → Code security → CodeQL analysis
   - Click "Set up" → "Default"
   - GitHub auto-detects languages and schedules scans

2. **OpenSSF Scorecard** - [Add workflow](https://github.com/ossf/scorecard-action#installation)
   - Copy [our scorecard.yml](.github/workflows/scorecard.yml) to your repo
   - Evaluates 20+ security best practices
   - Public badge shows security health

3. **Gitleaks (Secret Scanning)** - [Add workflow](https://github.com/gitleaks/gitleaks-action#usage)
   - Copy [our gitleaks.yml](.github/workflows/gitleaks.yml) to your repo
   - Scans for hardcoded secrets in code and history
   - Fails CI if secrets detected

4. **Semgrep (Performance & Correctness)** - [Add workflow](https://semgrep.dev/docs/semgrep-ci/overview/)
   - Copy [our semgrep.yml](.github/workflows/semgrep.yml) to your repo
   - Detects performance anti-patterns and bugs
   - Fast, customizable rules

**Copy all workflows at once**:
```bash
# Copy security workflows to your repository
curl -o .github/workflows/codeql.yml https://raw.githubusercontent.com/securedotcom/agent-os-action/main/.github/workflows/codeql.yml
curl -o .github/workflows/scorecard.yml https://raw.githubusercontent.com/securedotcom/agent-os-action/main/.github/workflows/scorecard.yml
curl -o .github/workflows/gitleaks.yml https://raw.githubusercontent.com/securedotcom/agent-os-action/main/.github/workflows/gitleaks.yml
curl -o .github/workflows/semgrep.yml https://raw.githubusercontent.com/securedotcom/agent-os-action/main/.github/workflows/semgrep.yml
```

---

## Aardvark Mode: Advanced Exploit Analysis

Agent OS now includes **Aardvark mode**, inspired by OpenAI's Aardvark, providing:

- **Exploitability Classification**: Prioritize vulnerabilities by how easily they can be exploited
- **Exploit Chain Analysis**: Identify how multiple vulnerabilities combine for greater impact
- **Automatic Security Test Generation**: Generate comprehensive test suites for discovered vulnerabilities
- **Strategic Remediation**: Fix chain-blocking vulnerabilities for maximum security ROI

```
[CHAIN-001] Auth Bypass → Full System Compromise
Step 1: SQL Injection → Bypass auth (⚠️ Trivial, 5 min)
Step 2: IDOR → Access admin (⚠️ Trivial, 5 min)
Step 3: Data Exfiltration → Download DB (⚠️ Trivial, 5 min)

Strategic Fix: Fixing Step 1 blocks entire chain
```

**Learn more**: [Aardvark Mode Documentation](docs/aardvark-mode.md)

**Example workflows**: [.github/workflows/examples/](.github/workflows/examples/)

---

## 🚀 Quick Start (5 Minutes)

### Prerequisites
- GitHub repository
- GitHub Actions enabled
- Anthropic API key ([Get one here](https://console.anthropic.com/))

> **⚠️ Runner Security**: For public repositories, **always use GitHub-hosted runners** (ubuntu-latest, macos-latest, windows-latest). Self-hosted runners on public repos pose significant security risks. For private repos, use locked-down, ephemeral self-hosted runners with network isolation and no persistent state.

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
| **Multi-Agent Mode** | | | |
| `multi-agent-mode` | No | `'single'` | Review mode: `single` (1 agent, fast), `sequential` (7 agents, deep with Aardvark) |
| `enable-exploit-analysis` | No | `'true'` | Enable exploit chain analysis (Aardvark mode) |
| `generate-security-tests` | No | `'true'` | Auto-generate security tests for vulnerabilities |
| `exploitability-threshold` | No | `'trivial'` | Block merge threshold: `trivial`, `moderate`, `complex`, `theoretical`, `none` |
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
| **Aardvark Mode Outputs** | | |
| `exploitability-trivial` | Number of trivially exploitable vulnerabilities | `2` |
| `exploitability-moderate` | Number of moderately exploitable vulnerabilities | `3` |
| `exploitability-complex` | Number of complex exploitability vulnerabilities | `1` |
| `exploit-chains-found` | Number of exploit chains identified | `2` |
| `tests-generated` | Number of security test files generated | `8` |

### Uploading SARIF to Security Tab

To surface findings in GitHub's Security tab, upload the SARIF output:

```yaml
- name: Run Code Review
  id: agent
  uses: securedotcom/agent-os-action@a03c88d  # v2.1.0
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}

- name: Upload SARIF to Code Scanning
  if: always() && steps.agent.outputs.sarif-path != ''
  continue-on-error: true  # Don't fail if Code Scanning not enabled
  uses: github/codeql-action/upload-sarif@afb54ba388a7dca6ecae48f608c4ff05ff4cc77a  # v3.25.15
  with:
    sarif_file: ${{ steps.agent.outputs.sarif-path }}
    category: agent-os-code-review
```

This makes findings visible in:
- **Security** → **Code scanning** tab
- Pull request checks
- Security overview dashboard

> **Note**: Code Scanning must be enabled first. See [Enable Code Scanning Guide](docs/ENABLE_CODE_SCANNING.md) for setup instructions.

#### Troubleshooting SARIF Uploads

If SARIF upload fails, check these common issues:

**1. Code Scanning Not Enabled**
```
Error: Code Security must be enabled for this repository to use code scanning
```
**Solution**: Enable Code Scanning in repository settings:
- Go to **Settings** → **Code security and analysis**
- Click **Set up** next to "Code scanning"
- Choose "Default" or "Advanced" setup

**2. Missing Permissions**
```
Error: Resource not accessible by integration
```
**Solution**: Add required permissions to workflow:
```yaml
permissions:
  contents: read
  security-events: write  # Required for SARIF upload
  actions: read           # Required for Code Scanning
```

**3. SARIF File Not Found**
```
Error: Unable to find SARIF file
```
**Solution**: Ensure the review completed successfully:
```yaml
- name: Upload SARIF
  if: always() && steps.review.outputs.sarif-path != ''
  uses: github/codeql-action/upload-sarif@afb54ba388a7dca6ecae48f608c4ff05ff4cc77a  # v3.25.15
  with:
    sarif_file: ${{ steps.review.outputs.sarif-path }}
```

**4. Invalid SARIF Format**
```
Error: Invalid SARIF file
```
**Solution**: The action generates valid SARIF 2.1.0. If you see this error, check:
- File wasn't corrupted during upload
- No custom modifications to SARIF output
- GitHub Actions runner has sufficient disk space

**5. Rate Limiting**
```
Error: You have exceeded a secondary rate limit
```
**Solution**: Add delays between uploads or reduce frequency:
```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@afb54ba388a7dca6ecae48f608c4ff05ff4cc77a  # v3.25.15
  with:
    sarif_file: ${{ steps.review.outputs.sarif-path }}
    wait-for-processing: true  # Wait for GitHub to process
```

**Debugging Tips**:
```yaml
- name: Debug SARIF
  run: |
    echo "SARIF path: ${{ steps.review.outputs.sarif-path }}"
    ls -la .agent-os/reviews/
    cat .agent-os/reviews/results.sarif | jq .version
```

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
  uses: securedotcom/agent-os-action@a03c88d  # v2.1.0
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    fail-on-blockers: 'true'

# Granular: Fail on specific severity/category
- name: Run Code Review  
  uses: securedotcom/agent-os-action@a03c88d  # v2.1.0
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    fail-on: 'security:high,security:critical,test:critical'

# Strict: Fail on any critical issue
- name: Run Code Review
  uses: securedotcom/agent-os-action@a03c88d  # v2.1.0
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    fail-on: 'any:critical'
```

**Cost-Optimized Example**:
```yaml
- name: Run Code Review (Cost-Optimized)
  uses: securedotcom/agent-os-action@a03c88d  # v2.1.0
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    only-changed: 'true'              # Only review changed files
    include-paths: 'src/**,lib/**'    # Only source code
    exclude-paths: 'test/**,docs/**'  # Skip tests and docs
    max-files: 30                     # Limit file count
    cost-limit: '0.50'                # Cap at $0.50
```

---

## 📁 Changed-Files Mode (PR Optimization)

For large repositories, analyzing only changed files dramatically reduces cost and latency.

### How It Works

When `only-changed: 'true'`, Agent OS:
1. Runs `git diff` to find changed files between PR base and head
2. Filters to only code files (`.js`, `.ts`, `.py`, `.java`, etc.)
3. Analyzes only those files instead of entire codebase
4. Typical reduction: **90-95% fewer files analyzed**

### Configuration

```yaml
on:
  pull_request:
    branches: [ main ]

jobs:
  pr-review:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    
    steps:
      - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332  # v4.1.7
        with:
          fetch-depth: 0  # Required for git diff
      
      - name: Review Changed Files Only
        uses: securedotcom/agent-os-action@a03c88d  # v2.1.0
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          only-changed: 'true'  # ← Enable changed-files mode
          fail-on: 'security:critical,security:high'
```

### Cost Comparison

**Full Codebase** (10,000 LOC):
- Files analyzed: ~200
- Duration: 2-3 minutes
- Cost: ~$0.50

**Changed Files Only** (typical PR with 500 LOC changed):
- Files analyzed: ~10
- Duration: 20-30 seconds
- Cost: ~$0.03

**Savings**: 94% cost reduction, 90% faster

### Best Practices

#### 1. Use for PR Reviews
```yaml
on:
  pull_request:  # ← Perfect for PRs
jobs:
  pr-review:
    steps:
      - uses: securedotcom/agent-os-action@a03c88d  # v2.1.0
        with:
          only-changed: 'true'
```

#### 2. Combine with Path Filters
```yaml
- uses: securedotcom/agent-os-action@a03c88d  # v2.1.0
  with:
    only-changed: 'true'
    include-paths: 'src/**,lib/**'  # Only source directories
    exclude-paths: 'test/**,docs/**,*.md'  # Skip non-code
```

#### 3. Full Audit on Schedule
```yaml
# PR reviews: changed files only
on:
  pull_request:
    # only-changed: 'true'

# Weekly audit: full codebase
on:
  schedule:
    - cron: '0 2 * * 0'
    # only-changed: 'false'
```

### Limitations

**Changed-files mode may miss**:
- Issues in unchanged files that interact with changes
- Systemic issues across the codebase
- Architecture-level problems

**Recommendation**: Use changed-files for PRs, full audit weekly/monthly.

### Troubleshooting

**Issue**: "No changed files found"
```
Warning: No files to analyze after applying filters
```
**Solution**: Ensure `fetch-depth: 0` in checkout step:
```yaml
- uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332  # v4.1.7
  with:
    fetch-depth: 0  # Required for git diff
```

**Issue**: Changed files not detected
**Solution**: Check that PR has a valid base branch:
```yaml
on:
  pull_request:
    branches: [ main, develop ]  # Specify base branches
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

### Enterprise API Gateway Support

Agent OS supports enterprise API gateways and custom endpoints for enhanced security, compliance, and cost management.

#### Anthropic via AWS Bedrock

```yaml
- name: Run Code Review (AWS Bedrock)
  uses: securedotcom/agent-os-action@a03c88d  # v2.1.0
  with:
    ai-provider: 'anthropic'
    anthropic-api-key: ${{ secrets.AWS_BEDROCK_API_KEY }}
  env:
    ANTHROPIC_BASE_URL: 'https://bedrock-runtime.us-east-1.amazonaws.com'
    AWS_REGION: 'us-east-1'
```

#### OpenAI via Azure OpenAI

```yaml
- name: Run Code Review (Azure OpenAI)
  uses: securedotcom/agent-os-action@a03c88d  # v2.1.0
  with:
    ai-provider: 'openai'
    openai-api-key: ${{ secrets.AZURE_OPENAI_API_KEY }}
  env:
    OPENAI_BASE_URL: 'https://your-resource.openai.azure.com'
    OPENAI_API_VERSION: '2024-02-15-preview'
```

#### Anthropic via Google Vertex AI

```yaml
- name: Run Code Review (Vertex AI)
  uses: securedotcom/agent-os-action@a03c88d  # v2.1.0
  with:
    ai-provider: 'anthropic'
    anthropic-api-key: ${{ secrets.VERTEX_API_KEY }}
  env:
    ANTHROPIC_BASE_URL: 'https://us-central1-aiplatform.googleapis.com/v1/projects/YOUR_PROJECT/locations/us-central1/publishers/anthropic/models'
    GOOGLE_APPLICATION_CREDENTIALS: ${{ secrets.GCP_CREDENTIALS }}
```

#### Custom API Gateway (Enterprise)

For organizations with custom API gateways:

```yaml
- name: Run Code Review (Custom Gateway)
  uses: securedotcom/agent-os-action@a03c88d  # v2.1.0
  with:
    ai-provider: 'anthropic'
    anthropic-api-key: ${{ secrets.GATEWAY_API_KEY }}
  env:
    ANTHROPIC_BASE_URL: 'https://api-gateway.your-company.com/ai/anthropic'
    # Optional: Custom headers for authentication/routing
    ANTHROPIC_HEADERS: '{"X-Custom-Auth": "bearer-token", "X-Tenant-ID": "your-tenant"}'
```

#### Self-Hosted Ollama (Air-Gapped)

For air-gapped or highly secure environments:

```yaml
- name: Run Code Review (Self-Hosted)
  uses: securedotcom/agent-os-action@a03c88d  # v2.1.0
  with:
    ai-provider: 'ollama'
    ollama-endpoint: 'http://internal-ollama.company.local:11434'
    model: 'llama3:70b'  # Use your deployed model
```

#### Enterprise Benefits

✅ **Data Sovereignty**: Keep data within your cloud/region  
✅ **Compliance**: Meet HIPAA, SOC 2, GDPR requirements  
✅ **Cost Control**: Use reserved capacity or committed spend  
✅ **Network Security**: Route through private VPCs/VPNs  
✅ **Audit Trail**: Centralized logging and monitoring  
✅ **Rate Limiting**: Org-wide quota management  

#### Environment Variables Reference

| Variable | Purpose | Example |
|----------|---------|---------|
| `ANTHROPIC_BASE_URL` | Custom Anthropic endpoint | `https://bedrock-runtime.us-east-1.amazonaws.com` |
| `OPENAI_BASE_URL` | Custom OpenAI endpoint | `https://your-resource.openai.azure.com` |
| `OPENAI_API_VERSION` | Azure OpenAI API version | `2024-02-15-preview` |
| `OLLAMA_ENDPOINT` | Ollama server URL | `http://localhost:11434` |
| `AWS_REGION` | AWS region for Bedrock | `us-east-1` |
| `GOOGLE_APPLICATION_CREDENTIALS` | GCP credentials path | `/path/to/credentials.json` |

---

## 🤖 Multi-Agent Mode

Agent OS supports **two review modes** with different trade-offs:

### Single-Agent Mode (Default)
- **Agents**: 1 unified agent
- **Duration**: 1-2 minutes
- **Cost**: ~$0.15 per run
- **Quality**: Good - comprehensive analysis
- **Best For**: PR reviews, daily CI, cost-conscious teams

### Multi-Agent Sequential Mode
- **Agents**: 7 specialized agents (with Aardvark mode)
- **Duration**: 8-10 minutes
- **Cost**: ~$1.00 per run (7x agents with Aardvark)
- **Quality**: Excellent - deep, focused analysis with exploit chains
- **Best For**: Weekly audits, pre-release reviews, compliance

### The 7 Specialized Agents (Aardvark Mode)

1. **🔴 Security Reviewer**
   - SQL injection, XSS, CSRF
   - Authentication & authorization flaws
   - Hardcoded secrets
   - Cryptographic issues
   - Dependency vulnerabilities

2. **🔴 Exploit Analyst** (Aardvark Mode)
   - Exploitability classification (trivial, moderate, complex)
   - Exploit chain identification
   - Attack surface analysis
   - Real-world risk assessment
   - Strategic remediation guidance

3. **🔴 Security Test Generator** (Aardvark Mode)
   - Automated unit test generation
   - Integration test creation
   - Fuzz test generation
   - PoC exploit creation (authorized testing)
   - Test coverage validation

4. **🟠 Performance Reviewer**
   - N+1 query problems
   - Memory leaks
   - Inefficient algorithms
   - Blocking I/O operations
   - Resource management issues

5. **🟢 Testing Reviewer**
   - Critical path coverage gaps
   - Missing edge case tests
   - Untested error scenarios
   - Integration test gaps
   - Test quality issues

6. **🔵 Code Quality Reviewer**
   - High complexity functions
   - Missing error handling
   - Code duplication
   - Documentation gaps
   - Architecture issues

7. **🟣 Review Orchestrator**
   - Deduplicates findings across agents
   - Prioritizes by business impact
   - Creates actionable plan
   - Makes APPROVED/REQUIRES FIXES decision

### Comparison Table

| Aspect | Single-Agent | Multi-Agent Sequential (Aardvark) |
|--------|--------------|-----------------------------------|
| **Agents** | 1 | 7 (with exploit-analyst + test-generator) |
| **Duration** | 1-2 min | 8-10 min |
| **Cost** | ~$0.15 | ~$1.00 |
| **Depth** | Comprehensive | Deep + Specialized + Exploit Analysis |
| **Deduplication** | N/A | Orchestrator handles |
| **Reports** | 1 main report | 7 agent + 1 orchestrated |
| **Exploit Analysis** | No | Yes (chains + exploitability) |
| **Test Generation** | No | Yes (automated security tests) |
| **Best For** | Fast feedback | Thorough audits + security |

### Usage Example

```yaml
name: Weekly Deep Audit

on:
  schedule:
    - cron: '0 9 * * 1'  # Monday 9 AM

jobs:
  deep-audit:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    
    steps:
      - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332  # v4.1.7
      
      - name: Multi-Agent Code Review
        uses: securedotcom/agent-os-action@a03c88d  # v2.1.0
        with:
          multi-agent-mode: 'sequential'
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          cost-limit: '5.0'  # Higher limit for multi-agent
          fail-on: 'security:critical,security:high'
```

### Output Structure

Multi-agent mode generates additional reports:

```
.agent-os/reviews/
├── audit-report.md          # Final orchestrated report
├── results.sarif            # SARIF for Code Scanning
├── results.json             # Structured findings
├── metrics.json             # Cost/time metrics
└── agents/                  # Individual agent reports
    ├── security-report.md
    ├── performance-report.md
    ├── testing-report.md
    ├── quality-report.md
    └── metrics.json         # Per-agent metrics
```

### When to Use Each Mode

**Use Single-Agent Mode for**:
- ✅ Pull request reviews (fast feedback)
- ✅ Daily CI checks
- ✅ Cost-conscious teams
- ✅ Small-medium codebases (<10K LOC)
- ✅ Quick iteration cycles

**Use Multi-Agent Sequential for**:
- ✅ Weekly/monthly deep audits
- ✅ Pre-release security reviews
- ✅ Compliance audits (SOC 2, HIPAA, etc.)
- ✅ Large enterprise codebases (>50K LOC)
- ✅ High-stakes production code
- ✅ When you need detailed per-category analysis

### Cost Optimization

**For Regular Use** (Daily/PR):
```yaml
multi-agent-mode: 'single'
cost-limit: '0.50'
only-changed: 'true'
```

**For Deep Audits** (Weekly):
```yaml
multi-agent-mode: 'sequential'
cost-limit: '5.0'
only-changed: 'false'
```

---

## 💰 Cost Estimation

### Expected Cost per Run

| Mode | Agents | Cost | Duration | Use Case |
|------|--------|------|----------|----------|
| **Single Agent** | 1 | $0.15-0.20 | 1-2 min | PR reviews, daily CI |
| **Multi-Agent (Standard)** | 5 | $0.75 | 5-7 min | Weekly audits |
| **Multi-Agent (Aardvark)** | 7 | $1.00 | 8-10 min | Security audits + tests |

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
- IDE extensions (VS Code)
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
