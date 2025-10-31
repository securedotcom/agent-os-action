# Architecture Documentation

**Agent OS Code Reviewer System Architecture**

---

## 🎯 Overview

Agent OS Code Reviewer is a distributed AI-powered code analysis system built on GitHub Actions. It uses a multi-agent architecture where specialized AI reviewers analyze different aspects of code quality.

### Design Principles

1. **Modularity** - Separate concerns into distinct components
2. **Scalability** - Handle codebases of any size
3. **Extensibility** - Easy to add new review types
4. **Reliability** - Graceful degradation and fallbacks
5. **Security** - Secure handling of code and credentials

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          GitHub Actions                              │
│                                                                       │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │              Agent OS Code Reviewer Action                     │ │
│  │                   (Composite Action)                           │ │
│  │                                                                 │ │
│  │  ┌──────────────────────────────────────────────────────────┐ │ │
│  │  │  1. Setup Phase                                          │ │ │
│  │  │     - Install dependencies                               │ │ │
│  │  │     - Detect project type                                │ │ │
│  │  │     - Load standards                                     │ │ │
│  │  └──────────────────────────────────────────────────────────┘ │ │
│  │                          │                                     │ │
│  │                          ▼                                     │ │
│  │  ┌──────────────────────────────────────────────────────────┐ │ │
│  │  │  2. Analysis Phase                                       │ │ │
│  │  │     ┌─────────────────────────────────────────────────┐ │ │ │
│  │  │     │  Review Orchestrator                            │ │ │ │
│  │  │     │  (Coordinates multi-agent analysis)             │ │ │ │
│  │  │     └─────────────────────────────────────────────────┘ │ │ │
│  │  │                          │                               │ │ │
│  │  │         ┌────────────────┼────────────────┬────────┐    │ │ │
│  │  │         │                │                │        │    │ │ │
│  │  │    ┌────▼────┐     ┌────▼────┐     ┌────▼────┐ ┌─▼──┐ │ │ │
│  │  │    │Security │     │Perform- │     │Testing  │ │Code│ │ │ │
│  │  │    │Reviewer │     │ance     │     │Reviewer │ │Qual│ │ │ │
│  │  │    │         │     │Reviewer │     │         │ │ity │ │ │ │
│  │  │    └────┬────┘     └────┬────┘     └────┬────┘ └─┬──┘ │ │ │
│  │  │         │                │                │        │    │ │ │
│  │  │         └────────────────┼────────────────┴────────┘    │ │ │
│  │  │                          │                               │ │ │
│  │  │                          ▼                               │ │ │
│  │  │     ┌─────────────────────────────────────────────────┐ │ │ │
│  │  │     │  Claude Sonnet 4 (Anthropic API)               │ │ │ │
│  │  │     │  - Analyzes code context                        │ │ │ │
│  │  │     │  - Identifies issues                            │ │ │ │
│  │  │     │  - Generates recommendations                    │ │ │ │
│  │  │     └─────────────────────────────────────────────────┘ │ │ │
│  │  └──────────────────────────────────────────────────────────┘ │ │
│  │                          │                                     │ │
│  │                          ▼                                     │ │
│  │  ┌──────────────────────────────────────────────────────────┐ │ │
│  │  │  3. Report Generation Phase                              │ │ │
│  │  │     - Aggregate findings                                 │ │ │
│  │  │     - Generate markdown reports                          │ │ │
│  │  │     - Calculate metrics                                  │ │ │
│  │  └──────────────────────────────────────────────────────────┘ │ │
│  │                          │                                     │ │
│  │                          ▼                                     │ │
│  │  ┌──────────────────────────────────────────────────────────┐ │ │
│  │  │  4. Integration Phase                                    │ │ │
│  │  │     ┌────────┬────────┬────────┬────────┐              │ │ │
│  │  │     │Create  │Upload  │Slack   │Metrics │              │ │ │
│  │  │     │PR      │Reports │Notify  │Track   │              │ │ │
│  │  │     └────────┴────────┴────────┴────────┘              │ │ │
│  │  └──────────────────────────────────────────────────────────┘ │ │
│  └─────────────────────────────────────────────────────────────── │ │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🧩 Component Details

### 1. GitHub Actions Runner

**Purpose**: Execution environment for the workflow

**Responsibilities**:
- Provides Ubuntu Linux environment
- Manages workflow lifecycle
- Handles secrets and environment variables
- Provides GitHub API access via `GITHUB_TOKEN`

**Technology**: GitHub-hosted runners (ubuntu-latest)

---

### 2. Agent OS Action (Composite Action)

**Purpose**: Main orchestration component

**Location**: `action.yml`

**Responsibilities**:
- Coordinate all phases of code review
- Manage dependencies and setup
- Handle errors and fallbacks
- Provide outputs for downstream steps

**Inputs**:
```yaml
- review-type: 'audit' | 'security' | 'review'
- project-path: Path to analyze
- project-type: 'auto' | 'backend-api' | 'dashboard-ui' | etc.
- fail-on-blockers: boolean
- comment-on-pr: boolean
- upload-reports: boolean
- anthropic-api-key: API key for Claude
- cursor-api-key: Optional Cursor key
```

**Outputs**:
```yaml
- completed: boolean
- blockers: number
- suggestions: number
- report-path: string
```

---

### 3. Project Type Detector

**Purpose**: Automatically identify project type

**Location**: `scripts/detect-project-type.sh`

**Detection Logic**:
```bash
Backend API:
  - package.json with express/fastify/koa
  - pom.xml with spring-boot
  - go.mod with gin/echo
  - requirements.txt with flask/django

Dashboard/UI:
  - package.json with react/vue/angular
  - next.config.js or nuxt.config.js
  - public/index.html

Data Pipeline:
  - airflow.cfg
  - dbt_project.yml
  - spark configuration

Infrastructure:
  - terraform files (*.tf)
  - kubernetes manifests (*.yaml in k8s/)
  - ansible playbooks
```

**Output**: Project type string used to load appropriate standards

---

### 4. Review Orchestrator

**Purpose**: Coordinate multi-agent analysis

**Location**: `scripts/run-ai-audit.py`

**Workflow**:
```python
1. Load project context
   - Read file tree
   - Identify important files
   - Extract code snippets

2. Select reviewers based on review type
   - audit: all reviewers
   - security: security reviewer only
   - review: quality + testing

3. For each reviewer:
   - Load reviewer profile
   - Load standards/checklists
   - Prepare AI prompt
   - Call Anthropic API
   - Parse response

4. Aggregate results
   - Merge findings
   - Deduplicate issues
   - Prioritize by severity
   - Generate final report
```

---

### 5. AI Reviewers

**Purpose**: Specialized agents for different concerns

#### Security Reviewer
**Profile**: `profiles/default/agents/security-reviewer.md`

**Focus Areas**:
- Authentication & Authorization
- Input validation & sanitization
- SQL/NoSQL injection
- XSS vulnerabilities
- CSRF protection
- Cryptography
- Secrets management
- Dependency vulnerabilities

**Standards**: `profiles/default/standards/review/security-checklist.md`

#### Performance Reviewer
**Profile**: `profiles/default/agents/performance-reviewer.md`

**Focus Areas**:
- N+1 query patterns
- Memory leaks
- Algorithm efficiency
- Caching strategies
- Database indexing
- Connection pooling
- Resource management

**Standards**: `profiles/default/standards/review/performance-checklist.md`

#### Testing Reviewer
**Profile**: `profiles/default/agents/test-coverage-reviewer.md`

**Focus Areas**:
- Unit test coverage
- Integration test gaps
- Critical path testing
- Edge case coverage
- Test quality
- Regression tests

**Standards**: `profiles/default/standards/review/testing-checklist.md`

#### Code Quality Reviewer
**Profile**: `profiles/default/agents/code-quality-reviewer.md`

**Focus Areas**:
- Code maintainability
- Documentation
- Error handling
- Logging & observability
- Configuration management
- Code organization

**Standards**: `profiles/default/standards/review/merge-blockers.md`

---

### 6. Claude Sonnet 4 (AI Backend)

**Purpose**: Perform actual code analysis

**API**: Anthropic API (https://api.anthropic.com/v1)

**Model**: `claude-3-5-sonnet-20241022`

**Configuration**:
```python
client = Anthropic(api_key=api_key)
response = client.messages.create(
    model="claude-3-5-sonnet-20241022",
    max_tokens=8000,
    temperature=0.3,  # Low for consistent analysis
    messages=[{
        "role": "user",
        "content": prompt
    }]
)
```

**Prompt Structure**:
```
You are a [REVIEWER_TYPE] reviewer.

Your role: [ROLE_DESCRIPTION]

Standards to check:
[CHECKLIST_CONTENT]

Codebase context:
[FILE_TREE]
[CODE_SNIPPETS]

Analyze the code and provide:
1. Critical issues (merge blockers)
2. Suggestions for improvement
3. Good practices observed

Format as markdown with severity tags.
```

---

### 7. Report Generator

**Purpose**: Create comprehensive markdown reports

**Location**: Integrated in `scripts/run-ai-audit.py`

**Report Structure**:
```markdown
# Code Review Report

## Executive Summary
- Overall status
- Risk level
- Issue counts

## Merge Blockers
- Critical issues requiring immediate fix

## Suggestions
- Recommended improvements

## Good Practices
- Positive observations

## Metrics
- Analysis statistics

## Action Items
- Prioritized todo list
```

**Output Location**: `.agent-os/reviews/[review-type]-report.md`

---

### 8. PR Manager

**Purpose**: Create and update pull requests with findings

**Location**: `action.yml` (GitHub Script step)

**Workflow**:
```javascript
1. Check for existing PR
   - Search for PRs with label "automated-review"
   - Check if branch exists

2. Create or update branch
   - Create new branch: audit/code-review-findings-YYYYMMDD
   - Or update existing branch

3. Commit report
   - Create blob with report content
   - Create tree with new blob
   - Create commit on branch

4. Create or update PR
   - Create new PR if none exists
   - Or add comment to existing PR
   - Add labels: "automated-review", "code-quality"

5. Set PR metadata
   - Title: "🤖 Code Review Findings - [DATE]"
   - Body: Summary + link to full report
   - Reviewers: Team leads (if configured)
```

---

### 9. Notification System

**Purpose**: Send alerts to Slack

**Integration**: GitHub App for Slack

**Setup**:
```bash
# In Slack channel:
/github subscribe owner/repo pulls reviews comments
```

**Notifications Sent**:
- PR created with findings
- PR updated with new findings
- Critical issues detected
- Review completed

**Alternative**: Webhook-based (deprecated in favor of GitHub App)

---

### 10. Metrics Tracker

**Purpose**: Track code quality trends over time

**Location**: `deployment-files/metrics/post-metrics.sh` (archived)

**Metrics Collected**:
- Number of blockers
- Number of suggestions
- Files analyzed
- Analysis time
- Trend over time

**Storage**: JSON file in GitHub Pages (planned feature)

---

## 🔄 Data Flow

### 1. Workflow Trigger
```
Schedule (cron) or Manual (workflow_dispatch) or PR event
    │
    ▼
GitHub Actions starts workflow
    │
    ▼
Checkout code
```

### 2. Setup Phase
```
Install dependencies (Python, pip packages)
    │
    ▼
Detect project type (backend-api, dashboard-ui, etc.)
    │
    ▼
Load appropriate standards and checklists
    │
    ▼
Copy Agent OS files to workspace
```

### 3. Analysis Phase
```
Scan codebase (file tree, important files)
    │
    ▼
For each reviewer:
    │
    ├─▶ Load reviewer profile
    │
    ├─▶ Prepare AI prompt with context
    │
    ├─▶ Call Anthropic API
    │
    ├─▶ Parse AI response
    │
    └─▶ Extract findings
    │
    ▼
Aggregate all findings
```

### 4. Report Generation
```
Merge findings from all reviewers
    │
    ▼
Deduplicate issues
    │
    ▼
Prioritize by severity (blocker > suggestion > nit)
    │
    ▼
Generate markdown report
    │
    ▼
Save to .agent-os/reviews/
```

### 5. Integration
```
Create/update PR with findings
    │
    ├─▶ Create branch
    │
    ├─▶ Commit report
    │
    └─▶ Create/update PR
    │
    ▼
Upload reports as artifacts
    │
    ▼
Slack notification (via GitHub App)
    │
    ▼
Post metrics (if configured)
```

---

## 🔐 Security Architecture

### Secrets Management

**GitHub Secrets** (encrypted at rest):
- `ANTHROPIC_API_KEY` - API key for Claude
- `CURSOR_API_KEY` - Optional Cursor key
- `GITHUB_TOKEN` - Auto-provided by GitHub Actions

**Access Control**:
- Secrets never logged or exposed
- Only accessible within workflow steps
- Encrypted in transit to Anthropic API

### Code Privacy

**What's Sent to Anthropic**:
- Up to 50 files (most important)
- File tree structure
- Code snippets for analysis

**What's NOT Sent**:
- Full git history
- Secrets or credentials
- Binary files
- Large files (>50KB)

**Anthropic Privacy**:
- API requests not used for training
- Not retained long-term
- See: https://www.anthropic.com/privacy

---

## 📊 Performance Characteristics

### Analysis Speed

| Codebase Size | Files Analyzed | Time |
|---------------|----------------|------|
| Small (<100 files) | 30-40 | 1-2 min |
| Medium (100-500 files) | 40-50 | 2-3 min |
| Large (500+ files) | 50 | 3-5 min |

**Optimization**: Only most important files analyzed (limited to 50)

### API Costs

| Review Type | Tokens | Cost |
|-------------|--------|------|
| Security only | ~50K | $0.15 |
| Performance only | ~50K | $0.15 |
| Full audit | ~150K | $0.45 |

**Monthly Cost** (weekly audits): $2-8 per repository

### Resource Usage

- **CPU**: Low (mostly I/O bound)
- **Memory**: ~500MB peak
- **Disk**: ~100MB for reports
- **Network**: ~5MB per analysis

---

## 🔌 Extension Points

### Adding New Reviewers

1. Create reviewer profile: `profiles/default/agents/new-reviewer.md`
2. Create standards: `profiles/default/standards/review/new-checklist.md`
3. Update orchestrator: `scripts/run-ai-audit.py`

### Adding New Project Types

1. Update detector: `scripts/detect-project-type.sh`
2. Create standards: `profiles/default/standards/[type]/`
3. Document in README

### Custom AI Prompts

Edit reviewer profiles in `profiles/default/agents/`

### Custom Standards

Edit checklists in `profiles/default/standards/review/`

---

## 🚀 Deployment Architecture

### Single Repository
```
Repository
    └── .github/workflows/code-review.yml
            │
            ▼
    Uses: securedotcom/agent-os-action@v1.0.14
```

### Multiple Repositories (Organization)
```
Organization
    ├── Secrets (organization-level)
    │   └── ANTHROPIC_API_KEY
    │
    ├── Repo 1
    │   └── .github/workflows/code-review.yml
    │
    ├── Repo 2
    │   └── .github/workflows/code-review.yml
    │
    └── Repo N
        └── .github/workflows/code-review.yml
```

### Monorepo
```
Monorepo
    └── .github/workflows/code-review.yml
            │
            ├─▶ Job 1: Review frontend/
            ├─▶ Job 2: Review backend/
            └─▶ Job 3: Review shared/
```

---

## 🔮 Future Architecture

### Planned Improvements

1. **Local LLM Support**
   - Ollama integration
   - Self-hosted models
   - No API costs

2. **Real-time Dashboard**
   - Live metrics
   - Trend analysis
   - Team leaderboard

3. **IDE Integration**
   - VS Code extension
   - Cursor integration
   - Real-time suggestions

4. **Custom Rules Engine**
   - User-defined rules
   - Company-specific standards
   - Rule marketplace

---

## 📚 References

- **GitHub Actions**: https://docs.github.com/en/actions
- **Anthropic API**: https://docs.anthropic.com/
- **Composite Actions**: https://docs.github.com/en/actions/creating-actions/creating-a-composite-action

---

**Last Updated**: October 27, 2025  
**Version**: 1.0.14

