# 🚀 GitHub Action for Code Reviewer System

## 🎯 Overview

This GitHub Action provides automated code review capabilities for any repository. It performs comprehensive security, performance, testing, and quality analysis with detailed reporting and PR comments.

## 📋 Features

### **Automated Code Reviews**
- ✅ **Security Analysis**: Vulnerability detection, secrets scanning, injection testing
- ✅ **Performance Analysis**: N+1 queries, memory leaks, optimization opportunities
- ✅ **Test Coverage**: Critical path testing, regression test validation
- ✅ **Code Quality**: Maintainability, documentation, style compliance
- ✅ **Merge Blocker Detection**: Critical issues that must be fixed before merge
- ✅ **PR Comments**: Automatic comments on pull requests with findings
- ✅ **Artifact Reports**: Detailed reports uploaded as artifacts

### **Review Types**
- **`audit`**: Full codebase audit (default)
- **`security`**: Quick security-focused scan
- **`review`**: PR/change review with inline comments

## 🚀 Usage

### **Basic Usage**

```yaml
# .github/workflows/code-review.yml
name: Code Review

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  code-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: your-username/agent-os@main
        with:
          review-type: 'audit'
          fail-on-blockers: 'true'
          comment-on-pr: 'true'
          upload-reports: 'true'
```

### **Advanced Usage**

```yaml
# .github/workflows/code-review.yml
name: Code Review

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]
  workflow_dispatch:
    inputs:
      review_type:
        description: 'Type of review to run'
        required: true
        default: 'audit'
        type: choice
        options:
        - audit
        - security
        - review

jobs:
  code-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for better analysis
      
      - uses: your-username/agent-os@main
        with:
          review-type: ${{ github.event.inputs.review_type || 'audit' }}
          project-path: '.'
          fail-on-blockers: 'true'
          comment-on-pr: 'true'
          upload-reports: 'true'
```

### **Security-Only Workflow**

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on:
  push:
    branches: [ main ]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: your-username/agent-os@main
        with:
          review-type: 'security'
          fail-on-blockers: 'true'
          comment-on-pr: 'false'
          upload-reports: 'true'
```

## ⚙️ Configuration Options

### **Input Parameters**

| Parameter | Description | Required | Default | Options |
|-----------|-------------|----------|---------|---------|
| `review-type` | Type of review to run | No | `audit` | `audit`, `security`, `review` |
| `project-path` | Path to the project to review | No | `.` | Any valid path |
| `fail-on-blockers` | Fail workflow if merge blockers found | No | `true` | `true`, `false` |
| `comment-on-pr` | Comment on PR with review results | No | `true` | `true`, `false` |
| `upload-reports` | Upload review reports as artifacts | No | `true` | `true`, `false` |

### **Output Parameters**

| Parameter | Description | Type |
|-----------|-------------|------|
| `review-completed` | Whether the review completed successfully | Boolean |
| `blockers-found` | Number of merge blockers found | Number |
| `suggestions-found` | Number of suggestions found | Number |
| `report-path` | Path to the generated report | String |

## 📊 Sample Output

### **PR Comment Example**

```markdown
## 🔍 Code Review Report

# Code Review Report
Generated: 2024-01-15T10:30:00Z
Repository: your-org/your-repo
Branch: feature/new-feature
Commit: abc123def456

## Review Summary
**Review Date:** 2024-01-15T10:30:00Z
**Repository:** your-org/your-repo
**Branch:** feature/new-feature
**Commit:** abc123def456
**Overall Status:** REQUIRES FIXES
**Risk Level:** HIGH

### Summary Statistics
- **Total Issues Found:** 15
- **Merge Blockers:** 5 (Must fix before merge)
- **Suggestions:** 8 (Good to have improvements)
- **Nits:** 2 (Can ignore)

## Inline Comments

### [BLOCKER] Critical Issues (Must Fix)

#### File: `src/config.js`
```javascript
// Line 15: [BLOCKER] Hardcoded API key detected
const apiKey = "sk-1234567890abcdef"; // ❌ SECURITY RISK
```

**Issue:** Hardcoded API key in source code
**Risk:** High - API key could be exposed in version control
**Fix:** Use environment variable: `process.env.API_KEY`

#### File: `src/services/userService.js`
```javascript
// Line 42: [BLOCKER] SQL injection vulnerability detected
const query = `SELECT * FROM users WHERE id = ${userId}`; // ❌ SECURITY RISK
```

**Issue:** SQL injection vulnerability in user query
**Risk:** High - Could lead to data breach
**Fix:** Use parameterized queries: `SELECT * FROM users WHERE id = ?`

## Review Decision

### Overall Assessment
**Status:** REQUIRES FIXES

### Reasoning
- **Security:** Critical issues - Hardcoded secrets and SQL injection
- **Performance:** Good - No major performance issues
- **Testing:** Needs attention - Missing critical tests
- **Quality:** Good - Code quality is acceptable

### Next Steps
1. **Address merge blockers** - Fix all [BLOCKER] issues
2. **Consider suggestions** - Implement [SUGGESTION] items
3. **Re-review** - Request re-review after fixes

---

**Review completed by:** Code Reviewer System
**Review date:** 2024-01-15T10:30:00Z
**Repository:** your-org/your-repo
**Branch:** feature/new-feature
**Commit:** abc123def456

📁 **Detailed reports available in artifacts:** code-review-reports-123
```

### **Artifact Reports**

The action uploads detailed reports as artifacts:

```
code-review-reports-123/
├── audit-report.md          # Full audit report
├── security-report.md       # Security scan report
└── review-report.md         # PR review report
```

## 🔧 Customization

### **Custom Standards**

```yaml
# .github/workflows/code-review.yml
name: Code Review

on: [push, pull_request]

jobs:
  code-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      # Add custom standards
      - name: Add Custom Standards
        run: |
          mkdir -p .agent-os/standards/review
          cp custom-standards.md .agent-os/standards/review/
      
      - uses: your-username/agent-os@main
        with:
          review-type: 'audit'
```

### **Environment-Specific Reviews**

```yaml
# .github/workflows/code-review.yml
name: Code Review

on:
  push:
    branches: [ main, develop, staging ]

jobs:
  code-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set Environment
        run: |
          if [[ "${{ github.ref }}" == "refs/heads/main" ]]; then
            echo "ENVIRONMENT=production" >> $GITHUB_ENV
          elif [[ "${{ github.ref }}" == "refs/heads/staging" ]]; then
            echo "ENVIRONMENT=staging" >> $GITHUB_ENV
          else
            echo "ENVIRONMENT=development" >> $GITHUB_ENV
          fi
      
      - uses: your-username/agent-os@main
        with:
          review-type: 'audit'
          project-path: '.'
```

### **Conditional Reviews**

```yaml
# .github/workflows/code-review.yml
name: Code Review

on: [push, pull_request]

jobs:
  code-review:
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request' || contains(github.event.head_commit.message, '[review]')
    steps:
      - uses: actions/checkout@v4
      - uses: your-username/agent-os@main
        with:
          review-type: 'review'
```

## 📈 Best Practices

### **Workflow Organization**

```yaml
# .github/workflows/code-review.yml
name: Code Review

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]
  workflow_dispatch:
    inputs:
      review_type:
        description: 'Type of review to run'
        required: true
        default: 'audit'
        type: choice
        options:
        - audit
        - security
        - review

jobs:
  code-review:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - name: Run Code Review
        uses: your-username/agent-os@main
        with:
          review-type: ${{ github.event.inputs.review_type || 'audit' }}
          fail-on-blockers: 'true'
          comment-on-pr: 'true'
          upload-reports: 'true'
      
      - name: Create Review Summary
        run: |
          echo "## Code Review Summary" >> $GITHUB_STEP_SUMMARY
          echo "**Review Type:** ${{ github.event.inputs.review_type || 'audit' }}" >> $GITHUB_STEP_SUMMARY
          echo "**Repository:** ${{ github.repository }}" >> $GITHUB_STEP_SUMMARY
          echo "**Branch:** ${{ github.ref_name }}" >> $GITHUB_STEP_SUMMARY
          echo "**Commit:** ${{ github.sha }}" >> $GITHUB_STEP_SUMMARY
```

### **Team Notifications**

```yaml
# .github/workflows/code-review.yml
name: Code Review

on: [push, pull_request]

jobs:
  code-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: your-username/agent-os@main
        with:
          review-type: 'audit'
          fail-on-blockers: 'true'
      
      - name: Notify Team
        if: failure()
        uses: 8398a7/action-slack@v3
        with:
          status: failure
          text: "Code review failed for ${{ github.repository }} - Check the workflow for details"
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
```

## 🚨 Troubleshooting

### **Common Issues**

**Issue 1: Action fails to install Agent OS**
```yaml
# Solution: Add retry logic
- name: Install Agent OS with Retry
  run: |
    for i in {1..3}; do
      curl -sSL https://raw.githubusercontent.com/buildermethods/agent-os/main/setup/base.sh | bash -s -- --claude-code --cursor && break
      sleep 5
    done
```

**Issue 2: Reports not uploaded**
```yaml
# Solution: Check artifact upload
- name: Upload Reports
  uses: actions/upload-artifact@v4
  with:
    name: code-review-reports-${{ github.run_number }}
    path: .agent-os/reviews/
    retention-days: 30
  if: always()  # Upload even if previous steps fail
```

**Issue 3: PR comments not posted**
```yaml
# Solution: Check permissions
- name: Comment on PR
  uses: actions/github-script@v7
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
    script: |
      // Your comment script
```

### **Debug Mode**

```yaml
# .github/workflows/code-review.yml
name: Code Review

on: [push, pull_request]

jobs:
  code-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Debug Information
        run: |
          echo "Repository: ${{ github.repository }}"
          echo "Branch: ${{ github.ref_name }}"
          echo "Commit: ${{ github.sha }}"
          echo "Event: ${{ github.event_name }}"
          echo "Actor: ${{ github.actor }}"
      
      - uses: your-username/agent-os@main
        with:
          review-type: 'audit'
```

## 📚 Examples

### **Complete Workflow Example**

```yaml
# .github/workflows/code-review.yml
name: Code Review

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]
  workflow_dispatch:
    inputs:
      review_type:
        description: 'Type of review to run'
        required: true
        default: 'audit'
        type: choice
        options:
        - audit
        - security
        - review

jobs:
  code-review:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '18'
          cache: 'npm'
      
      - name: Run Code Review
        uses: your-username/agent-os@main
        with:
          review-type: ${{ github.event.inputs.review_type || 'audit' }}
          project-path: '.'
          fail-on-blockers: 'true'
          comment-on-pr: 'true'
          upload-reports: 'true'
      
      - name: Create Review Summary
        run: |
          echo "## Code Review Summary" >> $GITHUB_STEP_SUMMARY
          echo "**Review Type:** ${{ github.event.inputs.review_type || 'audit' }}" >> $GITHUB_STEP_SUMMARY
          echo "**Repository:** ${{ github.repository }}" >> $GITHUB_STEP_SUMMARY
          echo "**Branch:** ${{ github.ref_name }}" >> $GITHUB_STEP_SUMMARY
          echo "**Commit:** ${{ github.sha }}" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          echo "### Review Results" >> $GITHUB_STEP_SUMMARY
          echo "- ✅ Security analysis completed" >> $GITHUB_STEP_SUMMARY
          echo "- ✅ Performance analysis completed" >> $GITHUB_STEP_SUMMARY
          echo "- ✅ Test coverage analysis completed" >> $GITHUB_STEP_SUMMARY
          echo "- ✅ Code quality analysis completed" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          echo "### Issues Found" >> $GITHUB_STEP_SUMMARY
          echo "- 🚨 **Critical Issues:** 5 (Must fix before merge)" >> $GITHUB_STEP_SUMMARY
          echo "- ⚠️ **High-Priority Issues:** 12 (Address soon)" >> $GITHUB_STEP_SUMMARY
          echo "- 💡 **Suggestions:** 8 (Good to have improvements)" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          echo "📁 **Detailed reports available in artifacts**" >> $GITHUB_STEP_SUMMARY
          echo "👉 **Review the uploaded reports for detailed findings and action items**" >> $GITHUB_STEP_SUMMARY
```

## 🎯 Next Steps

1. **Add the workflow** to your repository
2. **Configure the action** with your preferred settings
3. **Test the workflow** with a test PR
4. **Customize standards** for your project needs
5. **Set up team notifications** for review results

---

**Ready to automate your code reviews!** 🚀  
**Add the workflow to your repository and start getting automated code reviews on every PR.**





