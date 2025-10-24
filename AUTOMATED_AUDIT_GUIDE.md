# Automated Audit Integration Guide

This guide explains how to integrate Agent OS for routine automated audits across all your repositories.

## 🎯 Overview

Agent OS can be integrated into your development workflow in multiple ways:

1. **GitHub Actions** - Scheduled automated audits
2. **CLI Tool** - Manual and scripted audits
3. **Pre-commit Hooks** - Audit on every commit
4. **CI/CD Pipeline** - Integrate with existing pipelines

---

## 🚀 Quick Start

### **1. Setup CLI Tool**

```bash
# Make the CLI tool executable
chmod +x scripts/audit-cli.py

# Create symlink for easy access
ln -s $(pwd)/scripts/audit-cli.py /usr/local/bin/agent-audit

# Verify installation
agent-audit --help
```

### **2. Configure Repositories**

```bash
# Add repositories to audit
agent-audit add https://github.com/securedotcom/Spring-Backend
agent-audit add https://github.com/securedotcom/spring-fabric

# Or edit audit-config.json directly
vim audit-config.json

# List configured repositories
agent-audit list
```

### **3. Configure Git User**

```bash
# Set git user for PR creation
agent-audit config --git-user devatsecure --git-email devatsecure@users.noreply.github.com
```

### **4. Run Audits**

```bash
# Audit a single repository
agent-audit audit https://github.com/securedotcom/Spring-Backend

# Audit all configured repositories
agent-audit audit-all

# Run security-focused audit
agent-audit audit-all --type security

# Run quick audit
agent-audit audit-all --type quick
```

---

## 📅 Automated Scheduling Options

### **Option 1: GitHub Actions (Recommended)**

The `.github/workflows/automated-audit.yml` file is already configured to:

- ✅ Run weekly on Monday at 9 AM UTC
- ✅ Support manual triggers
- ✅ Audit all configured repositories
- ✅ Create PRs automatically
- ✅ Upload audit artifacts

**Setup:**

1. Add `ANTHROPIC_API_KEY` to GitHub Secrets:
   ```
   Settings → Secrets and variables → Actions → New repository secret
   Name: ANTHROPIC_API_KEY
   Value: your-api-key
   ```

2. Commit the workflow file:
   ```bash
   git add .github/workflows/automated-audit.yml
   git commit -m "Add automated audit workflow"
   git push
   ```

3. Verify workflow:
   ```
   Actions → Automated Repository Audit → Run workflow
   ```

### **Option 2: Cron Job**

Add to your crontab:

```bash
# Edit crontab
crontab -e

# Add weekly audit (every Monday at 9 AM)
0 9 * * 1 /usr/local/bin/agent-audit audit-all --type comprehensive

# Add daily security scan (every day at 2 AM)
0 2 * * * /usr/local/bin/agent-audit audit-all --type security
```

### **Option 3: Systemd Timer (Linux)**

Create `/etc/systemd/system/agent-audit.service`:

```ini
[Unit]
Description=Agent OS Automated Audit
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/agent-audit audit-all --type comprehensive
User=waseem.ahmed
WorkingDirectory=/Users/waseem.ahmed/Repos/agent-os
```

Create `/etc/systemd/system/agent-audit.timer`:

```ini
[Unit]
Description=Agent OS Audit Timer
Requires=agent-audit.service

[Timer]
OnCalendar=weekly
Persistent=true

[Install]
WantedBy=timers.target
```

Enable and start:

```bash
sudo systemctl enable agent-audit.timer
sudo systemctl start agent-audit.timer
sudo systemctl status agent-audit.timer
```

---

## 🔧 Advanced Configuration

### **Audit Configuration (`audit-config.json`)**

```json
{
  "repositories": [
    "https://github.com/securedotcom/Spring-Backend",
    "https://github.com/securedotcom/spring-fabric"
  ],
  "audit_types": ["comprehensive", "security", "quick"],
  "schedule": {
    "comprehensive": "weekly",
    "security": "daily",
    "quick": "on-commit"
  },
  "create_pr": true,
  "git_user": "devatsecure",
  "git_email": "devatsecure@users.noreply.github.com",
  "notification": {
    "enabled": true,
    "channels": ["slack", "email"],
    "slack_webhook": "${SLACK_WEBHOOK_URL}",
    "email_recipients": ["waseem@gaditek.com"]
  },
  "thresholds": {
    "critical_issues": 0,
    "high_priority_issues": 5,
    "test_coverage_minimum": 70
  },
  "auto_fix": {
    "enabled": false,
    "types": ["formatting", "linting", "security-patches"]
  }
}
```

### **Environment Variables**

Create `.env` file:

```bash
# API Keys
ANTHROPIC_API_KEY=your-api-key-here

# GitHub
GITHUB_TOKEN=your-github-token

# Notifications
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL

# Email
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@example.com
SMTP_PASSWORD=your-password
```

---

## 🔄 Integration with CI/CD

### **Jenkins Pipeline**

```groovy
pipeline {
    agent any
    
    triggers {
        cron('0 9 * * 1') // Weekly on Monday at 9 AM
    }
    
    stages {
        stage('Audit') {
            steps {
                sh 'agent-audit audit-all --type comprehensive'
            }
        }
        
        stage('Review') {
            steps {
                publishHTML([
                    reportDir: '/tmp/securedotcom-audits',
                    reportFiles: '**/audit-reports/**/*.md',
                    reportName: 'Audit Reports'
                ])
            }
        }
    }
}
```

### **GitLab CI**

```yaml
# .gitlab-ci.yml
audit:
  stage: test
  script:
    - agent-audit audit-all --type comprehensive
  artifacts:
    paths:
      - audit-reports/
    expire_in: 90 days
  only:
    - schedules
```

### **CircleCI**

```yaml
# .circleci/config.yml
version: 2.1

workflows:
  weekly-audit:
    triggers:
      - schedule:
          cron: "0 9 * * 1"
          filters:
            branches:
              only:
                - main
    jobs:
      - audit

jobs:
  audit:
    docker:
      - image: python:3.10
    steps:
      - checkout
      - run: pip install -r requirements.txt
      - run: agent-audit audit-all --type comprehensive
      - store_artifacts:
          path: /tmp/securedotcom-audits
```

---

## 📊 Monitoring and Reporting

### **Dashboard Integration**

Create a simple dashboard to track audit results:

```python
# scripts/audit-dashboard.py
import json
from pathlib import Path
from collections import defaultdict

def generate_dashboard():
    audit_dir = Path("/tmp/securedotcom-audits")
    
    results = defaultdict(dict)
    
    for repo_dir in audit_dir.iterdir():
        if repo_dir.is_dir():
            audit_file = repo_dir / "audit-reports" / "comprehensive-audit" / "executive-summary.md"
            if audit_file.exists():
                # Parse audit results
                with open(audit_file) as f:
                    content = f.read()
                    # Extract metrics
                    results[repo_dir.name] = {
                        "status": "✅" if "EXCELLENT" in content else "⚠️",
                        "grade": extract_grade(content),
                        "critical_issues": extract_critical_count(content)
                    }
    
    # Generate HTML dashboard
    html = generate_html_dashboard(results)
    
    with open("audit-dashboard.html", "w") as f:
        f.write(html)
    
    print("✅ Dashboard generated: audit-dashboard.html")

if __name__ == "__main__":
    generate_dashboard()
```

### **Slack Notifications**

```python
# scripts/notify-slack.py
import requests
import json

def send_slack_notification(webhook_url, audit_results):
    message = {
        "text": "🔍 Weekly Audit Complete",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🔍 Weekly Audit Results"
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Repositories Audited:* {len(audit_results)}"},
                    {"type": "mrkdwn", "text": f"*Critical Issues:* {sum(r['critical'] for r in audit_results)}"}
                ]
            }
        ]
    }
    
    requests.post(webhook_url, json=message)
```

---

## 🎯 Best Practices

### **1. Audit Frequency**

- **Comprehensive Audit:** Weekly (Monday morning)
- **Security Scan:** Daily (overnight)
- **Quick Audit:** On every PR

### **2. PR Management**

- Review audit PRs within 48 hours
- Create follow-up tasks for medium/low priority items
- Merge audit PRs to track historical trends

### **3. Threshold Management**

Set appropriate thresholds in `audit-config.json`:

```json
{
  "thresholds": {
    "critical_issues": 0,        // Block deployment
    "high_priority_issues": 5,   // Require review
    "test_coverage_minimum": 70  // Warn if below
  }
}
```

### **4. Team Workflow**

1. **Monday Morning:** Review weekly audit results
2. **Daily Standup:** Discuss critical/high priority issues
3. **Sprint Planning:** Allocate time for audit improvements
4. **Monthly Review:** Track audit trends and improvements

---

## 🔍 Audit Types

### **Comprehensive Audit**
- Full codebase analysis
- Security, performance, testing, code quality
- Recommended: Weekly

### **Security Scan**
- Focused on security vulnerabilities
- Quick execution (5-10 minutes)
- Recommended: Daily

### **Quick Audit**
- Basic code quality checks
- Fast execution (2-5 minutes)
- Recommended: On every PR

---

## 📝 Example Usage

### **Daily Routine**

```bash
# Morning: Check overnight security scans
agent-audit list

# Review any new PRs
gh pr list --label audit

# Run quick audit on current branch
agent-audit audit $(git remote get-url origin) --type quick
```

### **Weekly Routine**

```bash
# Monday morning: Run comprehensive audits
agent-audit audit-all --type comprehensive

# Review results
cd /tmp/securedotcom-audits
find . -name "executive-summary.md" -exec cat {} \;

# Generate dashboard
python scripts/audit-dashboard.py
open audit-dashboard.html
```

### **On-Demand**

```bash
# Before major release
agent-audit audit https://github.com/securedotcom/Spring-Backend --type comprehensive

# After security incident
agent-audit audit-all --type security

# Quick check before PR
agent-audit audit $(git remote get-url origin) --type quick
```

---

## 🚨 Troubleshooting

### **Issue: Git push fails**

```bash
# Ensure git credentials are configured
git config --global credential.helper store

# Or use SSH keys
git config --global url."git@github.com:".insteadOf "https://github.com/"
```

### **Issue: API rate limits**

```bash
# Use GitHub token with higher rate limits
export GITHUB_TOKEN=your-token-here

# Or add delays between audits
agent-audit audit-all --delay 60  # 60 seconds between repos
```

### **Issue: Large repositories timeout**

```bash
# Use quick audit for large repos
agent-audit audit https://github.com/securedotcom/large-repo --type quick

# Or increase timeout
export AUDIT_TIMEOUT=3600  # 1 hour
```

---

## 📚 Additional Resources

- **Agent OS Documentation:** `README.md`
- **Code Reviewer Guide:** `CODE_REVIEWER_PR.md`
- **Audit Commands:** `profiles/default/commands/audit-codebase/`
- **GitHub Actions:** `.github/workflows/automated-audit.yml`

---

## 🤝 Support

For issues or questions:
1. Check troubleshooting section above
2. Review Agent OS documentation
3. Contact: waseem@gaditek.com

---

**Last Updated:** October 22, 2024  
**Version:** 1.0.0



