# Deployment Files for Agent OS Code Reviewer

## Overview
This directory contains all files needed to deploy the Agent OS Code Reviewer system.

---

## Directory Structure

```
deployment-files/
├── workflows/
│   └── spring-backend-workflow.yml    # GitHub Actions workflow template
├── dashboard/
│   ├── index.html                     # Dashboard UI
│   ├── styles.css                     # Dashboard styling
│   └── app.js                         # Dashboard logic
├── metrics/
│   └── post-metrics.sh                # Metrics posting script
├── slack/
│   └── slack-approval-request.md      # Slack admin approval template
└── README.md                          # This file
```

---

## Quick Start

### 1. Deploy GitHub Action (Phase 1)

```bash
# From agent-os repository root
cd /Users/waseem.ahmed/Repos/agent-os

# Create private repository on GitHub: securedotcom/agent-os-action
# Then push this codebase:
git remote add action-repo https://github.com/securedotcom/agent-os-action.git
git push action-repo main

# Tag release
git tag -a v1.0.0 -m "Initial release"
git push action-repo v1.0.0
```

### 2. Deploy to Spring-Backend (Phase 2)

```bash
# Copy workflow file to Spring-Backend repository
cp deployment-files/workflows/spring-backend-workflow.yml \
   /path/to/Spring-Backend/.github/workflows/agent-os-code-review.yml

# Commit and push
cd /path/to/Spring-Backend
git add .github/workflows/agent-os-code-review.yml
git commit -m "Add Agent OS Code Reviewer workflow"
git push origin main
```

### 3. Request Slack Approval (Phase 3)

```bash
# Send the approval request
cat deployment-files/slack/slack-approval-request.md | \
  mail -s "Slack Integration Request" slack-admin@yourcompany.com
```

### 4. Deploy Dashboard (Phase 4)

```bash
# Create metrics repository
git clone https://github.com/securedotcom/agent-os-metrics.git
cd agent-os-metrics

# Copy dashboard files
mkdir -p docs
cp /Users/waseem.ahmed/Repos/agent-os/deployment-files/dashboard/* docs/

# Create data directory
mkdir -p data/2025

# Commit and push
git add .
git commit -m "Initial dashboard setup"
git push origin main

# Enable GitHub Pages in repository settings
# Settings → Pages → Source: docs/
```

### 5. Run CLI Batch Audit (Phase 6)

```bash
# Make CLI executable
chmod +x /Users/waseem.ahmed/Repos/agent-os/scripts/audit-cli.py

# Configure CLI
./scripts/audit-cli.py config \
  --git-user "devatsecure" \
  --git-email "devatsecure@users.noreply.github.com"

# Run batch audit
./scripts/audit-cli.py audit-all --type comprehensive
```

---

## File Usage

### Workflow Template
**File:** `workflows/spring-backend-workflow.yml`
**Usage:** Copy to `.github/workflows/` in target repository
**Customization:**
- Update `project-type` if not backend-api
- Adjust schedule/triggers as needed
- Configure secrets: `SLACK_WEBHOOK_URL`, `METRICS_API_TOKEN`

### Dashboard Files
**Files:** `dashboard/index.html`, `styles.css`, `app.js`
**Usage:** Deploy to GitHub Pages via agent-os-metrics repository
**Customization:**
- Update `dataUrl` in app.js for production
- Adjust colors/branding in styles.css
- Modify dashboard cards in index.html

### Metrics Script
**File:** `metrics/post-metrics.sh`
**Usage:** Called by GitHub Actions to post metrics
**Requirements:**
- `METRICS_API_TOKEN` environment variable
- `jq` command-line tool installed

### Slack Approval
**File:** `slack/slack-approval-request.md`
**Usage:** Email template for Slack admin
**Customization:**
- Update dates and contact information
- Add specific channel names
- Include organization-specific requirements

---

## Environment Variables

### Required Secrets (GitHub Actions)
```bash
GITHUB_TOKEN          # Automatically provided by GitHub
SLACK_WEBHOOK_URL     # From Slack app (Phase 3)
SLACK_ALERT_WEBHOOK_URL  # For critical alerts
METRICS_API_TOKEN     # GitHub personal access token
```

### Setup Secrets
```bash
# In repository settings: Settings → Secrets → Actions
gh secret set SLACK_WEBHOOK_URL --body "https://hooks.slack.com/..."
gh secret set METRICS_API_TOKEN --body "ghp_..."
```

---

## Project Type Standards

Custom standards are automatically applied based on project type:

- **backend-api**: Spring Boot, REST APIs, microservices
- **dashboard-ui**: React, Vue, Angular frontends
- **data-pipeline**: Airflow, ETL, data processing
- **infrastructure**: Terraform, Kubernetes, IaC

Standards location: `profiles/default/standards/{project-type}/`

---

## Testing Deployment

### Test Workflow Locally
```bash
# Test project type detection
cd /path/to/Spring-Backend
/Users/waseem.ahmed/Repos/agent-os/scripts/detect-project-type.sh
# Expected output: backend-api
```

### Test Dashboard Locally
```bash
# Serve dashboard locally
cd deployment-files/dashboard
python3 -m http.server 8000
# Visit: http://localhost:8000
```

### Test Slack Notification
```bash
# Test notification script
export SLACK_WEBHOOK_URL="https://hooks.slack.com/..."
export REPOSITORY="securedotcom/Spring-Backend"
export BRANCH="main"
export REVIEW_TYPE="audit"
export WORKFLOW_URL="https://github.com/..."
export REPORT_PATH=".agent-os/reviews/audit-report.md"

/Users/waseem.ahmed/Repos/agent-os/scripts/notify-slack.sh audit
```

---

## Rollout Checklist

### Phase 1: GitHub Action Setup
- [ ] Create `securedotcom/agent-os-action` repository
- [ ] Push codebase to action repository
- [ ] Tag v1.0.0 release
- [ ] Verify repository structure

### Phase 2: Pilot Deployment
- [ ] Copy workflow to Spring-Backend
- [ ] Configure repository secrets
- [ ] Run manual workflow test
- [ ] Verify audit reports generated
- [ ] Confirm PR comments working

### Phase 3: Slack Notifications
- [ ] Send approval request to Slack admin
- [ ] Create Slack app (after approval)
- [ ] Configure webhooks
- [ ] Test notifications
- [ ] Add webhook URLs to secrets

### Phase 4: Metrics Dashboard
- [ ] Create agent-os-metrics repository
- [ ] Deploy dashboard files
- [ ] Enable GitHub Pages
- [ ] Configure metrics posting
- [ ] Verify dashboard displays data

### Phase 5: Custom Standards
- [ ] Test project type detection
- [ ] Verify standards loading
- [ ] Run audit with custom standards
- [ ] Review standards output
- [ ] Adjust standards based on feedback

### Phase 6: CLI Batch Audit
- [ ] Install Python dependencies
- [ ] Configure CLI tool
- [ ] Test single repository audit
- [ ] Run batch audit on all repos
- [ ] Schedule automated runs

### Phase 7: Full Rollout
- [ ] Deploy to remaining 11 repositories
- [ ] Monitor all workflows
- [ ] Track metrics dashboard
- [ ] Review Slack notifications
- [ ] Gather team feedback

---

## Troubleshooting

### Issue: Workflow fails to find action
**Solution:** Verify action reference is correct
```yaml
uses: securedotcom/agent-os-action@v1  # Correct
# Not: uses: agent-os-action@v1  # Wrong
```

### Issue: Project type not detected correctly
**Solution:** Add manual override
```yaml
with:
  project-type: 'backend-api'  # Override auto-detection
```

### Issue: Metrics not posting
**Solution:** Check token permissions
```bash
# Token needs: repo, workflow, write:packages
gh auth refresh -s repo,workflow,write:packages
```

### Issue: Dashboard shows no data
**Solution:** Check data file exists
```bash
# Verify metrics file
curl https://raw.githubusercontent.com/securedotcom/agent-os-metrics/main/data/latest-metrics.json
```

---

## Support

For issues or questions:
- **Primary Contact**: Waseem Ahmed (waseem@gaditek.com)
- **Documentation**: `/Users/waseem.ahmed/Repos/agent-os/DEPLOYMENT_GUIDE.md`
- **Action Logs**: GitHub Actions workflow logs
- **Dashboard**: https://securedotcom.github.io/agent-os-metrics/

---

## Version History

- **v1.0.0** (2025-01-24): Initial deployment files
  - GitHub Actions workflow
  - Dashboard UI
  - Metrics posting
  - Slack notifications
  - Custom standards for 4 project types
  - CLI batch audit tool

