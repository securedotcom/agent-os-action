# Agent OS Code Reviewer - Deployment Guide

## Overview

This guide provides step-by-step instructions for deploying the Agent OS Code Reviewer system as a private GitHub Action within the securedotcom organization.

## Prerequisites

- GitHub organization admin access (securedotcom)
- Repository access to Spring-Backend (pilot repository)
- Python 3.8+ for CLI tool
- Git configured with appropriate credentials

---

## Phase 1: GitHub Action Setup (Private Organization)

### Step 1.1: Create Private Repository

1. Go to GitHub: https://github.com/organizations/securedotcom/repositories/new
2. Repository name: `agent-os-action`
3. Description: "Agent OS Code Reviewer - Automated security, performance, and quality analysis"
4. Set to **Private**
5. Do not initialize with README (we'll push from existing codebase)

### Step 1.2: Prepare Repository for Push

From your local `agent-os` directory:

```bash
# Add the new remote
git remote add action-repo https://github.com/securedotcom/agent-os-action.git

# Create a new branch for the action repository
git checkout -b action-v1

# Push to the new repository
git push action-repo action-v1:main
```

### Step 1.3: Verify Repository Structure

The repository should contain:
- ✅ `action.yml` - GitHub Action definition
- ✅ `profiles/` - All agents, workflows, standards
- ✅ `scripts/` - CLI tools and installation scripts
- ✅ `README.md` - Documentation
- ✅ `audit-config.json` - Configuration

### Step 1.4: Create Release Tag

```bash
# Tag the release
git tag -a v1.0.0 -m "Initial release: Agent OS Code Reviewer v1.0.0"

# Push the tag
git push action-repo v1.0.0
```

---

## Phase 2: Pilot Deployment (Spring-Backend)

### Step 2.1: Create Workflow File

Navigate to the Spring-Backend repository and create:

File: `.github/workflows/agent-os-code-review.yml`

Use the template from: `deployment-files/spring-backend-workflow.yml` (created in this repo)

### Step 2.2: Configure Repository Secrets

In Spring-Backend repository settings:

1. Go to Settings → Secrets and variables → Actions
2. Add secrets:
   - `GITHUB_TOKEN` (automatically available, verify permissions)
   - `SLACK_WEBHOOK_URL` (placeholder for Phase 3)
   - `METRICS_API_TOKEN` (generate random token for Phase 4)

### Step 2.3: Test Pilot Run

```bash
# In Spring-Backend repository
git checkout -b test/code-review-pilot
git add .github/workflows/agent-os-code-review.yml
git commit -m "Add Agent OS Code Reviewer workflow"
git push origin test/code-review-pilot

# Go to Actions tab and manually trigger workflow
# Select "Run workflow" → Choose "audit" type
```

Expected results:
- ✅ Workflow completes successfully
- ✅ Audit report generated in artifacts
- ✅ No false-positive blockers

---

## Phase 3: Slack Notifications Setup

### Step 3.1: Request Slack Admin Approval

**Email Template** (save as `deployment-files/slack-approval-request.md`):

```
Subject: Request: Slack App Integration for Code Review Automation

Hi [Slack Admin Name],

I'm requesting approval to create a Slack app for automated code quality notifications.

Purpose: Automated code review system that posts security, performance, and quality findings

Permissions Needed:
- Incoming Webhooks (to post messages)
- Channels: #code-reviews, #security-alerts

Security:
- Webhook URLs stored as GitHub secrets
- No data collection or external services
- Read-only notifications (no bot commands)

Benefits:
- Proactive security issue detection
- Automated quality monitoring
- Team awareness of code health

Example notification format attached in slack-notification-example.png

Estimated setup time: 15 minutes
Approval needed by: [Date]

Thank you!
```

Send to: [Your Slack Admin Email]

### Step 3.2: Create Slack App (Once Approved)

1. Go to: https://api.slack.com/apps
2. Click "Create New App" → "From scratch"
3. App name: "Agent OS Code Reviewer"
4. Workspace: [Your Workspace]
5. Enable Features:
   - Incoming Webhooks → Turn On
   - Add webhook for #code-reviews
   - Add webhook for #security-alerts
6. Copy webhook URLs

### Step 3.3: Add Webhook URLs to GitHub

In Spring-Backend (and later all repos):
```bash
# Settings → Secrets → Update
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
SLACK_ALERT_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/ALERT/URL
```

### Step 3.4: Test Notifications

Run a manual audit on Spring-Backend and verify:
- ✅ Message posted to #code-reviews
- ✅ If critical issues found, alert posted to #security-alerts
- ✅ Message formatting is clear and actionable

---

## Phase 4: Metrics Dashboard (GitHub Pages)

### Step 4.1: Create Metrics Repository

```bash
# Create new repository: securedotcom/agent-os-metrics
# Settings:
# - Private repository
# - Initialize with README
# - Enable GitHub Pages: Settings → Pages → Source: docs/

git clone https://github.com/securedotcom/agent-os-metrics.git
cd agent-os-metrics

# Create directory structure
mkdir -p data/2025 docs scripts
```

### Step 4.2: Copy Dashboard Files

From agent-os repository:
```bash
# Copy dashboard files created in deployment-files/
cp deployment-files/dashboard/index.html docs/
cp deployment-files/dashboard/styles.css docs/
cp deployment-files/dashboard/app.js docs/
cp deployment-files/metrics/post-metrics.sh scripts/
cp deployment-files/metrics/aggregate-metrics.sh scripts/

# Make scripts executable
chmod +x scripts/*.sh
```

### Step 4.3: Configure GitHub Pages

1. Go to repository Settings → Pages
2. Source: Deploy from a branch
3. Branch: main
4. Folder: /docs
5. Save

Dashboard will be available at:
`https://securedotcom.github.io/agent-os-metrics/`

### Step 4.4: Integrate with Workflows

Update Spring-Backend workflow to post metrics after each run.
The workflow already includes this step if using the provided template.

---

## Phase 5: Custom Standards per Project Type

### Step 5.1: Review Project Type Standards

Standards are organized in:
```
profiles/default/standards/
├── backend-api/
├── dashboard-ui/
├── data-pipeline/
└── infrastructure/
```

### Step 5.2: Project Type Detection

The system auto-detects project types using `scripts/detect-project-type.sh`

Manual override available in workflow:
```yaml
with:
  project-type: 'backend-api'  # Optional override
```

### Step 5.3: Test Detection

Run detection script locally:
```bash
cd /path/to/Spring-Backend
/path/to/agent-os/scripts/detect-project-type.sh
# Expected output: backend-api
```

---

## Phase 6: CLI Tool Setup for Batch Audits

### Step 6.1: Install Dependencies

```bash
cd /path/to/agent-os

# Install Python dependencies
pip3 install gitpython requests

# Make CLI executable
chmod +x scripts/audit-cli.py

# Test CLI
./scripts/audit-cli.py --help
```

### Step 6.2: Configure CLI

```bash
# Set Git user for automated commits
./scripts/audit-cli.py config \
  --git-user "devatsecure" \
  --git-email "devatsecure@users.noreply.github.com"

# Verify configuration
cat audit-config.json
```

### Step 6.3: Test Single Repository Audit

```bash
# Test with one repository first
./scripts/audit-cli.py audit https://github.com/securedotcom/Spring-Backend --type quick

# Check results
# - Repository cloned to /tmp/securedotcom-audits/Spring-Backend
# - Audit reports generated
# - PR created with findings
```

### Step 6.4: Run Batch Audit

```bash
# Audit all 12 repositories
./scripts/audit-cli.py audit-all --type comprehensive

# Monitor progress
# This will take 30-60 minutes depending on repository sizes
```

### Step 6.5: Schedule Automated Runs

```bash
# Edit crontab
crontab -e

# Add these lines:
# Weekly comprehensive audit (Sundays at 2 AM)
0 2 * * 0 cd /Users/waseem.ahmed/Repos/agent-os && ./scripts/audit-cli.py audit-all --type comprehensive >> /tmp/agent-os-audit.log 2>&1

# Daily security scan (6 AM)
0 6 * * * cd /Users/waseem.ahmed/Repos/agent-os && ./scripts/audit-cli.py audit-all --type security >> /tmp/agent-os-security.log 2>&1
```

---

## Phase 7: Full Rollout

### Step 7.1: Add Workflow to Remaining Repositories

For each of the 11 remaining repositories:

1. Clone repository
2. Copy `.github/workflows/agent-os-code-review.yml` from Spring-Backend
3. Adjust project-specific settings if needed
4. Create PR with the workflow
5. Merge after review

Repositories to enable:
- [ ] spring-fabric
- [ ] spring-topography-apis
- [ ] platform-dashboard-apis
- [ ] siem-agent-provisioning
- [ ] case_management_pipeline
- [ ] case-management-backend
- [ ] Risk-Register
- [ ] Spring-dashboard
- [ ] Spring_CIA_algorithm
- [ ] spring-attack-surface
- [ ] secure_data_retrieval_agent

### Step 7.2: Verify All Workflows

```bash
# Use CLI to check workflow status
./scripts/audit-cli.py list

# Verify dashboard shows all repositories
# Visit: https://securedotcom.github.io/agent-os-metrics/
```

---

## Troubleshooting

### Issue: Action fails to install Agent OS

**Solution**: Check network connectivity and GitHub API rate limits
```bash
# Test installation manually
curl -sSL https://raw.githubusercontent.com/buildermethods/agent-os/main/setup/base.sh | bash -s -- --claude-code --cursor
```

### Issue: No PR comments posted

**Solution**: Verify GITHUB_TOKEN has correct permissions
- Go to repo Settings → Actions → General
- Set "Workflow permissions" to "Read and write permissions"

### Issue: Metrics not appearing in dashboard

**Solution**: Check metrics posting script
```bash
# Manually post test metric
cd agent-os-metrics
./scripts/post-metrics.sh Spring-Backend audit 2 5 pass abc123
```

### Issue: Slack notifications not working

**Solution**: Test webhook manually
```bash
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"Test notification from Agent OS"}' \
  YOUR_WEBHOOK_URL
```

---

## Monitoring & Maintenance

### Daily Checks
- [ ] Review Slack #code-reviews channel for new findings
- [ ] Check dashboard for any failing repositories
- [ ] Review critical security alerts

### Weekly Tasks
- [ ] Review batch audit results
- [ ] Update standards based on team feedback
- [ ] Check workflow success rate (target: >95%)

### Monthly Tasks
- [ ] Review and archive old audit reports
- [ ] Update Agent OS action to latest version
- [ ] Analyze trends and share insights with team

---

## Support & Contacts

**Primary Contact**: Waseem Ahmed (waseem@gaditek.com)
**Slack Admin**: [Name/Email]
**GitHub Organization Admin**: [Name/Email]

**Resources**:
- Agent OS Documentation: `/Users/waseem.ahmed/Repos/agent-os/README.md`
- GitHub Action Guide: `/Users/waseem.ahmed/Repos/agent-os/GITHUB_ACTION_GUIDE.md`
- Metrics Dashboard: https://securedotcom.github.io/agent-os-metrics/

---

## Success Metrics

After full deployment, track:
- Total audits completed: Target 50+ per week
- Critical issues found: Track trend (should decrease over time)
- Mean time to fix: Target <48 hours for blockers
- False positive rate: Target <5%
- Workflow adoption: 12/12 repositories active

**Deployment Status**: Ready for Phase 1 implementation

