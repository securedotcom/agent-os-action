# Manual Deployment Steps Guide

## Overview
This guide provides detailed step-by-step instructions for the manual deployment phases that require human action.

---

## Phase 2: Pilot Deployment to Spring-Backend

### Prerequisites
- GitHub organization admin access
- Access to Spring-Backend repository
- GitHub CLI installed (`gh`) or web access

### Step 1: Create Private Action Repository (15 minutes)

#### Option A: Using GitHub CLI
```bash
# Create private repository
gh repo create securedotcom/agent-os-action \
  --private \
  --description "Agent OS Code Reviewer - Automated code quality analysis" \
  --disable-issues \
  --disable-wiki

# Verify creation
gh repo view securedotcom/agent-os-action
```

#### Option B: Using GitHub Web UI
1. Go to: https://github.com/organizations/securedotcom/repositories/new
2. Repository name: `agent-os-action`
3. Description: "Agent OS Code Reviewer - Automated code quality analysis"
4. Visibility: **Private**
5. Uncheck: Initialize with README, .gitignore, license
6. Click "Create repository"

### Step 2: Push Codebase to Action Repository (10 minutes)

```bash
# Navigate to agent-os directory
cd /Users/waseem.ahmed/Repos/agent-os

# Add remote for action repository
git remote add action-repo https://github.com/securedotcom/agent-os-action.git

# Create and checkout deployment branch (optional, or use main)
git checkout -b v1.0-release

# Push to action repository
git push action-repo HEAD:main

# Tag the release
git tag -a v1.0.0 -m "Release v1.0.0: Initial Agent OS Code Reviewer"
git push action-repo v1.0.0

# Verify
gh repo view securedotcom/agent-os-action
```

### Step 3: Deploy Workflow to Spring-Backend (30 minutes)

```bash
# Clone Spring-Backend (or navigate if already cloned)
cd ~/Repos
git clone https://github.com/securedotcom/Spring-Backend.git
cd Spring-Backend

# Create workflow directory
mkdir -p .github/workflows

# Copy workflow file
cp /Users/waseem.ahmed/Repos/agent-os/deployment-files/workflows/spring-backend-workflow.yml \
   .github/workflows/agent-os-code-review.yml

# Review the workflow file
cat .github/workflows/agent-os-code-review.yml

# Create a feature branch
git checkout -b feature/add-code-review-automation

# Commit workflow
git add .github/workflows/agent-os-code-review.yml
git commit -m "Add Agent OS Code Reviewer workflow

- Automated security, performance, and quality analysis
- Runs on PR and weekly schedule
- Posts metrics to dashboard
- Sends Slack notifications
"

# Push to remote
git push origin feature/add-code-review-automation
```

### Step 4: Configure Repository Secrets (10 minutes)

#### Option A: Using GitHub CLI
```bash
cd ~/Repos/Spring-Backend

# Set SLACK_WEBHOOK_URL (get from Slack admin after Phase 3)
gh secret set SLACK_WEBHOOK_URL --body "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

# Set SLACK_ALERT_WEBHOOK_URL
gh secret set SLACK_ALERT_WEBHOOK_URL --body "https://hooks.slack.com/services/YOUR/ALERT/URL"

# Set METRICS_API_TOKEN (GitHub Personal Access Token)
# Create token at: https://github.com/settings/tokens
# Scopes needed: repo, workflow, write:packages
gh secret set METRICS_API_TOKEN --body "ghp_YOUR_TOKEN_HERE"

# Verify secrets
gh secret list
```

#### Option B: Using GitHub Web UI
1. Go to: https://github.com/securedotcom/Spring-Backend/settings/secrets/actions
2. Click "New repository secret"
3. Add each secret:
   - Name: `SLACK_WEBHOOK_URL`, Value: `https://hooks.slack.com/...` (placeholder for now)
   - Name: `SLACK_ALERT_WEBHOOK_URL`, Value: `https://hooks.slack.com/...` (placeholder for now)
   - Name: `METRICS_API_TOKEN`, Value: Your GitHub PAT

### Step 5: Create Pull Request and Merge (5 minutes)

```bash
cd ~/Repos/Spring-Backend

# Create PR using GitHub CLI
gh pr create \
  --title "Add Agent OS Code Reviewer automation" \
  --body "This PR adds automated code review capabilities to Spring-Backend.

**What's included:**
- Security vulnerability scanning
- Performance bottleneck detection  
- Test coverage analysis
- Code quality assessment

**Workflow triggers:**
- Pull requests to main/develop
- Push to main/develop
- Weekly comprehensive audit (Sundays 2 AM)
- Manual dispatch

**Next steps after merge:**
1. Test manual workflow dispatch
2. Monitor first automated audit
3. Review metrics in dashboard
4. Fine-tune standards based on results

See DEPLOYMENT_GUIDE.md for full documentation." \
  --base main

# Or create via web: https://github.com/securedotcom/Spring-Backend/compare
```

### Step 6: Test Manual Workflow Run (10 minutes)

After merging the PR:

```bash
# Trigger manual workflow
gh workflow run agent-os-code-review.yml \
  --repo securedotcom/Spring-Backend \
  --field review_type=audit

# Watch workflow execution
gh run watch

# Or view in web browser
open "https://github.com/securedotcom/Spring-Backend/actions"
```

Expected results:
- ✅ Workflow completes successfully
- ✅ Audit report generated in artifacts
- ✅ Step summary shows review results
- ✅ No critical errors in logs

### Step 7: Verify Audit Results (10 minutes)

```bash
# List recent workflow runs
gh run list --workflow=agent-os-code-review.yml --limit 5

# Download latest artifacts
gh run download --name code-review-reports-<run-number>

# Review audit report
cat audit-reports/audit-report.md
```

Check for:
- [ ] Report contains security findings
- [ ] Performance issues identified
- [ ] Test coverage analyzed
- [ ] Merge blockers clearly marked
- [ ] Suggestions provided

---

## Phase 6: CLI Batch Audit Setup

### Prerequisites
- Python 3.8 or higher
- Git configured with GitHub credentials
- Access to all 12 repositories

### Step 1: Install Python Dependencies (5 minutes)

```bash
cd /Users/waseem.ahmed/Repos/agent-os

# Install required packages
pip3 install gitpython requests

# Verify installation
python3 -c "import git, requests; print('Dependencies OK')"

# Make CLI executable
chmod +x scripts/audit-cli.py

# Test CLI
./scripts/audit-cli.py --help
```

### Step 2: Configure Git Credentials (10 minutes)

```bash
# Configure git user for automated commits
./scripts/audit-cli.py config \
  --git-user "devatsecure" \
  --git-email "devatsecure@users.noreply.github.com"

# Set up GitHub authentication
# Option A: Use credential helper
git config --global credential.helper store
echo "https://YOUR_GITHUB_TOKEN@github.com" | git credential approve

# Option B: Use SSH keys (recommended)
# Ensure SSH key is added to devatsecure GitHub account
ssh -T git@github.com

# Verify configuration
cat audit-config.json
```

### Step 3: List Configured Repositories (2 minutes)

```bash
# View all repositories configured for auditing
./scripts/audit-cli.py list

# Expected output:
# 📋 Repositories configured for audit:
# ============================================================
# 1. https://github.com/securedotcom/Spring-Backend
# 2. https://github.com/securedotcom/spring-fabric
# ... (12 total)
```

### Step 4: Test Single Repository Audit (15 minutes)

```bash
# Test with Spring-Backend first
./scripts/audit-cli.py audit \
  https://github.com/securedotcom/Spring-Backend \
  --type quick

# Monitor progress
# Expected steps:
# 📥 Cloning Spring-Backend...
# 🤖 Running quick audit...
# 📊 Analyzing codebase...
# 🔒 Security analysis...
# ✅ Audit complete: Spring-Backend

# Verify audit reports
ls -la /tmp/securedotcom-audits/Spring-Backend/audit-reports/

# Review audit findings
cat /tmp/securedotcom-audits/Spring-Backend/audit-reports/quick/audit-summary.md
```

### Step 5: Run Batch Audit on All Repositories (1-2 hours)

```bash
# Run comprehensive audit on all 12 repositories
./scripts/audit-cli.py audit-all --type comprehensive

# This will:
# 1. Clone/update each repository
# 2. Run comprehensive analysis
# 3. Generate audit reports
# 4. Create feature branch
# 5. Commit findings
# 6. Push to remote
# 7. Create PR (if configured)

# Monitor progress (will take 60-120 minutes)
tail -f /tmp/agent-os-audit.log
```

Expected output:
```
🚀 Starting batch audit...
📊 Repositories to audit: 12
🔍 Audit type: comprehensive
============================================================

🔍 Auditing: https://github.com/securedotcom/Spring-Backend
============================================================
📥 Updating Spring-Backend...
🤖 Running comprehensive audit...
✅ Audit complete: Spring-Backend

... (repeat for all 12 repos)

============================================================
📊 Audit Summary
============================================================
✅ Successful: 11
❌ Failed: 1
📊 Total: 12

❌ Failed audits:
   - https://github.com/securedotcom/repository-with-issue
```

### Step 6: Set Up Automated Schedules (5 minutes)

```bash
# Open crontab editor
crontab -e

# Add these lines:
# Weekly comprehensive audit (Sundays at 2 AM)
0 2 * * 0 cd /Users/waseem.ahmed/Repos/agent-os && ./scripts/audit-cli.py audit-all --type comprehensive >> /tmp/agent-os-audit.log 2>&1

# Daily security scan (6 AM)
0 6 * * * cd /Users/waseem.ahmed/Repos/agent-os && ./scripts/audit-cli.py audit-all --type security >> /tmp/agent-os-security.log 2>&1

# Save and exit

# Verify cron jobs
crontab -l

# Test cron email notifications (optional)
echo "Test audit complete" | mail -s "Agent OS Test" waseem@gaditek.com
```

---

## Phase 7: Full Rollout to Remaining Repositories

### Prerequisites
- Phase 2 completed successfully
- Spring-Backend pilot validated
- Metrics dashboard operational
- Slack notifications configured

### Step 1: Validate Pilot Success (15 minutes)

```bash
# Review Spring-Backend metrics
cd ~/Repos/Spring-Backend

# Check recent workflow runs
gh run list --workflow=agent-os-code-review.yml --limit 10

# Calculate success rate
# Should be >90% successful runs

# Review dashboard
open "https://securedotcom.github.io/agent-os-metrics/"

# Verify:
# [ ] At least 5 successful audits
# [ ] Dashboard showing metrics
# [ ] Slack notifications working
# [ ] No false-positive blockers
# [ ] Team satisfied with results
```

### Step 2: Prepare Rollout Script (10 minutes)

Create a script to automate workflow deployment:

```bash
cat > /tmp/deploy-agent-os.sh << 'EOF'
#!/bin/bash
set -e

REPO=$1

if [ -z "$REPO" ]; then
  echo "Usage: $0 <repository-name>"
  exit 1
fi

echo "Deploying Agent OS to $REPO..."

# Clone repository
cd ~/Repos
if [ ! -d "$REPO" ]; then
  gh repo clone "securedotcom/$REPO"
fi

cd "$REPO"
git checkout main
git pull

# Create workflow directory
mkdir -p .github/workflows

# Copy workflow
cp /Users/waseem.ahmed/Repos/agent-os/deployment-files/workflows/spring-backend-workflow.yml \
   .github/workflows/agent-os-code-review.yml

# Customize project type if needed
# (Manual step - review and adjust)

# Create branch
git checkout -b feature/add-agent-os-review

# Commit
git add .github/workflows/agent-os-code-review.yml
git commit -m "Add Agent OS Code Reviewer automation"

# Push
git push origin feature/add-agent-os-review

# Create PR
gh pr create \
  --title "Add Agent OS Code Reviewer" \
  --body "Adds automated code review. See Spring-Backend for pilot results." \
  --base main

echo "✅ Deployed to $REPO"
EOF

chmod +x /tmp/deploy-agent-os.sh
```

### Step 3: Deploy to Remaining Repositories (2-3 hours)

Deploy to each repository one at a time:

```bash
# Deploy to each repository
/tmp/deploy-agent-os.sh spring-fabric
/tmp/deploy-agent-os.sh spring-topography-apis
/tmp/deploy-agent-os.sh platform-dashboard-apis
/tmp/deploy-agent-os.sh siem-agent-provisioning
/tmp/deploy-agent-os.sh case_management_pipeline
/tmp/deploy-agent-os.sh case-management-backend
/tmp/deploy-agent-os.sh Risk-Register
/tmp/deploy-agent-os.sh Spring-dashboard
/tmp/deploy-agent-os.sh Spring_CIA_algorithm
/tmp/deploy-agent-os.sh spring-attack-surface
/tmp/deploy-agent-os.sh secure_data_retrieval_agent

# For each repository:
# 1. Review and merge PR
# 2. Configure secrets (if not inherited from org)
# 3. Trigger manual test run
# 4. Monitor first automated audit
```

### Step 4: Configure Secrets (if needed) (30 minutes)

If secrets are not configured at organization level:

```bash
# For each repository
for repo in spring-fabric spring-topography-apis platform-dashboard-apis siem-agent-provisioning case_management_pipeline case-management-backend Risk-Register Spring-dashboard Spring_CIA_algorithm spring-attack-surface secure_data_retrieval_agent; do
  echo "Configuring secrets for $repo..."
  
  gh secret set SLACK_WEBHOOK_URL --repo "securedotcom/$repo" --body "$SLACK_WEBHOOK_URL"
  gh secret set SLACK_ALERT_WEBHOOK_URL --repo "securedotcom/$repo" --body "$SLACK_ALERT_WEBHOOK_URL"
  gh secret set METRICS_API_TOKEN --repo "securedotcom/$repo" --body "$METRICS_API_TOKEN"
  
  echo "✅ $repo configured"
done
```

### Step 5: Monitor Initial Runs (1 hour)

```bash
# Monitor all repositories
for repo in Spring-Backend spring-fabric spring-topography-apis platform-dashboard-apis siem-agent-provisioning case_management_pipeline case-management-backend Risk-Register Spring-dashboard Spring_CIA_algorithm spring-attack-surface secure_data_retrieval_agent; do
  echo "=== $repo ==="
  gh run list --repo "securedotcom/$repo" --workflow=agent-os-code-review.yml --limit 3
  echo ""
done

# Check dashboard for all repositories
open "https://securedotcom.github.io/agent-os-metrics/"
```

### Step 6: Team Training & Documentation (1 hour)

Schedule a team meeting to cover:

1. **How the system works** (15 min)
   - Workflow triggers
   - Review types
   - Severity classification

2. **Reading audit reports** (15 min)
   - Understanding blockers
   - Addressing suggestions
   - Interpreting metrics

3. **Using the dashboard** (15 min)
   - Repository health
   - Trend analysis
   - Filtering and searching

4. **Slack notifications** (10 min)
   - Channel organization
   - Alert severity
   - Taking action on alerts

5. **Q&A** (5 min)

---

## Verification Checklist

### After Phase 2 (Pilot)
- [ ] Spring-Backend workflow running successfully
- [ ] Audit reports generated
- [ ] Metrics posting to dashboard
- [ ] No false-positive blockers
- [ ] Team can access and understand reports

### After Phase 6 (CLI Batch Audit)
- [ ] All 12 repositories audited
- [ ] Audit reports in each repository
- [ ] PRs created with findings
- [ ] Cron jobs scheduled
- [ ] Email notifications working

### After Phase 7 (Full Rollout)
- [ ] All 12 repositories have workflow enabled
- [ ] All workflows running successfully
- [ ] Dashboard shows all repositories
- [ ] Slack notifications working
- [ ] Team trained
- [ ] Feedback collected
- [ ] Standards adjusted based on feedback

---

## Troubleshooting

### Issue: Workflow fails with "Action not found"
**Solution:** Verify action reference
```yaml
uses: securedotcom/agent-os-action@v1  # Correct
```

### Issue: Secrets not found
**Solution:** Check secret configuration
```bash
gh secret list --repo securedotcom/REPO_NAME
```

### Issue: CLI fails to clone repository
**Solution:** Check Git authentication
```bash
gh auth status
git config --list | grep credential
```

### Issue: Dashboard not showing data
**Solution:** Verify metrics are being posted
```bash
curl https://raw.githubusercontent.com/securedotcom/agent-os-metrics/main/data/latest-metrics.json
```

---

## Support

For issues during deployment:
- **Primary Contact:** Waseem Ahmed (waseem@gaditek.com)
- **Documentation:** DEPLOYMENT_GUIDE.md
- **Implementation Summary:** IMPLEMENTATION_SUMMARY.md
- **GitHub Issues:** https://github.com/securedotcom/agent-os-action/issues

---

**Last Updated:** January 24, 2025  
**Version:** 1.0.0

