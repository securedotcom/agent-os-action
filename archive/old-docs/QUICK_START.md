# Agent OS Code Reviewer - Quick Start Guide

## 🚀 5-Minute Setup

### Step 1: Create Action Repository
```bash
gh repo create securedotcom/agent-os-action --private
cd /Users/waseem.ahmed/Repos/agent-os
git push https://github.com/securedotcom/agent-os-action.git main
git tag v1.0.0 && git push --tags
```

### Step 2: Deploy to Spring-Backend
```bash
cd ~/Repos/Spring-Backend
mkdir -p .github/workflows
cp /Users/waseem.ahmed/Repos/agent-os/deployment-files/workflows/spring-backend-workflow.yml \
   .github/workflows/agent-os-code-review.yml
git add . && git commit -m "Add code review automation"
git push
```

### Step 3: Configure Secrets
```bash
gh secret set SLACK_WEBHOOK_URL --body "https://hooks.slack.com/..."
gh secret set METRICS_API_TOKEN --body "ghp_..."
```

### Step 4: Run Test
```bash
gh workflow run agent-os-code-review.yml --field review_type=audit
gh run watch
```

---

## 📊 Dashboard Setup

```bash
gh repo create securedotcom/agent-os-metrics --private
cd /tmp && git clone https://github.com/securedotcom/agent-os-metrics.git
cd agent-os-metrics
mkdir docs && cp /Users/waseem.ahmed/Repos/agent-os/deployment-files/dashboard/* docs/
git add . && git commit -m "Add dashboard" && git push
```

Enable GitHub Pages: Settings → Pages → Source: `docs/`

Dashboard URL: `https://securedotcom.github.io/agent-os-metrics/`

---

## 🤖 CLI Batch Audit

```bash
cd /Users/waseem.ahmed/Repos/agent-os
pip3 install gitpython requests
chmod +x scripts/audit-cli.py
./scripts/audit-cli.py config --git-user "devatsecure" --git-email "bot@example.com"
./scripts/audit-cli.py audit-all --type comprehensive
```

---

## 📝 Key Files

| File | Purpose |
|------|---------|
| `DEPLOYMENT_GUIDE.md` | Complete step-by-step guide (480 lines) |
| `IMPLEMENTATION_SUMMARY.md` | What was built (overview) |
| `deployment-files/MANUAL_STEPS_GUIDE.md` | Detailed manual steps |
| `deployment-files/README.md` | Deployment files reference |
| `QUICK_START.md` | This file (quick commands) |

---

## 🎯 Project Type Standards

Auto-detected based on codebase:
- **backend-api**: Spring Boot, Java, APIs (Spring-Backend, platform-dashboard-apis, etc.)
- **dashboard-ui**: React, Vue, Angular (Spring-dashboard, Risk-Register)
- **data-pipeline**: Airflow, ETL, data processing (case_management_pipeline, secure_data_retrieval_agent)
- **infrastructure**: Terraform, K8s, IaC (spring-fabric, siem-agent-provisioning, spring-topography-apis)

Override: Add `project-type: 'backend-api'` to workflow

---

## 🔔 Slack Notifications

1. Request approval: Send `deployment-files/slack/slack-approval-request.md` to Slack admin
2. Create app: https://api.slack.com/apps → "Create New App"
3. Enable webhooks: Features → Incoming Webhooks → On
4. Add to channels: #code-reviews, #security-alerts
5. Copy webhook URLs to GitHub secrets

---

## ⚡ Commands Reference

```bash
# Test project type detection
/Users/waseem.ahmed/Repos/agent-os/scripts/detect-project-type.sh .

# Send test Slack notification
export SLACK_WEBHOOK_URL="..." REPOSITORY="..." BRANCH="main"
/Users/waseem.ahmed/Repos/agent-os/scripts/notify-slack.sh audit

# List configured repositories
/Users/waseem.ahmed/Repos/agent-os/scripts/audit-cli.py list

# Audit single repository
./scripts/audit-cli.py audit https://github.com/securedotcom/Spring-Backend --type quick

# Batch audit all repositories
./scripts/audit-cli.py audit-all --type comprehensive

# View workflow runs
gh run list --workflow=agent-os-code-review.yml --limit 10

# Download audit reports
gh run download --name code-review-reports-123

# Trigger manual workflow
gh workflow run agent-os-code-review.yml --field review_type=security
```

---

## 📊 What Gets Reviewed

### Security
- Hardcoded secrets
- SQL/NoSQL injection
- Authentication/authorization gaps
- Insecure dependencies
- Missing encryption

### Performance
- N+1 query patterns
- Memory leaks
- Resource management issues
- Missing indexes
- Inefficient algorithms

### Testing
- Coverage gaps
- Missing critical tests
- No regression tests
- Integration test gaps

### Code Quality
- Maintainability issues
- Documentation gaps
- Style violations
- Error handling problems

---

## 🎓 Review Severity

- **[BLOCKER]** - Must fix before merge (workflow fails)
- **[SUGGESTION]** - Good to have improvements
- **[NIT]** - Minor style/preference issues

---

## 📈 Success Metrics

**Week 1:** 5+ audits, zero false positives, dashboard working  
**Week 4:** All 12 repos enabled, 50+ audits, <5% false positive rate  
**Month 3:** 200+ audits/month, declining issues trend, <48h fix time

---

## 🆘 Quick Troubleshooting

| Problem | Solution |
|---------|----------|
| Action not found | Check `uses: securedotcom/agent-os-action@v1` |
| Secrets missing | `gh secret list --repo securedotcom/REPO` |
| Workflow fails | Check Actions tab logs |
| Dashboard empty | Verify metrics posting in workflow |
| CLI can't clone | Check `gh auth status` |

---

## 📞 Support

**Contact:** Waseem Ahmed (waseem@gaditek.com)  
**Docs:** `/Users/waseem.ahmed/Repos/agent-os/DEPLOYMENT_GUIDE.md`  
**Dashboard:** `https://securedotcom.github.io/agent-os-metrics/`  
**Issues:** `https://github.com/securedotcom/agent-os-action/issues`

---

## ✅ Deployment Phases

1. **Phase 1: GitHub Action Setup** ✅ Complete - All files ready
2. **Phase 2: Pilot Deployment** ⏳ Ready - Instructions in MANUAL_STEPS_GUIDE.md
3. **Phase 3: Slack Notifications** ✅ Complete - Templates and scripts ready
4. **Phase 4: Metrics Dashboard** ✅ Complete - Dashboard files ready
5. **Phase 5: Custom Standards** ✅ Complete - 16 standard files created
6. **Phase 6: CLI Batch Audit** ⏳ Ready - Instructions in MANUAL_STEPS_GUIDE.md
7. **Phase 7: Full Rollout** ⏳ Ready - Instructions in MANUAL_STEPS_GUIDE.md

---

**Version:** 1.0.0  
**Status:** Ready for Deployment  
**Date:** January 24, 2025

