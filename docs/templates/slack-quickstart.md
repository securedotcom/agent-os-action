# Slack Integration - Quick Start

## 3-Step Setup (No Webhooks!)

### Step 1: Install GitHub App in Slack (1 minute)
1. In Slack, go to: Apps → Browse Apps
2. Search for "GitHub"
3. Click "Add to Slack"
4. Authorize the app

### Step 2: Sign In (30 seconds)
In any Slack channel, type:
```
/github signin
```
Follow the authentication flow.

### Step 3: Subscribe to Repository (30 seconds)
In your #code-reviews channel, type:
```
/github subscribe securedotcom/Spring-Backend pulls reviews comments
```

## That's It! 🎉

You'll now automatically receive notifications when:
- ✅ Agent OS creates a PR with audit findings
- ✅ Someone comments on the PR
- ✅ Someone reviews the PR
- ✅ PR is merged or closed

## Test It

Run a workflow and watch the notification appear in Slack:
```bash
gh workflow run agent-os-code-review.yml --field review_type=audit
```

## Customize Notifications

**See all subscriptions:**
```
/github subscribe list
```

**Add more events:**
```
/github subscribe securedotcom/Spring-Backend issues deployments
```

**Remove events:**
```
/github unsubscribe securedotcom/Spring-Backend commits
```

## For All 12 Repositories

Run these commands in your #code-reviews channel:
```
/github subscribe securedotcom/Spring-Backend pulls reviews comments
/github subscribe securedotcom/spring-fabric pulls reviews comments
/github subscribe securedotcom/platform-dashboard-apis pulls reviews comments
/github subscribe securedotcom/siem-agent-provisioning pulls reviews comments
/github subscribe securedotcom/case_management_pipeline pulls reviews comments
/github subscribe securedotcom/case-management-backend pulls reviews comments
/github subscribe securedotcom/Risk-Register pulls reviews comments
/github subscribe securedotcom/Spring-dashboard pulls reviews comments
/github subscribe securedotcom/Spring_CIA_algorithm pulls reviews comments
/github subscribe securedotcom/spring-attack-surface pulls reviews comments
/github subscribe securedotcom/spring-topography-apis pulls reviews comments
/github subscribe securedotcom/secure_data_retrieval_agent pulls reviews comments
```

## No Webhook Configuration Needed!

❌ No webhook URLs  
❌ No secrets to configure  
❌ No maintenance  
✅ Just slash commands!

See `SLACK_GITHUB_APP_SETUP.md` for detailed documentation.
