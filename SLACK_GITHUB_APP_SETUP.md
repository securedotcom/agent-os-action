# Slack Integration with GitHub App

## Overview

The Agent OS Code Reviewer integrates with Slack using the **official GitHub app for Slack**. This is simpler and more powerful than webhooks, as it provides native GitHub event notifications directly in Slack.

## Setup Instructions

### Step 1: Install GitHub App in Slack

1. **In your Slack workspace:**
   - Go to your Slack workspace
   - Click on your workspace name → Settings & administration → Manage apps
   - Search for "GitHub" in the app directory
   - Click "Add to Slack"
   - Authorize the app

2. **Connect your GitHub account:**
   - In any Slack channel, type: `/github signin`
   - Follow the authentication flow
   - Authorize the GitHub app to access your repositories

### Step 2: Subscribe to Repository Events

1. **In your desired Slack channel (e.g., #code-reviews):**
   ```
   /github subscribe securedotcom/Spring-Backend
   ```

2. **Configure which events to receive:**
   ```
   /github subscribe securedotcom/Spring-Backend reviews comments
   ```

3. **For security alerts channel (#security-alerts):**
   ```
   /github subscribe securedotcom/Spring-Backend issues pulls
   ```

### Step 3: Customize Notifications

**Available event types:**
- `issues` - Opened or closed issues
- `pulls` - Opened or closed pull requests
- `commits` - New commits pushed
- `reviews` - Pull request reviews
- `comments` - New comments on issues and pull requests
- `branches` - Branch creation or deletion
- `releases` - Published releases
- `deployments` - Deployment status updates

**Example configurations:**

```bash
# For code reviews channel - get PR and review notifications
/github subscribe securedotcom/Spring-Backend pulls reviews comments

# For security alerts channel - get issues and PRs
/github subscribe securedotcom/Spring-Backend issues pulls

# To see current subscriptions
/github subscribe list

# To unsubscribe from specific events
/github unsubscribe securedotcom/Spring-Backend commits
```

## How It Works with Agent OS Code Reviewer

### Automatic Notifications

When the Agent OS Code Reviewer runs:

1. **PR Creation:**
   - When audit finds issues, it creates a PR
   - GitHub app automatically notifies the subscribed Slack channel
   - You see: "New pull request opened: 🔍 Code Review Findings..."

2. **PR Comments:**
   - When workflow adds comments to existing PRs
   - GitHub app sends notification to Slack
   - You see: "New comment on PR #4..."

3. **PR Reviews:**
   - When someone reviews the audit PR
   - GitHub app notifies the channel
   - You see: "Review submitted on PR #4..."

### No Webhook Configuration Needed!

The GitHub app handles all notifications automatically. You don't need to:
- ❌ Create webhook URLs
- ❌ Configure secrets in GitHub Actions
- ❌ Manage webhook endpoints
- ✅ Just subscribe to repos with `/github subscribe`

## Recommended Channel Setup

### Option 1: Single Channel
```bash
# In #code-reviews channel
/github subscribe securedotcom/Spring-Backend pulls reviews comments
```

### Option 2: Separate Channels
```bash
# In #code-reviews channel
/github subscribe securedotcom/Spring-Backend pulls reviews

# In #security-alerts channel
/github subscribe securedotcom/Spring-Backend issues
```

### Option 3: Multiple Repositories
```bash
# Subscribe all 12 repositories to #code-reviews
/github subscribe securedotcom/Spring-Backend pulls reviews comments
/github subscribe securedotcom/spring-fabric pulls reviews comments
/github subscribe securedotcom/platform-dashboard-apis pulls reviews comments
# ... and so on for all repositories
```

## Advanced Features

### 1. Unfurling
GitHub links automatically expand with rich previews in Slack.

### 2. Actions
You can interact with PRs directly from Slack:
- Approve/Request changes
- Merge PRs
- Close issues
- Add comments

### 3. Reminders
Set up reminders for pending reviews:
```bash
/github subscribe securedotcom/Spring-Backend reviews
```

### 4. Scheduled Digests
Get daily/weekly summaries:
```bash
/github subscribe securedotcom/Spring-Backend +digest
```

## Troubleshooting

### Not receiving notifications?
1. Check subscription: `/github subscribe list`
2. Verify channel subscription: `/github subscribe securedotcom/Spring-Backend`
3. Re-authenticate: `/github signin`

### Too many notifications?
1. Unsubscribe from specific events:
   ```bash
   /github unsubscribe securedotcom/Spring-Backend commits
   ```
2. Use filters:
   ```bash
   /github subscribe securedotcom/Spring-Backend pulls reviews -label:"automated-review"
   ```

### Want to test?
1. Create a test PR in the repository
2. Check if notification appears in Slack
3. Adjust subscriptions as needed

## Benefits Over Webhooks

✅ **Simpler Setup:** Just use slash commands  
✅ **More Features:** Interactive actions, unfurling, reminders  
✅ **Better Security:** No webhook URLs to manage  
✅ **Native Integration:** Built by GitHub and Slack teams  
✅ **Automatic Updates:** Always uses latest GitHub features  
✅ **No Maintenance:** No webhook endpoints to monitor  

## Quick Start Commands

```bash
# 1. Sign in to GitHub
/github signin

# 2. Subscribe to your main repository
/github subscribe securedotcom/Spring-Backend pulls reviews comments

# 3. Check what you're subscribed to
/github subscribe list

# 4. Test it by creating a PR or triggering the workflow
gh workflow run agent-os-code-review.yml --field review_type=audit
```

## Next Steps

1. ✅ Install GitHub app in Slack
2. ✅ Sign in with `/github signin`
3. ✅ Subscribe to Spring-Backend with `/github subscribe`
4. ✅ Run a workflow and watch notifications appear
5. ✅ Adjust subscriptions based on your needs

That's it! No webhook configuration needed. The GitHub app handles everything automatically.

