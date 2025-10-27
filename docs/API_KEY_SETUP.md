# API Key Setup Guide

## 🔑 Getting Your Anthropic API Key

### Step 1: Create Anthropic Account
1. Visit: https://console.anthropic.com/
2. Click "Sign Up" or "Sign In"
3. Complete registration

### Step 2: Generate API Key
1. Go to: https://console.anthropic.com/settings/keys
2. Click "Create Key"
3. Give it a name (e.g., "Agent OS Code Reviewer")
4. Copy the key (starts with `sk-ant-`)
5. **Important**: Save it securely - you won't see it again!

### Step 3: Add to GitHub Secrets

#### For Spring-Backend Repository:
1. Go to: https://github.com/securedotcom/Spring-Backend/settings/secrets/actions
2. Click "New repository secret"
3. Name: `ANTHROPIC_API_KEY`
4. Value: Paste your `sk-ant-...` key
5. Click "Add secret"

#### For Other Repositories:
Repeat the above steps for each repository where you want to use Agent OS.

### Step 4: Verify Setup

Run this command to check if the secret is set:
```bash
gh secret list --repo securedotcom/Spring-Backend
```

You should see `ANTHROPIC_API_KEY` in the list.

### Step 5: Test the Integration

Trigger a manual workflow run:
```bash
cd /path/to/Spring-Backend
gh workflow run agent-os-code-review.yml --field review_type=audit
```

Monitor the run:
```bash
gh run watch
```

---

## 🔍 Troubleshooting

### Issue: "invalid x-api-key"
**Cause**: API key is incorrect or expired
**Solution**: 
1. Verify key starts with `sk-ant-`
2. Check for extra spaces or characters
3. Generate a new key if needed

### Issue: "Authentication error"
**Cause**: Secret not set or wrong name
**Solution**:
1. Verify secret name is exactly `ANTHROPIC_API_KEY`
2. Check secret is set in correct repository
3. Try deleting and re-adding the secret

### Issue: "Rate limit exceeded"
**Cause**: Too many API calls
**Solution**:
1. Check your Anthropic usage dashboard
2. Upgrade your plan if needed
3. Reduce analysis frequency

---

## 💰 Pricing Information

### Anthropic Claude Pricing (as of 2025)
- **Claude Sonnet 4**: ~$3 per 1M input tokens, ~$15 per 1M output tokens
- **Estimated cost per audit**: $0.10 - $0.50 (depending on codebase size)
- **Monthly cost (weekly audits)**: ~$2 - $8 per repository

### Tips to Reduce Costs:
1. Run audits weekly instead of daily
2. Focus on changed files only (for PR reviews)
3. Limit to 50 files per audit (already implemented)
4. Use smaller context windows

---

## 🔒 Security Best Practices

### DO:
✅ Store API keys in GitHub Secrets (encrypted)
✅ Use separate keys for different environments
✅ Rotate keys periodically (every 90 days)
✅ Monitor usage in Anthropic dashboard
✅ Set up billing alerts

### DON'T:
❌ Commit API keys to git
❌ Share keys via email or Slack
❌ Use the same key across multiple organizations
❌ Store keys in plain text files
❌ Leave unused keys active

---

## 🔄 Alternative: OpenAI API Key

If you prefer to use OpenAI instead:

### Setup:
1. Get key from: https://platform.openai.com/api-keys
2. Add as `OPENAI_API_KEY` secret
3. The script will auto-detect and use OpenAI

### Pricing:
- **GPT-4**: ~$30 per 1M input tokens, ~$60 per 1M output tokens
- More expensive than Claude but may have different strengths

---

## 📊 Monitoring Usage

### Anthropic Console:
- View usage: https://console.anthropic.com/settings/usage
- Set limits: https://console.anthropic.com/settings/limits
- Billing: https://console.anthropic.com/settings/billing

### GitHub Actions:
- Check workflow runs: Repository → Actions
- View logs for API calls
- Monitor artifact sizes

---

## ✅ Verification Checklist

Before considering setup complete:

- [ ] Anthropic account created
- [ ] API key generated and saved securely
- [ ] `ANTHROPIC_API_KEY` secret added to GitHub
- [ ] Test workflow run completed successfully
- [ ] Real AI analysis visible in PR
- [ ] No authentication errors in logs
- [ ] Billing alerts configured
- [ ] Usage monitoring set up

---

## 🆘 Need Help?

If you encounter issues:
1. Check `docs/TROUBLESHOOTING.md`
2. Review workflow logs in GitHub Actions
3. Verify API key in Anthropic console
4. Check GitHub Discussions for similar issues

---

**Last Updated**: October 24, 2025

