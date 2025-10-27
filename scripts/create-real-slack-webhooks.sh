#!/bin/bash

# Create Real Slack Webhooks for Agent OS Code Reviewer
# This script helps you create actual Slack webhooks that will send notifications

echo "🔧 Creating Real Slack Webhooks for Agent OS Code Reviewer"
echo "========================================================"
echo ""

echo "📋 Step-by-Step Instructions:"
echo ""
echo "1️⃣  CREATE SLACK APP (if not done already):"
echo "   - Go to: https://api.slack.com/apps"
echo "   - Click 'Create New App'"
echo "   - Choose 'From scratch'"
echo "   - App Name: 'Agent OS Code Reviewer'"
echo "   - Workspace: [Your workspace]"
echo "   - Click 'Create App'"
echo ""

echo "2️⃣  ENABLE INCOMING WEBHOOKS:"
echo "   - In your app settings, go to 'Features' → 'Incoming Webhooks'"
echo "   - Toggle 'Activate Incoming Webhooks' to ON"
echo "   - Click 'Add New Webhook to Workspace'"
echo ""

echo "3️⃣  CREATE WEBHOOK FOR #code-reviews:"
echo "   - Select #code-reviews channel (create it if it doesn't exist)"
echo "   - Click 'Allow'"
echo "   - Copy the webhook URL (starts with https://hooks.slack.com/services/)"
echo "   - Save this URL - you'll need it in a moment"
echo ""

echo "4️⃣  CREATE WEBHOOK FOR #security-alerts:"
echo "   - Click 'Add New Webhook to Workspace' again"
echo "   - Select #security-alerts channel (create it if it doesn't exist)"
echo "   - Click 'Allow'"
echo "   - Copy the webhook URL"
echo "   - Save this URL - you'll need it in a moment"
echo ""

echo "5️⃣  UPDATE GITHUB SECRETS:"
echo "   Once you have both webhook URLs, run these commands:"
echo ""
echo "   # For general notifications (#code-reviews)"
echo "   gh secret set SLACK_WEBHOOK_URL --body 'YOUR_CODE_REVIEWS_WEBHOOK_URL' --repo securedotcom/Spring-Backend"
echo ""
echo "   # For critical alerts (#security-alerts)"
echo "   gh secret set SLACK_ALERT_WEBHOOK_URL --body 'YOUR_SECURITY_ALERTS_WEBHOOK_URL' --repo securedotcom/Spring-Backend"
echo ""

echo "6️⃣  TEST THE NOTIFICATIONS:"
echo "   After updating the secrets, test with:"
echo "   gh workflow run agent-os-code-review.yml --field review_type=audit"
echo ""

echo "💡 TIP: If you don't have #code-reviews and #security-alerts channels,"
echo "   create them in your Slack workspace first."
echo ""

echo "🔧 Quick Channel Creation:"
echo "   - In Slack, type: /create #code-reviews"
echo "   - In Slack, type: /create #security-alerts"
echo ""

echo "Ready to proceed? Let me know when you have the webhook URLs!"

