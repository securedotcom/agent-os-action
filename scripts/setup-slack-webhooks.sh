#!/bin/bash

# Slack Webhook Setup Script for Agent OS Code Reviewer
# This script helps configure Slack webhooks for the code review system

echo "🔧 Setting up Slack Webhooks for Agent OS Code Reviewer"
echo "=================================================="
echo ""

# Check if we're in the right directory
if [ ! -f "action.yml" ]; then
    echo "❌ Please run this script from the agent-os root directory"
    exit 1
fi

echo "📋 Required Slack Webhook URLs:"
echo ""
echo "You need to create 2 Slack webhooks:"
echo ""
echo "1. GENERAL NOTIFICATIONS (#code-reviews channel):"
echo "   - Go to: https://api.slack.com/apps"
echo "   - Create new app or use existing"
echo "   - Go to 'Incoming Webhooks'"
echo "   - Create webhook for #code-reviews channel"
echo "   - Copy the webhook URL"
echo ""
echo "2. CRITICAL ALERTS (#security-alerts channel):"
echo "   - Same process as above"
echo "   - Create webhook for #security-alerts channel"
echo "   - Copy the webhook URL"
echo ""

# Function to update webhook URL
update_webhook() {
    local webhook_type=$1
    local webhook_url=$2
    local repo="securedotcom/Spring-Backend"
    
    echo "Updating $webhook_type..."
    if gh secret set "$webhook_type" --body "$webhook_url" --repo "$repo"; then
        echo "✅ $webhook_type updated successfully"
    else
        echo "❌ Failed to update $webhook_type"
        return 1
    fi
}

# Interactive setup
echo "🔧 Interactive Setup:"
echo ""

# Get general webhook URL
echo "Enter the GENERAL webhook URL (for #code-reviews):"
read -r general_webhook

if [ -n "$general_webhook" ]; then
    update_webhook "SLACK_WEBHOOK_URL" "$general_webhook"
fi

echo ""

# Get alert webhook URL
echo "Enter the ALERT webhook URL (for #security-alerts):"
read -r alert_webhook

if [ -n "$alert_webhook" ]; then
    update_webhook "SLACK_ALERT_WEBHOOK_URL" "$alert_webhook"
fi

echo ""
echo "🎉 Slack webhook setup complete!"
echo ""
echo "Next steps:"
echo "1. Test the workflow: gh workflow run agent-os-code-review.yml --field review_type=audit"
echo "2. Check Slack channels for notifications"
echo "3. Verify webhook URLs are working correctly"
echo ""
echo "For troubleshooting, check:"
echo "- GitHub Actions logs"
echo "- Slack app configuration"
echo "- Webhook URL validity"

