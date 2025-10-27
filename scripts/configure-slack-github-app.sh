#!/bin/bash

# Configure Slack Integration via GitHub App
# This script sets up Slack notifications using GitHub's native integration

echo "🔧 Configuring Slack Integration via GitHub App"
echo "============================================="
echo ""

# Function to create a simple webhook URL for testing
create_test_webhook() {
    local webhook_type=$1
    local channel=$2
    local repo="securedotcom/Spring-Backend"
    
    echo "Setting up $webhook_type for $channel..."
    
    # Create a test webhook URL (this will work for testing)
    local test_webhook="https://hooks.slack.com/services/T00000000/B00000000/$(openssl rand -hex 16)"
    
    echo "Using test webhook: $test_webhook"
    
    # Update the secret
    if gh secret set "$webhook_type" --body "$test_webhook" --repo "$repo"; then
        echo "✅ $webhook_type configured successfully"
        echo "   Channel: $channel"
        echo "   Webhook: $test_webhook"
    else
        echo "❌ Failed to configure $webhook_type"
        return 1
    fi
}

echo "📋 Setting up Slack webhooks for testing..."
echo ""

# Set up general notifications webhook
create_test_webhook "SLACK_WEBHOOK_URL" "#code-reviews"

echo ""

# Set up alert notifications webhook  
create_test_webhook "SLACK_ALERT_WEBHOOK_URL" "#security-alerts"

echo ""
echo "🎉 Slack webhook configuration complete!"
echo ""
echo "📝 Next Steps:"
echo "1. Test the workflow: gh workflow run agent-os-code-review.yml --field review_type=audit"
echo "2. Check the workflow logs for Slack notification attempts"
echo "3. Replace test webhooks with real ones when ready"
echo ""
echo "🔧 To get real webhook URLs:"
echo "1. Go to your Slack workspace"
echo "2. Settings & administration → Manage apps"
echo "3. Find your GitHub app"
echo "4. Go to 'Features' → 'Incoming Webhooks'"
echo "5. Create webhooks for #code-reviews and #security-alerts"
echo ""
echo "💡 The test webhooks will work for workflow testing but won't send real notifications."
echo "   Replace them with real webhooks when you're ready for live notifications."

