#!/bin/bash

# Slack Notification Script for Agent OS Code Reviewer
# Sends structured notifications to Slack channels

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TEMPLATES_DIR="$REPO_ROOT/profiles/default/notifications"

# Function to send notification
send_notification() {
    local webhook_url="$1"
    local message="$2"
    
    if [ -z "$webhook_url" ]; then
        echo "Warning: Slack webhook URL not provided, skipping notification"
        return 0
    fi
    
    echo "Sending Slack notification..."
    curl -X POST -H 'Content-type: application/json' \
        --data "$message" \
        --silent --show-error \
        "$webhook_url"
    
    echo "Notification sent successfully"
}

# Function to extract metrics from audit report
extract_metrics() {
    local report_file="$1"
    
    if [ ! -f "$report_file" ]; then
        echo "0"
        return
    fi
    
    grep -c "$2" "$report_file" 2>/dev/null || echo "0"
}

# Function to create audit complete notification
notify_audit_complete() {
    local repository="$1"
    local branch="$2"
    local review_type="$3"
    local workflow_url="$4"
    local report_path="$5"
    
    # Extract metrics
    local blockers=$(extract_metrics "$report_path" "\[BLOCKER\]")
    local suggestions=$(extract_metrics "$report_path" "\[SUGGESTION\]")
    
    # Determine status
    local status_emoji="✅"
    local status_text="Passed"
    if [ "$blockers" -gt 0 ]; then
        status_emoji="❌"
        status_text="Requires Fixes"
    fi
    
    # Build notification
    local message=$(cat <<EOF
{
  "text": "${status_emoji} Code Review Complete: ${repository}",
  "blocks": [
    {
      "type": "header",
      "text": {
        "type": "plain_text",
        "text": "${status_emoji} Code Review Complete"
      }
    },
    {
      "type": "section",
      "fields": [
        {
          "type": "mrkdwn",
          "text": "*Repository:*\n${repository}"
        },
        {
          "type": "mrkdwn",
          "text": "*Branch:*\n${branch}"
        },
        {
          "type": "mrkdwn",
          "text": "*Review Type:*\n${review_type}"
        },
        {
          "type": "mrkdwn",
          "text": "*Status:*\n${status_text}"
        }
      ]
    },
    {
      "type": "section",
      "fields": [
        {
          "type": "mrkdwn",
          "text": "*Blockers:*\n${blockers}"
        },
        {
          "type": "mrkdwn",
          "text": "*Suggestions:*\n${suggestions}"
        }
      ]
    },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "<${workflow_url}|View Full Report>"
      }
    }
  ]
}
EOF
)
    
    send_notification "${SLACK_WEBHOOK_URL}" "$message"
    
    # Send alert if blockers found
    if [ "$blockers" -gt 0 ] && [ -n "${SLACK_ALERT_WEBHOOK_URL}" ]; then
        notify_critical_alert "$repository" "$branch" "$blockers" "$workflow_url" "$report_path"
    fi
}

# Function to create critical alert notification
notify_critical_alert() {
    local repository="$1"
    local branch="$2"
    local blockers="$3"
    local workflow_url="$4"
    local report_path="$5"
    
    # Extract top 3 issues
    local top_issues=""
    if [ -f "$report_path" ]; then
        top_issues=$(grep "\[BLOCKER\]" "$report_path" | head -3 | sed 's/^/• /' | tr '\n' '\n')
    fi
    
    local message=$(cat <<EOF
{
  "text": "🚨 Critical Issues Found: ${repository}",
  "blocks": [
    {
      "type": "header",
      "text": {
        "type": "plain_text",
        "text": "🚨 Critical Security Alert"
      }
    },
    {
      "type": "section",
      "fields": [
        {
          "type": "mrkdwn",
          "text": "*Repository:*\n${repository}"
        },
        {
          "type": "mrkdwn",
          "text": "*Branch:*\n${branch}"
        }
      ]
    },
    {
      "type": "section",
      "fields": [
        {
          "type": "mrkdwn",
          "text": "*Critical Issues:*\n🚨 ${blockers}"
        }
      ]
    },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*⚠️ Action Required*\nCritical issues must be fixed before merging."
      }
    },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "<${workflow_url}|View Full Report>"
      }
    }
  ]
}
EOF
)
    
    send_notification "${SLACK_ALERT_WEBHOOK_URL}" "$message"
}

# Function to create PR review notification
notify_pr_review() {
    local repository="$1"
    local pr_number="$2"
    local pr_title="$3"
    local author="$4"
    local pr_url="$5"
    local workflow_url="$6"
    local report_path="$7"
    
    # Extract metrics
    local blockers=$(extract_metrics "$report_path" "\[BLOCKER\]")
    local suggestions=$(extract_metrics "$report_path" "\[SUGGESTION\]")
    local nits=$(extract_metrics "$report_path" "\[NIT\]")
    
    # Determine status and recommendation
    local status_emoji="✅"
    local status_text="Approved"
    local recommendation="✅ Ready to merge"
    
    if [ "$blockers" -gt 0 ]; then
        status_emoji="❌"
        status_text="Changes Requested"
        recommendation="❌ Fix ${blockers} blocker(s) before merging"
    elif [ "$suggestions" -gt 3 ]; then
        status_emoji="⚠️"
        status_text="Approved with Comments"
        recommendation="⚠️ Consider addressing ${suggestions} suggestion(s)"
    fi
    
    local message=$(cat <<EOF
{
  "text": "${status_emoji} PR Review: ${repository}#${pr_number}",
  "blocks": [
    {
      "type": "header",
      "text": {
        "type": "plain_text",
        "text": "📝 Pull Request Review"
      }
    },
    {
      "type": "section",
      "fields": [
        {
          "type": "mrkdwn",
          "text": "*Repository:*\n${repository}"
        },
        {
          "type": "mrkdwn",
          "text": "*PR:*\n#${pr_number} - ${pr_title}"
        },
        {
          "type": "mrkdwn",
          "text": "*Author:*\n@${author}"
        },
        {
          "type": "mrkdwn",
          "text": "*Status:*\n${status_emoji} ${status_text}"
        }
      ]
    },
    {
      "type": "section",
      "fields": [
        {
          "type": "mrkdwn",
          "text": "*Blockers:*\n${blockers}"
        },
        {
          "type": "mrkdwn",
          "text": "*Suggestions:*\n${suggestions}"
        },
        {
          "type": "mrkdwn",
          "text": "*Nits:*\n${nits}"
        }
      ]
    },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "${recommendation}"
      }
    },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "<${pr_url}|View Pull Request> | <${workflow_url}|View Review Details>"
      }
    }
  ]
}
EOF
)
    
    send_notification "${SLACK_WEBHOOK_URL}" "$message"
}

# Main script logic
main() {
    local notification_type="${1:-audit}"
    
    case "$notification_type" in
        audit)
            notify_audit_complete \
                "${REPOSITORY}" \
                "${BRANCH}" \
                "${REVIEW_TYPE:-audit}" \
                "${WORKFLOW_URL}" \
                "${REPORT_PATH:-.agent-os/reviews/audit-report.md}"
            ;;
        pr)
            notify_pr_review \
                "${REPOSITORY}" \
                "${PR_NUMBER}" \
                "${PR_TITLE}" \
                "${PR_AUTHOR}" \
                "${PR_URL}" \
                "${WORKFLOW_URL}" \
                "${REPORT_PATH:-.agent-os/reviews/review-report.md}"
            ;;
        security)
            notify_audit_complete \
                "${REPOSITORY}" \
                "${BRANCH}" \
                "security" \
                "${WORKFLOW_URL}" \
                "${REPORT_PATH:-.agent-os/reviews/security-report.md}"
            ;;
        *)
            echo "Error: Unknown notification type: $notification_type"
            echo "Usage: $0 [audit|pr|security]"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"

