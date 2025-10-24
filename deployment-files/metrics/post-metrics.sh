#!/bin/bash

# Post Metrics Script for Agent OS Code Reviewer
# Posts audit metrics to agent-os-metrics repository

set -e

# Configuration
METRICS_REPO="securedotcom/agent-os-metrics"
METRICS_BRANCH="main"

# Function to post metrics
post_metrics() {
    local repository="$1"
    local review_type="$2"
    local blockers="$3"
    local suggestions="$4"
    local status="$5"
    local commit="$6"
    
    # Validate inputs
    if [ -z "$repository" ] || [ -z "$review_type" ]; then
        echo "Error: Missing required parameters"
        echo "Usage: $0 <repository> <review_type> <blockers> <suggestions> <status> <commit>"
        exit 1
    fi
    
    # Generate timestamp
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local date_path=$(date -u +"%Y/%m")
    local filename="${repository//\//-}-$(date -u +"%Y%m%d-%H%M%S").json"
    
    # Create metrics JSON
    local metrics_json=$(cat <<EOF
{
  "repository": "$repository",
  "timestamp": "$timestamp",
  "review_type": "$review_type",
  "blockers_found": ${blockers:-0},
  "suggestions_found": ${suggestions:-0},
  "status": "$status",
  "commit": "$commit",
  "branch": "${GITHUB_REF_NAME:-main}",
  "actor": "${GITHUB_ACTOR:-unknown}"
}
EOF
)
    
    echo "Metrics JSON:"
    echo "$metrics_json"
    
    # In production, this would push to the metrics repository
    # For now, we'll save locally and document the process
    
    if [ -n "$METRICS_API_TOKEN" ]; then
        echo "Posting metrics to repository..."
        
        # Create temporary directory
        local temp_dir=$(mktemp -d)
        cd "$temp_dir"
        
        # Clone metrics repository
        git clone "https://${METRICS_API_TOKEN}@github.com/${METRICS_REPO}.git" metrics
        cd metrics
        
        # Create directory structure
        mkdir -p "data/$date_path"
        
        # Save metrics file
        echo "$metrics_json" > "data/$date_path/$filename"
        
        # Update latest-metrics.json (append to array)
        if [ -f "data/latest-metrics.json" ]; then
            # Read existing metrics
            local existing=$(cat data/latest-metrics.json)
            # Append new metric
            echo "$existing" | jq ". += [$metrics_json]" > data/latest-metrics.json
        else
            # Create new file
            echo "[$metrics_json]" > data/latest-metrics.json
        fi
        
        # Commit and push
        git config user.name "Agent OS Bot"
        git config user.email "bot@agent-os.dev"
        git add .
        git commit -m "Add metrics for $repository ($review_type audit)"
        git push origin "$METRICS_BRANCH"
        
        # Cleanup
        cd ../..
        rm -rf "$temp_dir"
        
        echo "✅ Metrics posted successfully"
    else
        echo "⚠️  METRICS_API_TOKEN not set, metrics not posted"
        echo "Metrics JSON saved locally for reference"
    fi
}

# Main script
main() {
    post_metrics "$@"
}

# Run main function
main "$@"

