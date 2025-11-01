#!/bin/bash
# Sync script to keep agent-os and agent-os-action repositories in sync
# Usage: ./scripts/sync-repos.sh

set -e

AGENT_OS_DIR="/Users/waseem.ahmed/Repos/agent-os"
AGENT_OS_ACTION_DIR="/Users/waseem.ahmed/Repos/agent-os-action"

echo "🔄 Syncing agent-os repositories..."

# Function to sync a repo
sync_repo() {
    local dir=$1
    local name=$2

    echo ""
    echo "📂 Syncing $name..."
    cd "$dir"

    # Fetch latest from remote
    git fetch origin

    # Check for uncommitted changes
    if ! git diff-index --quiet HEAD --; then
        echo "⚠️  Warning: $name has uncommitted changes"
        git status --short
        return 1
    fi

    # Check if behind remote
    LOCAL=$(git rev-parse @)
    REMOTE=$(git rev-parse @{u})

    if [ "$LOCAL" != "$REMOTE" ]; then
        echo "⬇️  Pulling latest from origin/main..."
        git reset --hard origin/main
        echo "✅ $name synced to $(git rev-parse --short HEAD)"
    else
        echo "✅ $name already up to date ($(git rev-parse --short HEAD))"
    fi
}

# Sync both repositories
sync_repo "$AGENT_OS_DIR" "agent-os" || echo "❌ Failed to sync agent-os"
sync_repo "$AGENT_OS_ACTION_DIR" "agent-os-action" || echo "❌ Failed to sync agent-os-action"

echo ""
echo "✅ Sync complete!"
echo ""
echo "💡 Tip: Run this script before starting work to ensure both repos are in sync"
