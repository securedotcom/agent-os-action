#!/bin/bash
# Quick test with Cursor API

export ANTHROPIC_API_KEY="key_216eb7123e38cc4e321ff3909cd4c06f35aa102d1abeabc34b93046bd8788213"
export INPUT_AI_PROVIDER="auto"
export INPUT_MAX_FILES="5"
export INPUT_MAX_TOKENS="2000"
export INPUT_COST_LIMIT="0.25"
export INPUT_INCLUDE_PATHS="scripts/run-ai-audit.py"
export GITHUB_REPOSITORY="securedotcom/agent-os-action"
export GITHUB_SHA="test"

echo "🧪 Testing with Cursor Claude 4.5 Sonnet..."
echo ""
python3 scripts/run-ai-audit.py . audit
