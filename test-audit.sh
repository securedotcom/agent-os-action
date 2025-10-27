#!/bin/bash
# Test Agent OS with Cursor API

echo "🧪 Testing Agent OS Code Review with Cursor Claude 4.5 Sonnet"
echo "============================================================"
echo ""

# Set up environment
export ANTHROPIC_API_KEY="key_216eb7123e38cc4e321ff3909cd4c06f35aa102d1abeabc34b93046bd8788213"
export INPUT_AI_PROVIDER="auto"
export INPUT_MODEL="auto"
export INPUT_ONLY_CHANGED="false"
export INPUT_INCLUDE_PATHS="scripts/**,profiles/**"
export INPUT_EXCLUDE_PATHS="test/**,node_modules/**"
export INPUT_MAX_FILE_SIZE="50000"
export INPUT_MAX_FILES="10"
export INPUT_MAX_TOKENS="4000"
export INPUT_COST_LIMIT="0.50"
export GITHUB_REPOSITORY="securedotcom/agent-os-action"
export GITHUB_SHA="test-run"

# Install dependencies
echo "📦 Installing Python dependencies..."
pip install -q anthropic openai

# Run audit
echo ""
echo "🚀 Running audit..."
python3 scripts/run-ai-audit.py . audit

# Check results
echo ""
echo "📊 Checking results..."
if [ -f ".agent-os/reviews/audit-report.md" ]; then
    echo "✅ Audit report generated"
    echo ""
    echo "📄 Report preview (first 50 lines):"
    head -50 .agent-os/reviews/audit-report.md
    echo ""
    echo "..."
    echo ""
fi

if [ -f ".agent-os/reviews/metrics.json" ]; then
    echo "📊 Metrics:"
    cat .agent-os/reviews/metrics.json | jq '.'
fi

if [ -f ".agent-os/reviews/results.sarif" ]; then
    echo "✅ SARIF file generated"
fi

if [ -f ".agent-os/reviews/results.json" ]; then
    echo "✅ JSON results generated"
fi

echo ""
echo "🎉 Test complete!"
