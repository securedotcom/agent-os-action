#!/bin/bash
# Go Performance and Complexity Linting
# Combines gocyclo, gocognit, and staticcheck for comprehensive analysis

set -e

echo "🔍 Running Go performance and complexity checks..."

# Install tools if not present
if ! command -v gocyclo &> /dev/null; then
    echo "📦 Installing gocyclo..."
    go install github.com/fzipp/gocyclo/cmd/gocyclo@latest
fi

if ! command -v gocognit &> /dev/null; then
    echo "📦 Installing gocognit..."
    go install github.com/uudashr/gocognit/cmd/gocognit@latest
fi

if ! command -v staticcheck &> /dev/null; then
    echo "📦 Installing staticcheck..."
    go install honnef.co/go/tools/cmd/staticcheck@latest
fi

# Configuration
MAX_CYCLOMATIC=10
MAX_COGNITIVE=15
MAX_LINES=50

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1️⃣  Cyclomatic Complexity (gocyclo)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Threshold: $MAX_CYCLOMATIC"
echo ""

# Run gocyclo
if gocyclo -over $MAX_CYCLOMATIC . 2>/dev/null; then
    echo "✅ No functions exceed cyclomatic complexity threshold"
else
    echo "⚠️  Functions with high cyclomatic complexity found (see above)"
    CYCLO_ISSUES=true
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "2️⃣  Cognitive Complexity (gocognit)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Threshold: $MAX_COGNITIVE"
echo ""

# Run gocognit
if gocognit -over $MAX_COGNITIVE . 2>/dev/null; then
    echo "✅ No functions exceed cognitive complexity threshold"
else
    echo "⚠️  Functions with high cognitive complexity found (see above)"
    COGNIT_ISSUES=true
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "3️⃣  Static Analysis (staticcheck)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Checking for performance issues, bugs, and style violations..."
echo ""

# Run staticcheck
if staticcheck ./... 2>&1; then
    echo "✅ No static analysis issues found"
else
    echo "⚠️  Static analysis issues found (see above)"
    STATIC_ISSUES=true
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 Summary"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ -z "$CYCLO_ISSUES" ] && [ -z "$COGNIT_ISSUES" ] && [ -z "$STATIC_ISSUES" ]; then
    echo "✅ All checks passed!"
    exit 0
else
    echo "⚠️  Issues found:"
    [ -n "$CYCLO_ISSUES" ] && echo "   - High cyclomatic complexity"
    [ -n "$COGNIT_ISSUES" ] && echo "   - High cognitive complexity"
    [ -n "$STATIC_ISSUES" ] && echo "   - Static analysis issues"
    echo ""
    echo "💡 Recommendations:"
    echo "   - Break down complex functions into smaller ones"
    echo "   - Reduce nesting depth with early returns"
    echo "   - Extract complex conditions into named variables"
    echo "   - Use guard clauses to handle edge cases first"
    exit 1
fi

# Additional checks (optional)
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "4️⃣  Additional Checks"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check for large functions (lines of code)
echo "Checking for large functions (>$MAX_LINES lines)..."
echo ""

# This is a simple grep-based check; for production, use a proper Go parser
find . -name "*.go" -not -path "*/vendor/*" -not -path "*/.git/*" | while read file; do
    awk '
        /^func / { 
            in_func=1; 
            func_name=$2; 
            start_line=NR; 
            brace_count=0;
            for(i=1;i<=NF;i++) {
                if($i ~ /{/) brace_count++;
                if($i ~ /}/) brace_count--;
            }
        }
        in_func { 
            for(i=1;i<=NF;i++) {
                if($i ~ /{/) brace_count++;
                if($i ~ /}/) brace_count--;
            }
            if(brace_count == 0 && in_func) {
                lines = NR - start_line + 1;
                if(lines > '"$MAX_LINES"') {
                    print FILENAME ":" start_line ": Function " func_name " is too long (" lines " lines, max '"$MAX_LINES"')";
                }
                in_func=0;
            }
        }
    ' FILENAME="$file" "$file"
done

echo ""
echo "✅ Performance and complexity checks complete"

