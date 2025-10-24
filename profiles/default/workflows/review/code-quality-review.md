# Code Quality Review Workflow

## Step 1: Linting and Style Compliance

### Linter Execution
```bash
# Run linters if available
if command -v eslint &> /dev/null; then
    eslint . --ext .js,.ts,.jsx,.tsx 2>/dev/null || echo "ESLint issues found"
fi

if command -v pylint &> /dev/null; then
    pylint *.py 2>/dev/null || echo "Pylint issues found"
fi

if command -v rubocop &> /dev/null; then
    rubocop 2>/dev/null || echo "RuboCop issues found"
fi

if command -v jshint &> /dev/null; then
    jshint *.js 2>/dev/null || echo "JSHint issues found"
fi
```

### Code Formatting Check
```bash
# Check for formatting tools
if command -v prettier &> /dev/null; then
    prettier --check . 2>/dev/null || echo "Prettier formatting issues"
fi

if command -v black &> /dev/null; then
    black --check . 2>/dev/null || echo "Black formatting issues"
fi
```

**Check for:**
- Linter compliance and error-free code
- Consistent code formatting
- Naming convention adherence
- Import organization
- Code style consistency

## Step 2: Code Maintainability Analysis

### Function and Method Analysis
```bash
# Look for large functions
grep -r "function\|def\|class" --include="*.js" --include="*.py" --include="*.rb" . | wc -l

# Check for function length patterns
find . -name "*.js" -o -name "*.py" -o -name "*.rb" | xargs wc -l | sort -nr | head -10
```

### Code Complexity Analysis
```bash
# Look for complex conditional logic
grep -r "if.*if\|for.*for\|while.*while" --include="*.js" --include="*.py" --include="*.rb" . | grep -v "test\|spec"

# Check for deep nesting
grep -r "    \|        \|            " --include="*.js" --include="*.py" --include="*.rb" . | head -10
```

**Check for:**
- Function and method size
- Code complexity and cyclomatic complexity
- Deep nesting and indentation
- Single responsibility principle adherence
- Code duplication and DRY violations

## Step 3: Documentation Quality Review

### Code Documentation
```bash
# Look for function documentation
grep -r "/\*\*\|#.*def\|#.*function" --include="*.js" --include="*.py" --include="*.rb" . | head -20

# Check for inline comments
grep -r "//\|#.*[^#]" --include="*.js" --include="*.py" --include="*.rb" . | wc -l
```

### README and Documentation Files
```bash
# Check for documentation files
find . -name "README*" -o -name "*.md" -o -name "docs" -type d

# Check documentation completeness
if [ -f README.md ]; then
    echo "README.md exists"
    wc -l README.md
else
    echo "No README.md found"
fi
```

**Check for:**
- Function and method documentation
- Inline code comments
- README file completeness
- API documentation
- Configuration documentation

## Step 4: Architecture Assessment

### Code Organization
```bash
# Analyze file structure
find . -name "*.js" -o -name "*.py" -o -name "*.rb" | head -20

# Check for proper module organization
grep -r "import\|require\|from" --include="*.js" . | head -10
grep -r "import\|from" --include="*.py" . | head -10
```

### Dependency Management
```bash
# Check for dependency organization
if [ -f package.json ]; then
    echo "Node.js dependencies:"
    cat package.json | grep -A 20 '"dependencies"'
fi

if [ -f requirements.txt ]; then
    echo "Python dependencies:"
    cat requirements.txt
fi
```

**Check for:**
- Proper module and file organization
- Dependency management
- Code coupling and cohesion
- Separation of concerns
- Architecture patterns adherence

## Step 5: Error Handling Review

### Exception Handling
```bash
# Look for error handling patterns
grep -r "try\|catch\|except\|rescue" --include="*.js" --include="*.py" --include="*.rb" . | grep -v "test\|spec"

# Check for proper error handling
grep -r "throw\|raise\|error" --include="*.js" --include="*.py" --include="*.rb" . | grep -v "test\|spec"
```

### Logging and Monitoring
```bash
# Look for logging patterns
grep -r "log\|console\|print" --include="*.js" --include="*.py" --include="*.rb" . | grep -v "test\|spec"
```

**Check for:**
- Proper exception handling
- Error logging and monitoring
- User-friendly error messages
- Graceful error recovery
- Error handling consistency

## Step 6: Configuration Management

### Environment Configuration
```bash
# Check for environment variable usage
grep -r "process\.env\|ENV\|getenv\|os\.environ" --include="*.js" --include="*.py" --include="*.rb" . | grep -v "test\|spec"

# Look for configuration files
find . -name "*.env*" -o -name "config*" -o -name "settings*"
```

### Configuration Validation
```bash
# Check for configuration validation
grep -r "validate\|check\|verify" --include="*.js" --include="*.py" --include="*.rb" . | grep -i "config\|env\|setting"
```

**Check for:**
- Environment variable usage
- Configuration file organization
- Sensitive data handling
- Default value management
- Configuration validation

## Code Quality Review Output

Generate code quality findings with severity classification:

### [BLOCKER] Critical Quality Issues
- Linter/formatter failures
- Missing critical documentation
- Poor error handling (blanket catch blocks)
- Security-sensitive configuration issues
- Build/CI failures

### [SUGGESTION] Quality Improvements
- Code readability improvements
- Documentation enhancements
- Architecture improvements
- Error handling optimization
- Configuration management improvements

### [NIT] Quality Nits
- Minor style inconsistencies
- Grammar in comments
- Subjective naming preferences
- Micro-optimization suggestions
- Non-critical documentation issues
