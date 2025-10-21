# Test Coverage Review Workflow

## Step 1: Test Discovery and Coverage Analysis

### Test File Discovery
```bash
# Find all test files
find . -name "*test*" -o -name "*spec*" -o -name "*_test*" -o -name "test_*" | grep -v node_modules | grep -v .git

# Count test files by type
find . -name "*.test.js" -o -name "*.spec.js" | wc -l
find . -name "*.test.py" -o -name "test_*.py" | wc -l
find . -name "*_test.rb" -o -name "*_spec.rb" | wc -l
```

### Test Coverage Analysis
```bash
# Run coverage analysis if available
if command -v npm &> /dev/null && [ -f package.json ]; then
    npm test -- --coverage 2>/dev/null || echo "Coverage not available"
fi

if command -v pytest &> /dev/null; then
    pytest --cov=. --cov-report=term-missing 2>/dev/null || echo "Coverage not available"
fi

if command -v rspec &> /dev/null; then
    rspec --format documentation 2>/dev/null || echo "RSpec not available"
fi
```

**Check for:**
- Test file existence and organization
- Test coverage percentages
- Critical path test coverage
- Integration test coverage
- End-to-end test coverage

## Step 2: Critical Path Test Validation

### Business Logic Testing
```bash
# Look for business logic tests
grep -r "describe\|it\|test\|should" --include="*.js" --include="*.py" --include="*.rb" . | grep -i "business\|logic\|service\|model"

# Check for critical functionality tests
grep -r "describe\|it\|test" --include="*.js" --include="*.py" --include="*.rb" . | grep -i "auth\|payment\|user\|order"
```

### API Endpoint Testing
```bash
# Look for API tests
grep -r "describe\|it\|test" --include="*.js" --include="*.py" --include="*.rb" . | grep -i "api\|endpoint\|route\|controller"
```

**Check for:**
- Critical business logic test coverage
- API endpoint test coverage
- User authentication and authorization tests
- Payment and transaction tests
- Data validation tests

## Step 3: Regression Test Review

### Bug Fix Regression Tests
```bash
# Look for regression test patterns
grep -r "regression\|bug.*fix\|issue.*\d+" --include="*.js" --include="*.py" --include="*.rb" . | grep -v "test\|spec"

# Check for test descriptions mentioning specific issues
grep -r "fixes\|resolves\|addresses" --include="*.js" --include="*.py" --include="*.rb" . | grep -i "test\|spec"
```

**Check for:**
- Regression tests for bug fixes
- Test cases for known issues
- Backward compatibility tests
- Migration tests
- Breaking change tests

## Step 4: Test Quality Assessment

### Test Structure and Organization
```bash
# Analyze test file structure
find . -name "*test*" -o -name "*spec*" | head -10 | xargs wc -l

# Check for test organization patterns
grep -r "describe\|context\|before\|after" --include="*.js" --include="*.py" --include="*.rb" . | head -20
```

### Test Isolation and Independence
```bash
# Look for test isolation patterns
grep -r "beforeEach\|afterEach\|setup\|teardown" --include="*.js" --include="*.py" --include="*.rb" . | grep -v "test\|spec"
```

**Check for:**
- Test file organization and structure
- Test isolation and independence
- Proper setup and teardown
- Mock and stub usage
- Test data management

## Step 5: Test Organization Review

### Test Naming and Descriptions
```bash
# Check test naming patterns
grep -r "describe\|it\|test" --include="*.js" --include="*.py" --include="*.rb" . | head -20

# Look for descriptive test names
grep -r "should\|expect\|assert" --include="*.js" --include="*.py" --include="*.rb" . | head -10
```

### Test Grouping and Categorization
```bash
# Check for test grouping
grep -r "describe\|context\|group" --include="*.js" --include="*.py" --include="*.rb" . | head -15
```

**Check for:**
- Descriptive test names
- Proper test grouping
- Test categorization
- Test helper utilities
- Test configuration management

## Step 6: Test Performance Analysis

### Test Execution Speed
```bash
# Check for slow tests
grep -r "slow\|timeout\|sleep" --include="*.js" --include="*.py" --include="*.rb" . | grep -v "test\|spec"

# Look for performance test patterns
grep -r "benchmark\|performance\|load" --include="*.js" --include="*.py" --include="*.rb" . | grep -v "test\|spec"
```

### Test Reliability
```bash
# Look for flaky test patterns
grep -r "retry\|flaky\|unstable" --include="*.js" --include="*.py" --include="*.rb" . | grep -v "test\|spec"
```

**Check for:**
- Test execution speed
- Flaky test identification
- Test parallelization opportunities
- Test resource usage
- CI/CD integration efficiency

## Test Coverage Review Output

Generate test coverage findings with severity classification:

### [BLOCKER] Critical Testing Issues
- Missing tests for critical business logic
- No regression tests for bug fixes
- Critical user workflows untested
- API endpoints without tests
- Database operations untested

### [SUGGESTION] Testing Improvements
- Additional test coverage for edge cases
- Test organization improvements
- Test performance optimization
- Test documentation enhancement
- Integration test additions

### [NIT] Testing Nits
- Minor test naming improvements
- Test style consistency
- Test documentation formatting
- Non-critical test suggestions
