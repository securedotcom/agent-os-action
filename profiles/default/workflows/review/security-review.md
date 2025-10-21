# Security Review Workflow

## Step 1: Secrets and Credentials Scan

Scan codebase for hardcoded secrets and sensitive data:

```bash
# Scan for common secret patterns
grep -r -i "password\|secret\|key\|token\|api_key\|private_key" --include="*.js" --include="*.py" --include="*.rb" --include="*.java" --include="*.ts" --include="*.php" . | grep -v "test\|spec\|example\|sample"

# Check for environment variable usage vs hardcoded values
grep -r "process\.env\|ENV\|getenv" --include="*.js" --include="*.py" --include="*.rb" .

# Look for configuration files with secrets
find . -name "*.env*" -o -name "config*" -o -name "*.json" | xargs grep -l "password\|secret\|key" 2>/dev/null
```

**Check for:**
- Hardcoded API keys, passwords, tokens
- Database connection strings with credentials
- Private keys in source code
- Configuration files with secrets
- Missing environment variable usage

## Step 2: Injection Vulnerability Detection

### SQL Injection Analysis
```bash
# Look for dynamic SQL construction
grep -r "SELECT\|INSERT\|UPDATE\|DELETE" --include="*.js" --include="*.py" --include="*.rb" --include="*.java" --include="*.php" . | grep -v "test\|spec"

# Check for string concatenation in queries
grep -r "query.*\+.*\$\|query.*\`.*\$\|query.*\".*\$\|query.*'.*\$" --include="*.js" --include="*.py" --include="*.rb" .
```

### NoSQL Injection Analysis
```bash
# Look for dynamic NoSQL queries
grep -r "find\|findOne\|update\|remove\|aggregate" --include="*.js" --include="*.py" . | grep -v "test\|spec"
```

### Command Injection Analysis
```bash
# Look for system command execution
grep -r "exec\|system\|shell_exec\|popen\|spawn" --include="*.js" --include="*.py" --include="*.rb" --include="*.php" . | grep -v "test\|spec"
```

**Check for:**
- Dynamic query construction without parameterization
- User input directly in database queries
- System command execution with user input
- Template injection vulnerabilities

## Step 3: Authentication & Authorization Review

### Authentication Checks
```bash
# Look for authentication middleware
grep -r "auth\|authenticate\|login\|session" --include="*.js" --include="*.py" --include="*.rb" . | grep -v "test\|spec"

# Check for protected routes
grep -r "middleware\|before_action\|before_filter\|@require_auth" --include="*.js" --include="*.py" --include="*.rb" .
```

### Authorization Checks
```bash
# Look for authorization logic
grep -r "authorize\|permission\|role\|admin\|user_id" --include="*.js" --include="*.py" --include="*.rb" . | grep -v "test\|spec"
```

**Check for:**
- Missing authentication on protected endpoints
- Inadequate authorization checks
- IDOR (Insecure Direct Object Reference) vulnerabilities
- Session management issues
- Token validation and expiration

## Step 4: Cryptographic Security Validation

### Crypto Implementation Review
```bash
# Look for crypto usage
grep -r "crypto\|encrypt\|decrypt\|hash\|salt\|iv" --include="*.js" --include="*.py" --include="*.rb" . | grep -v "test\|spec"

# Check for hardcoded crypto parameters
grep -r "salt.*=.*['\"]\|iv.*=.*['\"]\|key.*=.*['\"]" --include="*.js" --include="*.py" --include="*.rb" .
```

**Check for:**
- Hardcoded salts, IVs, or encryption keys
- Use of deprecated or weak cryptographic algorithms
- Proper random number generation
- Secure key management and storage
- TLS/SSL configuration and certificate validation

## Step 5: Dependency Security Audit

### CVE and Vulnerability Scanning
```bash
# Check for known vulnerabilities in dependencies
if command -v npm audit &> /dev/null; then
    npm audit --audit-level=high
fi

if command -v pip-audit &> /dev/null; then
    pip-audit
fi

if command -v bundle audit &> /dev/null; then
    bundle audit
fi
```

### Package Analysis
```bash
# Check package.json, requirements.txt, Gemfile for suspicious packages
find . -name "package.json" -o -name "requirements.txt" -o -name "Gemfile" | xargs cat
```

**Check for:**
- Known CVEs in dependencies
- Unvetted or suspicious packages
- License compliance issues
- Pinned vs unpinned versions
- Package authenticity and integrity

## Step 6: Input/Output Security Review

### Input Validation
```bash
# Look for input validation
grep -r "validate\|sanitize\|escape\|filter" --include="*.js" --include="*.py" --include="*.rb" . | grep -v "test\|spec"
```

### Output Encoding
```bash
# Look for output encoding
grep -r "escape\|encode\|sanitize\|htmlspecialchars" --include="*.js" --include="*.py" --include="*.rb" . | grep -v "test\|spec"
```

**Check for:**
- Input validation on all user inputs
- Output encoding to prevent XSS
- File upload security
- Error handling without information disclosure
- Rate limiting and abuse prevention

## Security Review Output

Generate security findings with severity classification:

### [BLOCKER] Critical Security Issues
- Hardcoded secrets or credentials
- SQL/NoSQL injection vulnerabilities
- Missing authentication on protected endpoints
- Insecure cryptographic practices
- High-severity CVE dependencies

### [SUGGESTION] Security Improvements
- Input validation enhancements
- Error handling improvements
- Security headers implementation
- Rate limiting implementation
- Logging and monitoring improvements

### [NIT] Security Nits
- Minor security documentation
- Style improvements in security code
- Non-critical security suggestions
