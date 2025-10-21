# Merge Blocker Standards

## Critical Issues That Must Be Fixed Before Merge

### Security Blockers

#### [BLOCKER] Hardcoded Secrets and Credentials
- **Pattern:** Hardcoded API keys, passwords, tokens, or private keys in source code
- **Examples:**
  - `const apiKey = "sk-1234567890abcdef";`
  - `password = "mypassword123"`
  - `private_key = "-----BEGIN PRIVATE KEY-----"`
- **Fix:** Use environment variables or secure configuration management
- **Impact:** High - Credentials could be exposed in version control

#### [BLOCKER] SQL/NoSQL Injection Vulnerabilities
- **Pattern:** User input directly concatenated into database queries
- **Examples:**
  - `query = "SELECT * FROM users WHERE id = " + userId`
  - `db.users.find({name: userInput})`
- **Fix:** Use parameterized queries or ORM methods
- **Impact:** High - Could lead to data breach or system compromise

#### [BLOCKER] Missing Authentication on Protected Endpoints
- **Pattern:** API endpoints without authentication middleware
- **Examples:**
  - `app.get('/api/users', handler)` without auth middleware
  - Missing `@RequireAuth` annotations
- **Fix:** Add authentication middleware or decorators
- **Impact:** High - Unauthorized access to sensitive data

#### [BLOCKER] Insecure Cryptographic Practices
- **Pattern:** Hardcoded salts, IVs, or weak encryption
- **Examples:**
  - `salt = "hardcoded_salt"`
  - `crypto.createHash('md5')`
- **Fix:** Use secure random generation and approved algorithms
- **Impact:** High - Weak encryption could be broken

#### [BLOCKER] High-Severity CVE Dependencies
- **Pattern:** Dependencies with known critical vulnerabilities
- **Examples:** Outdated packages with CVE scores > 7.0
- **Fix:** Update to secure versions or find alternatives
- **Impact:** High - Known security vulnerabilities

### Reliability Blockers

#### [BLOCKER] Poor Error Handling
- **Pattern:** Blanket catch blocks or missing error handling
- **Examples:**
  - `try { ... } catch { }`
  - Missing error handling for network calls
- **Fix:** Implement proper error handling with specific exception types
- **Impact:** High - Could cause silent failures or system crashes

#### [BLOCKER] Resource Leaks
- **Pattern:** Unclosed connections, files, or streams
- **Examples:**
  - Database connections not closed
  - File handles not released
  - Memory leaks in long-running processes
- **Fix:** Implement proper resource cleanup with try-finally or using statements
- **Impact:** High - Could cause system resource exhaustion

#### [BLOCKER] Missing Timeouts on Network Calls
- **Pattern:** Network operations without timeout configuration
- **Examples:**
  - HTTP requests without timeout
  - Database queries without timeout
- **Fix:** Set appropriate timeout values for all network operations
- **Impact:** High - Could cause system hangs or cascading failures

#### [BLOCKER] Unbounded Loops or Collections
- **Pattern:** Loops without termination conditions or unbounded data structures
- **Examples:**
  - `while (true)` without break conditions
  - Arrays that grow without limits
- **Fix:** Add proper termination conditions and bounds checking
- **Impact:** High - Could cause infinite loops or memory exhaustion

### Testing Blockers

#### [BLOCKER] Missing Tests for Critical Business Logic
- **Pattern:** Core business functions without test coverage
- **Examples:**
  - Payment processing without tests
  - User authentication without tests
  - Data validation without tests
- **Fix:** Add comprehensive tests for critical business logic
- **Impact:** High - Could lead to production bugs in critical functionality

#### [BLOCKER] No Regression Tests for Bug Fixes
- **Pattern:** Bug fixes without corresponding test cases
- **Examples:**
  - Fixed security vulnerability without test
  - Fixed data corruption bug without test
- **Fix:** Add regression tests that would have caught the original bug
- **Impact:** High - Bug could be reintroduced in future changes

#### [BLOCKER] Critical User Workflows Untested
- **Pattern:** End-to-end user journeys without test coverage
- **Examples:**
  - User registration flow without tests
  - Checkout process without tests
  - Password reset flow without tests
- **Fix:** Add integration or E2E tests for critical user workflows
- **Impact:** High - Critical user functionality could break

### Compatibility Blockers

#### [BLOCKER] Breaking API Changes Without Versioning
- **Pattern:** API changes that break existing clients
- **Examples:**
  - Removing required fields from API responses
  - Changing field types without migration
- **Fix:** Implement API versioning or backward compatibility
- **Impact:** High - Could break existing integrations

#### [BLOCKER] Database Schema Changes Without Migration
- **Pattern:** Database changes that could cause data loss
- **Examples:**
  - Dropping columns without migration
  - Changing column types without conversion
- **Fix:** Create proper database migrations
- **Impact:** High - Could cause data loss or application crashes

### Performance Blockers

#### [BLOCKER] N+1 Query Patterns
- **Pattern:** Database queries in loops causing performance issues
- **Examples:**
  - `users.forEach(user => db.query('SELECT * FROM posts WHERE user_id = ?', user.id))`
- **Fix:** Use batch queries or include related data in initial query
- **Impact:** High - Could cause severe performance degradation

#### [BLOCKER] Large I/O Operations Not Streamed
- **Pattern:** Loading large files or datasets into memory
- **Examples:**
  - `fs.readFileSync()` for large files
  - Loading entire datasets into memory
- **Fix:** Use streaming or chunked processing
- **Impact:** High - Could cause memory exhaustion

### Build and CI Blockers

#### [BLOCKER] Build Failures
- **Pattern:** Code that doesn't compile or build
- **Examples:**
  - Syntax errors
  - Missing dependencies
  - Type errors
- **Fix:** Resolve all build errors
- **Impact:** High - Code cannot be deployed

#### [BLOCKER] Linter Failures
- **Pattern:** Code that fails linting checks
- **Examples:**
  - ESLint errors
  - Pylint errors
  - RuboCop errors
- **Fix:** Resolve all linting issues
- **Impact:** High - Code quality standards not met

#### [BLOCKER] Test Suite Failures
- **Pattern:** Tests that fail in CI/CD pipeline
- **Examples:**
  - Unit test failures
  - Integration test failures
  - E2E test failures
- **Fix:** Fix all failing tests
- **Impact:** High - Code quality cannot be verified

## Review Process

### How to Identify Merge Blockers
1. **Security Review:** Scan for hardcoded secrets, injection vulnerabilities, missing auth
2. **Performance Review:** Check for N+1 queries, memory leaks, unbounded operations
3. **Testing Review:** Verify critical path coverage, regression tests
4. **Quality Review:** Ensure build passes, linting clean, tests pass

### Escalation Process
1. **Immediate:** Block merge for any [BLOCKER] issues
2. **Documentation:** Clearly explain why each issue is a blocker
3. **Resolution:** Provide specific fix recommendations
4. **Verification:** Require re-review after fixes are applied

### Exception Process
- **Emergency Fixes:** Only for critical production issues
- **Approval Required:** Senior developer or security team approval
- **Documentation:** Must document why exception was granted
- **Follow-up:** Must address blocker in next release
