# Backend API Security Checklist

## Overview
Security standards specific to backend API projects (Spring Boot, REST APIs, microservices).

---

## Authentication & Authorization

### Required Checks
- [ ] **Authentication on Protected Endpoints** - All sensitive endpoints must require authentication
- [ ] **Authorization Validation** - User permissions checked before resource access
- [ ] **JWT Token Validation** - Tokens properly validated and not expired
- [ ] **Session Management** - Secure session handling with timeout
- [ ] **API Key Security** - API keys not hardcoded, properly rotated

### Merge Blockers
- **[BLOCKER]** Missing authentication on endpoints that handle sensitive data
- **[BLOCKER]** Authorization bypass vulnerabilities
- **[BLOCKER]** Hardcoded credentials or API keys

---

## Input Validation

### Required Checks
- [ ] **SQL Injection Prevention** - Parameterized queries used everywhere
- [ ] **NoSQL Injection Prevention** - Query sanitization for MongoDB, etc.
- [ ] **Path Traversal Prevention** - File path inputs validated
- [ ] **Command Injection Prevention** - No direct command execution with user input
- [ ] **XML External Entity (XXE) Prevention** - XML parsing secured

### Merge Blockers
- **[BLOCKER]** SQL injection vulnerabilities
- **[BLOCKER]** Command injection vulnerabilities
- **[BLOCKER]** Path traversal vulnerabilities

---

## Data Protection

### Required Checks
- [ ] **Sensitive Data Encryption** - Passwords, tokens, PII encrypted at rest
- [ ] **TLS/SSL Usage** - HTTPS enforced for all endpoints
- [ ] **Secure Password Storage** - BCrypt/Argon2 used for password hashing
- [ ] **Data Sanitization** - Output encoding to prevent XSS
- [ ] **Secrets Management** - Environment variables or vault for secrets

### Merge Blockers
- **[BLOCKER]** Plaintext password storage
- **[BLOCKER]** Sensitive data exposed in logs
- **[BLOCKER]** API secrets hardcoded in source code

---

## API Security

### Required Checks
- [ ] **Rate Limiting** - API endpoints protected from abuse
- [ ] **CORS Configuration** - Properly configured Cross-Origin Resource Sharing
- [ ] **Content-Type Validation** - Request content types validated
- [ ] **Request Size Limits** - Maximum request size enforced
- [ ] **Error Handling** - No sensitive information in error responses

### Suggestions
- **[SUGGESTION]** Implement request throttling per user/IP
- **[SUGGESTION]** Add API versioning strategy
- **[SUGGESTION]** Implement request/response logging (sanitized)

---

## Database Security

### Required Checks
- [ ] **Prepared Statements** - No string concatenation for SQL queries
- [ ] **Least Privilege** - Database users have minimum required permissions
- [ ] **Connection Security** - Database connections encrypted
- [ ] **Transaction Management** - Proper rollback on errors
- [ ] **Audit Logging** - Sensitive operations logged

### Merge Blockers
- **[BLOCKER]** Dynamic SQL with user input concatenation
- **[BLOCKER]** Database credentials in code
- **[BLOCKER]** No transaction boundaries for critical operations

---

## Security Headers

### Required Checks
- [ ] **Content-Security-Policy** - CSP header configured
- [ ] **X-Content-Type-Options** - nosniff enabled
- [ ] **X-Frame-Options** - Clickjacking protection
- [ ] **Strict-Transport-Security** - HSTS enabled
- [ ] **X-XSS-Protection** - XSS filter enabled

### Suggestions
- **[SUGGESTION]** Implement comprehensive CSP policy
- **[SUGGESTION]** Add Referrer-Policy header
- **[SUGGESTION]** Configure Feature-Policy/Permissions-Policy

---

## Dependency Security

### Required Checks
- [ ] **Dependency Scanning** - Known vulnerabilities identified
- [ ] **Outdated Dependencies** - Critical dependencies up to date
- [ ] **License Compliance** - Dependency licenses reviewed
- [ ] **Transitive Dependencies** - Indirect dependencies audited

### Merge Blockers
- **[BLOCKER]** Critical CVEs in direct dependencies
- **[BLOCKER]** Known malicious packages

---

## Spring-Specific Security

### Required Checks
- [ ] **Spring Security Configuration** - Properly configured security filters
- [ ] **CSRF Protection** - Enabled for state-changing operations
- [ ] **Method-Level Security** - @PreAuthorize/@Secured annotations used
- [ ] **Password Encoding** - BCryptPasswordEncoder configured
- [ ] **Remember-Me Security** - Token-based remember-me if used

### Merge Blockers
- **[BLOCKER]** Spring Security disabled on protected endpoints
- **[BLOCKER]** CSRF protection disabled without justification
- **[BLOCKER]** Weak password encoder (plain text, MD5)

---

## Testing Requirements

### Required Checks
- [ ] **Security Test Coverage** - Security scenarios tested
- [ ] **Authentication Tests** - Login/logout flows tested
- [ ] **Authorization Tests** - Permission checks tested
- [ ] **Input Validation Tests** - Injection attempts tested
- [ ] **Integration Tests** - Security configuration tested

### Suggestions
- **[SUGGESTION]** Add penetration testing
- **[SUGGESTION]** Implement automated security scanning in CI
- **[SUGGESTION]** Add chaos engineering for security

---

## Logging & Monitoring

### Required Checks
- [ ] **Security Event Logging** - Failed auth attempts logged
- [ ] **Audit Trail** - Sensitive operations auditable
- [ ] **Log Sanitization** - No sensitive data in logs
- [ ] **Monitoring Alerts** - Security events trigger alerts
- [ ] **Log Protection** - Logs protected from tampering

### Suggestions
- **[SUGGESTION]** Implement centralized logging (ELK, Splunk)
- **[SUGGESTION]** Add anomaly detection
- **[SUGGESTION]** Set up security dashboards

---

## Common Vulnerabilities (OWASP Top 10)

### Critical Checks
- [ ] **A01 Broken Access Control** - Access controls properly implemented
- [ ] **A02 Cryptographic Failures** - Encryption used correctly
- [ ] **A03 Injection** - All injection types prevented
- [ ] **A04 Insecure Design** - Security considered in design
- [ ] **A05 Security Misconfiguration** - Secure defaults used
- [ ] **A06 Vulnerable Components** - Dependencies up to date
- [ ] **A07 Authentication Failures** - Strong authentication implemented
- [ ] **A08 Data Integrity Failures** - Data validation in place
- [ ] **A09 Logging Failures** - Adequate logging implemented
- [ ] **A10 SSRF** - Server-side request forgery prevented

---

## Review Process

### For Each PR
1. Run static security analysis (SonarQube, Snyk)
2. Verify all blockers addressed
3. Check test coverage includes security scenarios
4. Review changes for common vulnerabilities
5. Validate secrets not committed

### Merge Criteria
- Zero **[BLOCKER]** security issues
- All authentication/authorization changes tested
- Security review completed for high-risk changes
- Dependency scan passed

