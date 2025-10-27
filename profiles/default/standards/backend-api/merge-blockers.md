# Backend API Merge Blockers

## Security Blockers
- **[BLOCKER]** Hardcoded credentials, API keys, or secrets
- **[BLOCKER]** SQL injection vulnerabilities
- **[BLOCKER]** Missing authentication on protected endpoints
- **[BLOCKER]** Authorization bypass vulnerabilities
- **[BLOCKER]** Sensitive data exposed in logs or responses
- **[BLOCKER]** Plaintext password storage

## Performance Blockers
- **[BLOCKER]** N+1 query patterns
- **[BLOCKER]** Missing database indexes causing full table scans
- **[BLOCKER]** Memory leaks
- **[BLOCKER]** Resource leaks (connections, file handles)
- **[BLOCKER]** API endpoints taking >5 seconds
- **[BLOCKER]** No pagination on large result sets

## Code Quality Blockers
- **[BLOCKER]** Broken build or failing tests
- **[BLOCKER]** Critical bugs in production code paths
- **[BLOCKER]** Deprecated API usage without migration plan
- **[BLOCKER]** Missing error handling in critical paths
- **[BLOCKER]** Thread safety issues in concurrent code

## Testing Blockers
- **[BLOCKER]** No tests for new business logic
- **[BLOCKER]** Missing security tests for auth/authz changes
- **[BLOCKER]** No regression tests for critical bug fixes
- **[BLOCKER]** Test coverage drops below 70%

