# Test Quality Checklist

Ensure all generated tests meet these quality standards.

## Test Structure

- [ ] Clear, descriptive test names
- [ ] Test purpose documented in docstring/comment
- [ ] Links to vulnerability ID/ticket
- [ ] Follows project test conventions
- [ ] Uses appropriate test framework

## Test Coverage

- [ ] Tests the vulnerability is blocked
- [ ] Tests legitimate functionality still works
- [ ] Tests edge cases and boundary conditions
- [ ] Tests various attack payloads
- [ ] Tests error handling

## Test Quality

- [ ] Tests are independent (no shared state)
- [ ] Tests are repeatable (deterministic)
- [ ] Tests are fast (< 1 second each)
- [ ] Tests have clear pass/fail criteria
- [ ] Tests clean up after themselves

## Security Test Specifics

- [ ] Tests validate security control is enforced
- [ ] Tests verify sensitive data is not exposed
- [ ] Tests check authentication/authorization
- [ ] Tests validate input sanitization
- [ ] Tests verify proper error messages (no info disclosure)

## Code Quality

- [ ] No hardcoded credentials or secrets
- [ ] No hardcoded production URLs
- [ ] Proper use of test fixtures/mocks
- [ ] Clear assertion messages
- [ ] Follows code style guidelines

## Documentation

- [ ] Usage instructions provided
- [ ] Expected behavior documented
- [ ] References to security standards
- [ ] Explanation of what is being tested
- [ ] Links to related vulnerabilities

## Integration

- [ ] Tests added to appropriate test suite
- [ ] Tests run in CI/CD pipeline
- [ ] Tests marked with appropriate tags/categories
- [ ] Tests integrated with coverage reports
