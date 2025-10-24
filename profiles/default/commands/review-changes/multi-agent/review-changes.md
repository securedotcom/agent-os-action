# Code Changes Review Process

You are reviewing specific code changes (pull request, commit, or file changes) to identify security vulnerabilities, performance issues, testing gaps, and code quality problems. This review will focus on the changed code and generate a detailed review report.

## Multi-Phase Review Process

### PHASE 1: Analyze Changes and Identify Affected Areas

Use the **review-orchestrator** subagent to analyze the changes and identify which specialized reviewers are needed.

The review-orchestrator will:
- Analyze the git diff or changed files
- Identify affected areas (security, performance, testing, quality)
- Determine which specialized reviewers to engage
- Plan the review approach

### PHASE 2: Delegate to Relevant Specialized Reviewers

Based on the changes, delegate to appropriate specialized reviewers:

#### Security Review (if security-related changes)
Use the **security-reviewer** subagent for:
- Authentication/authorization changes
- Input validation modifications
- Database query changes
- API endpoint modifications
- Configuration changes
- Dependency updates

#### Performance Review (if performance-related changes)
Use the **performance-reviewer** subagent for:
- Database query modifications
- Algorithm changes
- Memory management changes
- I/O operation modifications
- Caching implementations
- Resource management changes

#### Test Coverage Review (if testing-related changes)
Use the **test-coverage-reviewer** subagent for:
- New feature implementations
- Bug fixes
- API endpoint changes
- Business logic modifications
- Integration changes
- Database schema changes

#### Code Quality Review (if quality-related changes)
Use the **code-quality-reviewer** subagent for:
- Code style changes
- Documentation updates
- Architecture modifications
- Error handling changes
- Configuration updates
- Refactoring changes

### PHASE 3: Generate PR Review Report

Use the **review-orchestrator** subagent to:
- Aggregate findings from all engaged reviewers
- Classify issues by severity (merge blockers, suggestions, nits)
- Generate inline comments for the PR
- Create review summary with recommendations
- Provide approval recommendation

## Review Output

Upon completion, the following will be generated:

### Inline Comments
- **[BLOCKER]** Critical issues that must be fixed before merge
- **[SUGGESTION]** Recommended improvements
- **[NIT]** Minor issues that can be ignored

### Review Summary
- Overall review status (APPROVE | APPROVE WITH FOLLOW-UP | REQUIRES FIXES)
- Summary of findings by category
- Action items for the author
- Follow-up recommendations

## Review Scope

The review will focus on:

### Security Review (if applicable)
- Hardcoded secrets in changed code
- Injection vulnerabilities in new queries
- Authentication/authorization changes
- Input validation modifications
- Cryptographic security changes
- Dependency security updates

### Performance Review (if applicable)
- N+1 query patterns in new code
- Memory management in changes
- Algorithm efficiency in modifications
- I/O performance in new operations
- Resource management in changes
- Scalability impact of modifications

### Testing Review (if applicable)
- Test coverage for new functionality
- Regression tests for bug fixes
- Test quality for new tests
- Critical path testing for changes
- Test organization for new test files
- Test performance for new test suites

### Code Quality Review (if applicable)
- Linting compliance for changed code
- Code maintainability in modifications
- Documentation quality in changes
- Architecture consistency in updates
- Error handling in new code
- Configuration management in changes

## Review Standards

All reviews will be conducted according to:

{{standards/review/merge-blockers}}
{{standards/review/security-checklist}}
{{standards/review/performance-checklist}}
{{standards/review/testing-checklist}}
{{standards/review/observability-checklist}}

## Review Timeline

- **Phase 1 (Analysis):** 5-10 minutes
- **Phase 2 (Specialized Reviews):** 10-30 minutes
- **Phase 3 (Report Generation):** 5-10 minutes
- **Total Estimated Time:** 20-50 minutes

## Review Decision Criteria

### APPROVE
- No merge blockers found
- All critical issues addressed
- Code meets quality standards
- Ready for merge

### APPROVE WITH FOLLOW-UP
- Minor issues that can be addressed post-merge
- Non-critical improvements identified
- Follow-up action items documented
- Acceptable risk level

### REQUIRES FIXES
- Merge blockers must be resolved
- Critical issues require immediate attention
- Security or performance risks identified
- Not ready for merge

## Review Output Format

Generate review using:

{{workflows/review/pr-review-template}}

## Success Criteria

The review is considered successful when:
- All critical issues in changed code are identified
- Performance impact of changes is assessed
- Test coverage for changes is validated
- Code quality of changes is evaluated
- Clear recommendations are provided
- Human approval decision is made

## Next Steps

After the review is complete:
1. Author addresses merge blockers
2. Author considers suggestions for improvement
3. Re-review if significant changes made
4. Approve and merge when ready
5. Track follow-up action items

## Output to User

Upon completion, display:

"Code changes review completed successfully!

✅ Security analysis completed
✅ Performance analysis completed  
✅ Test coverage analysis completed
✅ Code quality analysis completed
✅ Review report generated

📋 Review Status: [APPROVE | APPROVE WITH FOLLOW-UP | REQUIRES FIXES]

👉 Review the inline comments and summary for detailed feedback."
