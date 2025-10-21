# Generate Comprehensive Review Report

## Step 1: Aggregate Findings from All Reviewers

Collect and organize findings from specialized reviewers:

### Security Reviewer Findings
- Critical security vulnerabilities
- Security compliance issues
- Dependency vulnerabilities
- Authentication/authorization gaps

### Performance Reviewer Findings
- Performance bottlenecks
- Memory management issues
- Query optimization opportunities
- Resource management problems

### Test Coverage Reviewer Findings
- Missing test coverage
- Critical path testing gaps
- Regression test requirements
- Test quality issues

### Code Quality Reviewer Findings
- Code maintainability issues
- Documentation gaps
- Style compliance problems
- Architecture concerns

## Step 2: Classify Issues by Severity

### Merge Blockers (Must Fix Before Merge)
- Security vulnerabilities that could be exploited
- Performance issues that could cause system failure
- Missing tests for critical business logic
- Build/CI failures
- Compliance violations

### Suggestions (Good to Have)
- Code improvements that enhance maintainability
- Performance optimizations
- Documentation enhancements
- Architecture improvements
- Additional test coverage

### Nits (Can Ignore)
- Minor style inconsistencies
- Grammar in comments
- Subjective naming preferences
- Micro-optimization suggestions
- Non-critical documentation issues

## Step 3: Generate Executive Summary

Create high-level overview:
- Total issues found by category
- Critical action items requiring immediate attention
- Overall review status and recommendation
- Risk assessment and impact analysis

## Step 4: Create Detailed Findings Report

### Security Issues Section
- Critical vulnerabilities with exploit potential
- Security compliance gaps
- Dependency vulnerabilities
- Authentication/authorization issues
- Input validation problems

### Performance Issues Section
- Performance bottlenecks and optimization opportunities
- Memory management issues
- Database query inefficiencies
- Resource management problems
- Scalability concerns

### Testing Issues Section
- Missing test coverage for critical paths
- Regression test requirements
- Test quality and organization issues
- Integration testing gaps
- Test performance problems

### Code Quality Issues Section
- Code maintainability concerns
- Documentation gaps
- Style and formatting issues
- Architecture improvements
- Error handling problems

## Step 5: Generate Action Items

### Immediate Action Items (Merge Blockers)
- Security fixes requiring immediate attention
- Performance issues that could cause failures
- Missing critical tests
- Build/CI fixes
- Compliance requirements

### Follow-up Action Items (Suggestions)
- Code improvements for future iterations
- Performance optimizations
- Documentation updates
- Architecture enhancements
- Additional testing

### Monitoring Recommendations
- Areas requiring ongoing attention
- Metrics to track
- Review frequency recommendations
- Quality gates to implement

## Step 6: Create Review Report Template

Generate comprehensive report using:

{{workflows/review/review-report-template}}

## Step 7: Final Review Assessment

Provide overall review status:

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

## Review Report Output

Generate final report with:

### Executive Summary
- Overall review status: [APPROVE | APPROVE WITH FOLLOW-UP | REQUIRES FIXES]
- Total issues: [X] blockers, [Y] suggestions, [Z] nits
- Critical action items: [List]
- Risk assessment: [High | Medium | Low]

### Merge Blockers (Must Fix)
- [BLOCKER] Issue description and location
- [BLOCKER] Security vulnerability details
- [BLOCKER] Performance bottleneck information
- [BLOCKER] Missing test coverage details

### Suggestions (Good to Have)
- [SUGGESTION] Code improvement recommendations
- [SUGGESTION] Performance optimization opportunities
- [SUGGESTION] Documentation enhancements
- [SUGGESTION] Architecture improvements

### Nits (Can Ignore)
- [NIT] Minor style inconsistencies
- [NIT] Documentation formatting
- [NIT] Subjective preferences
- [NIT] Micro-optimizations

### Action Items
1. **Immediate (Merge Blockers)**
   - Fix security vulnerabilities
   - Resolve performance issues
   - Add missing critical tests
   - Fix build/CI failures

2. **Follow-up (Suggestions)**
   - Implement code improvements
   - Add performance optimizations
   - Enhance documentation
   - Improve architecture

3. **Monitoring**
   - Track identified metrics
   - Schedule follow-up reviews
   - Implement quality gates
   - Monitor for regressions
