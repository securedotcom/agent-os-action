# Code Reviewer System - Developer Guide

## 🎯 Quick Start

The code reviewer system is now implemented and ready for use. Here's how to get started:

### **Available Commands**
```bash
# Full codebase audit
/audit-codebase

# Review specific changes/PR
/review-changes

# Quick security scan
/security-scan
```

## 🏗️ Architecture Overview

### **Multi-Agent System**
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Security        │    │ Performance      │    │ Test Coverage   │
│ Reviewer        │    │ Reviewer         │    │ Reviewer        │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │ Code Quality     │
                    │ Reviewer         │
                    └─────────────────┘
                                 │
                    ┌─────────────────┐
                    │ Review          │
                    │ Orchestrator    │
                    └─────────────────┘
```

### **Review Flow**
1. **Orchestrator** analyzes codebase and delegates to specialized reviewers
2. **Specialized Reviewers** perform focused analysis in parallel
3. **Orchestrator** aggregates findings and classifies by severity
4. **Human Review** required for all recommendations
5. **Action Items** generated with prioritized fixes

## 🔍 Review Categories

### **Security Review**
- **Secrets Detection**: Hardcoded API keys, passwords, tokens
- **Injection Vulnerabilities**: SQL, NoSQL, Command, Template injection
- **Authentication/Authorization**: Missing auth, weak auth, IDOR vulnerabilities
- **Cryptographic Security**: Hardcoded salts, weak algorithms, key management
- **Dependency Security**: CVE scanning, license compliance

### **Performance Review**
- **Database Queries**: N+1 patterns, missing indexes, query optimization
- **Memory Management**: Leaks, unbounded collections, resource cleanup
- **Algorithm Efficiency**: Time complexity, redundant calculations
- **I/O Performance**: Streaming, network calls, file operations
- **Resource Management**: Connection pooling, caching, timeouts

### **Test Coverage Review**
- **Critical Path Testing**: Business logic, user workflows, API endpoints
- **Regression Testing**: Bug fixes, feature changes, breaking changes
- **Test Quality**: Organization, maintainability, performance
- **Test Coverage**: Minimum coverage requirements, gap analysis

### **Code Quality Review**
- **Linting/Style**: Code formatting, naming conventions, style compliance
- **Maintainability**: Function size, complexity, readability
- **Documentation**: Comments, README, API documentation
- **Architecture**: Design patterns, coupling, cohesion
- **Error Handling**: Exception handling, logging, monitoring

## 📊 Severity Classification

### **🔴 [BLOCKER] - Must Fix Before Merge**
- Security vulnerabilities that could be exploited
- Performance issues that could cause system failure
- Missing tests for critical business logic
- Build/CI failures
- Compliance violations

### **🟡 [SUGGESTION] - Good to Have**
- Code improvements that enhance maintainability
- Performance optimizations
- Documentation enhancements
- Architecture improvements
- Additional test coverage

### **🔵 [NIT] - Can Ignore**
- Minor style inconsistencies
- Grammar in comments
- Subjective naming preferences
- Micro-optimization suggestions
- Non-critical documentation issues

## 🛠️ Configuration

### **Reviewer Roles** (`profiles/default/roles/reviewers.yml`)
```yaml
reviewers:
  - id: security-reviewer
    description: Comprehensive security review
    areas_of_responsibility:
      - Secrets detection
      - Injection vulnerability detection
      - Authentication and authorization review
      - Cryptographic security validation
    standards:
      - review/merge-blockers
      - review/security-checklist
```

### **Standards Customization**
- **Merge Blockers**: Define what constitutes a merge blocker
- **Security Checklist**: Customize security requirements
- **Performance Checklist**: Set performance standards
- **Testing Checklist**: Define test coverage requirements
- **Observability Checklist**: Configure logging and monitoring standards

## 📝 Usage Examples

### **Full Codebase Audit**
```bash
# Run comprehensive audit
/audit-codebase

# Output: Comprehensive report in agent-os/reviews/[date]-codebase-audit/
```

### **PR Review**
```bash
# Review specific changes
/review-changes

# Output: Inline comments with severity tags
```

### **Security Scan**
```bash
# Quick security-focused scan
/security-scan

# Output: Security report with immediate action items
```

## 🔧 Customization

### **Adding Custom Standards**
1. Create new standards file in `profiles/default/standards/review/`
2. Reference in reviewer configuration
3. Update reviewer areas of responsibility

### **Adding New Reviewers**
1. Create new reviewer agent in `profiles/default/agents/`
2. Add to `profiles/default/roles/reviewers.yml`
3. Update orchestrator to include new reviewer

### **Customizing Workflows**
1. Modify workflow files in `profiles/default/workflows/review/`
2. Update command files to use new workflows
3. Test with sample codebase

## 📈 Best Practices

### **For Development Teams**
- Run security scans before each release
- Use PR reviews for all code changes
- Schedule regular full audits
- Address merge blockers immediately
- Plan follow-up for suggestions

### **For Security Teams**
- Focus on [BLOCKER] issues first
- Use security-scan for quick assessments
- Integrate with CI/CD pipeline
- Monitor for new vulnerabilities
- Update standards regularly

### **For DevOps Teams**
- Monitor performance recommendations
- Implement observability improvements
- Track resource usage patterns
- Optimize based on findings
- Plan capacity improvements

## 🚨 Troubleshooting

### **Common Issues**
- **No reviewers found**: Check `reviewers.yml` configuration
- **Standards not loading**: Verify file paths in standards references
- **Workflow errors**: Check workflow file syntax and references
- **Permission issues**: Ensure proper file permissions

### **Debug Mode**
- Enable verbose logging in reviewer agents
- Check orchestrator coordination logs
- Verify specialized reviewer outputs
- Test individual workflows separately

## 📚 Additional Resources

### **Documentation**
- Agent OS documentation: [Link to docs]
- Review standards: `profiles/default/standards/review/`
- Workflow examples: `profiles/default/workflows/review/`
- Command usage: `profiles/default/commands/`

### **Support**
- GitHub Issues: [Repository issues]
- Documentation: [Agent OS docs]
- Community: [Community forum]

## 🎉 Success Metrics

### **Key Performance Indicators**
- **Security**: Vulnerabilities detected and fixed
- **Performance**: Bottlenecks identified and optimized
- **Quality**: Code maintainability improvements
- **Testing**: Coverage gaps identified and filled

### **Monitoring**
- Review completion time
- Issue resolution rate
- False positive rate
- Team adoption metrics

---

**Ready to use!** 🚀  
**Need help?** Check the troubleshooting section or reach out to the team.

