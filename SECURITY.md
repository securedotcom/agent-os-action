# Security Policy

## 🛡️ Security Overview

Agent OS Code Reviewer takes security seriously. This document outlines our security practices, vulnerability reporting process, and the multiple layers of protection we employ.

## 🔒 Layered Security Approach

We use a **defense-in-depth** strategy with multiple complementary security tools:

### 1. **AI-Powered Analysis** (Our Core)
- Claude Sonnet 4 for intelligent code review
- Detects complex security issues, logic flaws, and architectural problems
- Context-aware analysis beyond pattern matching

### 2. **Static Analysis (CodeQL)**
- Automated SAST scanning for Python and JavaScript
- Detects common vulnerabilities (injection, XSS, etc.)
- Runs on every push and PR

### 3. **Secret Scanning (Gitleaks)**
- Scans for hardcoded secrets, API keys, tokens
- Checks full git history
- Runs daily for continuous monitoring

### 4. **Repository Health (OpenSSF Scorecard)**
- Evaluates 20+ security best practices
- Checks branch protection, code review, dependency management
- Runs weekly with public results

### 5. **Supply Chain Integrity (Attestations)**
- Signed release attestations with SLSA provenance
- SBOM (Software Bill of Materials) for transparency
- Verifiable with `gh attestation verify`

## 🔍 Security Scanning Schedule

| Tool | Frequency | Purpose |
|------|-----------|---------|
| **CodeQL** | Every push, PR, weekly | SAST scanning |
| **Gitleaks** | Every push, PR, daily | Secret detection |
| **Scorecard** | Weekly | Repo hygiene |
| **Attestation** | Every release | Supply chain |

## 📊 Security Badges

View our current security posture:

- **OpenSSF Scorecard**: [![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/securedotcom/agent-os-action/badge)](https://securityscorecards.dev/viewer/?uri=github.com/securedotcom/agent-os-action)
- **CodeQL**: Check the [Security tab](https://github.com/securedotcom/agent-os-action/security/code-scanning) for latest results

## 🚨 Reporting a Vulnerability

We take all security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### How to Report

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, please report via one of these methods:

1. **GitHub Security Advisories** (Preferred)
   - Go to: https://github.com/securedotcom/agent-os-action/security/advisories/new
   - Click "Report a vulnerability"
   - Provide details in the private advisory

2. **Email**
   - Send to: security@securedotcom.com
   - Use subject: `[SECURITY] Agent OS Code Reviewer - <brief description>`
   - Include:
     - Description of the vulnerability
     - Steps to reproduce
     - Potential impact
     - Suggested fix (if any)

3. **Private Disclosure via GitHub**
   - Contact: @waseem.ahmed (repository maintainer)
   - Request a private discussion

### What to Include

Please provide:
- **Description**: Clear explanation of the vulnerability
- **Impact**: What an attacker could do
- **Reproduction**: Step-by-step instructions
- **Affected Versions**: Which versions are vulnerable
- **Suggested Fix**: If you have ideas (optional)
- **Your Contact**: How we can reach you for clarification

### Response Timeline

We aim to respond within:
- **24 hours**: Initial acknowledgment
- **7 days**: Preliminary assessment and severity rating
- **30 days**: Fix development and testing
- **90 days**: Public disclosure (coordinated with reporter)

### Severity Levels

We use CVSS 3.1 for severity ratings:

| Severity | CVSS Score | Response Time |
|----------|------------|---------------|
| **Critical** | 9.0-10.0 | 24-48 hours |
| **High** | 7.0-8.9 | 7 days |
| **Medium** | 4.0-6.9 | 30 days |
| **Low** | 0.1-3.9 | 90 days |

## 🏆 Security Acknowledgments

We appreciate security researchers who help keep Agent OS secure. Responsible disclosure will be acknowledged in:
- Release notes
- SECURITY.md (this file)
- GitHub Security Advisories

### Hall of Fame

*No vulnerabilities reported yet. Be the first!*

## 🔐 Security Best Practices for Users

When using Agent OS Code Reviewer:

### 1. **API Key Management**
```yaml
# ✅ GOOD: Use GitHub Secrets
- uses: securedotcom/agent-os-action@v1
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}

# ❌ BAD: Hardcoded keys
- uses: securedotcom/agent-os-action@v1
  with:
    anthropic-api-key: sk-ant-api03-...  # NEVER DO THIS
```

### 2. **Pin Action Versions**
```yaml
# ✅ GOOD: Pin to specific version
- uses: securedotcom/agent-os-action@v1.0.0

# ⚠️ ACCEPTABLE: Use major version tag
- uses: securedotcom/agent-os-action@v1

# ❌ BAD: Use main branch
- uses: securedotcom/agent-os-action@main
```

### 3. **Least Privilege Permissions**
```yaml
# ✅ GOOD: Minimal permissions
permissions:
  contents: read
  pull-requests: write
  security-events: write

# ❌ BAD: Overly broad
permissions: write-all
```

### 4. **Review Findings**
- Don't blindly trust AI findings
- Verify critical security issues manually
- Use AI as a **supplement** to human review, not a replacement

### 5. **Data Privacy**
- Review what code is sent to AI providers
- Use `exclude-paths` to skip sensitive files
- Consider local Ollama for air-gapped environments

## 🔄 Security Update Process

### For Users

1. **Watch Releases**: Click "Watch" → "Custom" → "Releases" on GitHub
2. **Review Changelogs**: Check CHANGELOG.md for security fixes
3. **Update Promptly**: Update to latest versions when security fixes are released
4. **Test Updates**: Test in a non-production environment first

### For Maintainers

1. **Dependency Updates**: Automated via Dependabot
2. **Security Patches**: Prioritized and released ASAP
3. **Disclosure**: Coordinated with reporters
4. **Communication**: Via GitHub Security Advisories and release notes

## 📚 Security Resources

- **GitHub Security Features**: https://docs.github.com/en/code-security
- **SLSA Framework**: https://slsa.dev/
- **OpenSSF Best Practices**: https://bestpractices.coreinfrastructure.org/
- **OWASP Top 10**: https://owasp.org/www-project-top-ten/

## 🛠️ Security Tools We Use

| Tool | Purpose | Documentation |
|------|---------|---------------|
| **CodeQL** | SAST scanning | [GitHub CodeQL](https://codeql.github.com/) |
| **Gitleaks** | Secret detection | [Gitleaks](https://github.com/gitleaks/gitleaks) |
| **OpenSSF Scorecard** | Repo health | [Scorecard](https://github.com/ossf/scorecard) |
| **GitHub Attestations** | Supply chain | [Attestations](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds) |
| **Dependabot** | Dependency updates | [Dependabot](https://docs.github.com/en/code-security/dependabot) |

## 📞 Contact

- **Security Issues**: security@securedotcom.com
- **General Questions**: Open a GitHub Discussion
- **Bug Reports**: Open a GitHub Issue (non-security only)

## 📜 License

This security policy is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

---

**Last Updated**: October 27, 2025  
**Version**: 1.0.0

