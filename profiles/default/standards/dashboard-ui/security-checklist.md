# Dashboard/UI Security Checklist

## XSS Prevention
- [ ] **Input Sanitization**: All user inputs sanitized
- [ ] **Output Encoding**: HTML/JS/CSS contexts properly encoded
- [ ] **DOM Manipulation**: Safe DOM APIs used
- [ ] **dangerouslySetInnerHTML**: Avoided or properly sanitized

## Authentication & Session
- [ ] **Token Storage**: JWT stored securely (httpOnly cookies)
- [ ] **Session Timeout**: Auto-logout after inactivity
- [ ] **CSRF Protection**: CSRF tokens on state-changing forms
- [ ] **Secure Cookies**: Secure and HttpOnly flags set

## Content Security
- [ ] **CSP Headers**: Content-Security-Policy configured
- [ ] **Trusted Sources**: Only load resources from trusted domains
- [ ] **Inline Scripts**: Minimize or eliminate inline JavaScript
- [ ] **Frame Protection**: X-Frame-Options set

## Data Protection
- [ ] **Sensitive Data**: No PII in client-side storage
- [ ] **API Keys**: No API keys in frontend code
- [ ] **Environment Variables**: Secrets not in build artifacts
- [ ] **HTTPS**: All requests over HTTPS

## Merge Blockers
- **[BLOCKER]** XSS vulnerabilities (unescaped user input)
- **[BLOCKER]** API keys or secrets in frontend code
- **[BLOCKER]** Sensitive data in localStorage/sessionStorage
- **[BLOCKER]** Missing CSRF protection on forms
- **[BLOCKER]** HTTP requests to production APIs

