# Map Attack Surface Workflow

## Objective
Systematically identify and document all attack vectors and entry points in the application.

## Steps

### 1. Identify Entry Points

**Public API Endpoints**:
- Use Grep to find route definitions:
  - Express: `app.get(`, `app.post(`, `router.`
  - Flask/FastAPI: `@app.route(`, `@router.`
  - Spring: `@GetMapping`, `@PostMapping`, `@RequestMapping`
  - Django: `path(`, `url(`
- Document each endpoint's authentication requirements
- Note which endpoints are public vs. authenticated

**User Input Points**:
- Form submissions
- Search functionality
- File uploads
- API parameters (query, body, headers)
- WebSocket messages
- GraphQL queries

**External Integrations**:
- Webhook endpoints
- OAuth callbacks
- Third-party API calls
- Payment gateway integrations
- Email/SMS handling

### 2. Map Trust Boundaries

Identify transitions between trust levels:

**Authentication Boundaries**:
- Public → Authenticated user
- Authenticated user → Admin
- User → System/root
- Guest → Registered user

**Network Boundaries**:
- External → DMZ
- DMZ → Internal network
- Client → Server
- Server → Database

**Process Boundaries**:
- User process → System process
- Web server → Application server
- Application → Database

### 3. Trace Data Flow

For each entry point, trace data flow:
```
User Input → Validation → Processing → Storage → Output
```

Identify where validation happens (or doesn't):
- Is input validated on entry?
- Is output encoded before display?
- Are queries parameterized?
- Is data sanitized before storage?

### 4. Document Attack Vectors

For each entry point, document potential attack vectors:

```markdown
### Entry Point: POST /api/users/search

**Authentication**: None (public endpoint) ⚠️
**Input Parameters**:
- `query` (string, no length limit) ⚠️
- `limit` (integer, no validation) ⚠️

**Data Flow**:
1. Request → Controller (no validation) ⚠️
2. Controller → Database (string concatenation) 🚨 SQL INJECTION
3. Database → Response (full results returned)

**Attack Vectors**:
- SQL Injection via `query` parameter (CRITICAL)
- NoSQL Injection if database is NoSQL
- Denial of Service via large `limit` values
- Information disclosure via error messages

**Trust Boundary**: None (unauthenticated) ⚠️

**Risk Level**: CRITICAL
```

### 5. Prioritize by Risk

Rank entry points by risk:
1. **Critical**: Unauthenticated + injection vulnerability
2. **High**: Authenticated + privilege escalation potential
3. **Medium**: Authenticated + information disclosure
4. **Low**: Authenticated + minor issues

## Output Format

```markdown
## Attack Surface Analysis

### Summary
- **Total Entry Points**: 24
- **Critical Risk**: 3 ⚠️
- **High Risk**: 8 🟨
- **Medium Risk**: 10 🟦
- **Low Risk**: 3 ⬜

### Critical Entry Points

1. **POST /api/users/search** (Unauthenticated)
   - SQL Injection vulnerability
   - No input validation
   - Full database access possible
   - **Exploitability**: ⚠️ Trivial

2. **POST /api/auth/login** (Public)
   - No rate limiting
   - Weak password policy
   - Credential brute-forcing possible
   - **Exploitability**: 🟨 Moderate

3. **POST /api/files/upload** (Authenticated)
   - No file type validation
   - Arbitrary file upload
   - Remote code execution possible
   - **Exploitability**: 🟨 Moderate

### Trust Boundary Issues

1. **Weak Authentication Boundary**
   - SQL injection bypasses authentication (VULN-001)
   - Hardcoded credentials in source (VULN-002)
   - **Impact**: Complete authentication bypass

2. **Missing Authorization Checks**
   - IDOR in user profile endpoints (VULN-005)
   - No role-based access control
   - **Impact**: Unauthorized data access

### Attack Vector Map

```
Public Network
    ↓
[Entry: /api/users/search] ← SQL Injection (VULN-001)
    ↓
[Bypass: Authentication] ← Hardcoded creds (VULN-002)
    ↓
[Access: User data] ← IDOR (VULN-005)
    ↓
[Escalate: Admin] ← Missing RBAC (VULN-008)
    ↓
[Exfiltrate: Database] ← No rate limiting (VULN-012)
```

### Data Flow Vulnerabilities

**Untrusted Input → Trusted Process**:
- 8 endpoints with no input validation
- 5 endpoints with SQL/NoSQL injection risks
- 3 file upload endpoints with no type checking

**Sensitive Data Exposure**:
- Error messages expose stack traces
- API responses include internal IDs
- Logs contain PII and credentials
```
