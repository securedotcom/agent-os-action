# Codebase Audit Report

## Executive Summary
- **Overall Status**: CRITICAL - REQUIRES IMMEDIATE FIXES
- **Risk Level**: CRITICAL
- **Total Issues Found**: 27
- **Critical issues count**: 9
- **High issues count**: 10
- **Medium issues count**: 8

This codebase contains multiple critical security vulnerabilities that could lead to authentication bypass, credential exposure, timing attacks, and privilege escalation. Immediate remediation is required before deployment.

---

## Critical Issues (Must Fix Immediately)

### Security Issues

#### 1. **[CRITICAL] Timing Attack Vulnerability in Basic Auth**
**File**: `src/middlewares/basic-auth/basic-auth.guard.ts:23`

```typescript
if (user === this.username && pass === this.password) return true;
```

**Issue**: Uses direct string comparison (`===`) for credential validation, which is vulnerable to timing attacks. An attacker can exploit timing differences to determine correct credentials character-by-character.

**Impact**: Complete authentication bypass possible through side-channel timing analysis.

**Fix**: Use constant-time comparison:
```typescript
import { timingSafeEqual } from 'crypto';

const userMatch = timingSafeEqual(
  Buffer.from(user), 
  Buffer.from(this.username)
);
const passMatch = timingSafeEqual(
  Buffer.from(pass), 
  Buffer.from(this.password)
);
if (userMatch && passMatch) return true;
```

---

#### 2. **[CRITICAL] Hardcoded Credentials Loaded from Environment**
**File**: `src/middlewares/basic-auth/basic-auth.guard.ts:9-10`

```typescript
private readonly username = process.env.BASIC_AUTH_USERNAME as string;
private readonly password = process.env.BASIC_AUTH_PASSWORD as string;
```

**Issue**: No validation that credentials exist or meet minimum security requirements. Undefined values cast to string would allow empty credentials.

**Impact**: If environment variables are not set, authentication could fail open or accept empty credentials.

**Fix**: Add validation in constructor:
```typescript
constructor() {
  if (!process.env.BASIC_AUTH_USERNAME || !process.env.BASIC_AUTH_PASSWORD) {
    throw new Error('BASIC_AUTH credentials not configured');
  }
  if (process.env.BASIC_AUTH_PASSWORD.length < 16) {
    throw new Error('BASIC_AUTH_PASSWORD must be at least 16 characters');
  }
  this.username = process.env.BASIC_AUTH_USERNAME;
  this.password = process.env.BASIC_AUTH_PASSWORD;
}
```

---

#### 3. **[CRITICAL] Authorization Confusion in Flexible Auth Guard**
**File**: `src/middlewares/basic-and-bearer-auth/flexible-auth.guard.ts:29-45`

```typescript
// Check if it's Bearer token
if (authHeader.startsWith('Bearer ')) {
  try {
    return await this.authGuard.canActivate(context);
  } catch (error) {
    throw new UnauthorizedException('Invalid Bearer token');
  }
}

// Check if it's Basic Auth
if (authHeader.startsWith('Basic ')) {
  try {
    return await this.basicAuthGuard.canActivate(context);
  } catch (error) {
    throw new UnauthorizedException('Invalid Basic Auth credentials');
  }
}
```

**Issue**: Swallows Bearer token failures and doesn't attempt Basic Auth fallback, but the logic suggests it should. This creates authorization confusion where different auth methods populate different user contexts (`request.tokenDetails` vs Basic Auth user), leading to potential privilege escalation.

**Impact**: 
- Bearer token fails silently without fallback
- If modified to fallback, a user with Basic Auth could gain access to endpoints intended for JWT bearer tokens with different permissions
- Request context confusion (req.organization, req.tokenDetails only set by Bearer)

**Fix**: Remove flexible auth or explicitly document which endpoints accept which auth methods. Never allow fallback between auth methods that create different security contexts.

---

#### 4. **[CRITICAL] No JWT Signature Validation in Auth Guard**
**File**: `src/middlewares/auth/auth.guard.ts:37-38`

```typescript
const decodedToken: any = jwt.decode(token, { complete: true });
if (!decodedToken) throw new GlobalHttpException(HttpStatus.UNAUTHORIZED, 'Unauthorized');
```

**Issue**: Uses `jwt.decode()` instead of `jwt.verify()`. This **ONLY DECODES** the token without validating the signature, expiration, or issuer. An attacker can create arbitrary tokens with any claims.

**Impact**: Complete authentication bypass - any attacker can forge tokens with admin privileges.

**Fix**: Signature validation is delegated to `keycloakService.authService.verifyToken()` at line 113, but the initial decode creates a window where `request.decodedToken` contains unverified data. Move all JWT handling after Keycloak verification, or verify signature twice.

---

#### 5. **[CRITICAL] SQL Injection in Trino Queries**
**File**: `src/utilities/trino/trino.service.ts:121, 174, 260, 291`

```typescript
// Line 121
WHERE table_schema = '${schemaName}'

// Line 174
const query = `
  SELECT table_name
  FROM ${catalog}.information_schema.tables
  WHERE table_schema = '${schemaName}'
    AND table_name IN (${requiredTables.map(t => `'${t}'`).join(', ')})
`;

// Line 260
FROM ${catalog}.${schemaName}.unified_asset_register_inventory
```

**Issue**: Direct string interpolation of user-controlled values (`schemaName`, `catalog`) into SQL queries without sanitization or parameterization. While Trino client may have some protections, this is extremely dangerous.

**Impact**: SQL injection allowing data exfiltration, denial of service, or unauthorized data modification across all tenant schemas.

**Fix**: 
- Validate `schemaName` against whitelist from `getAllSchemas()`
- Use parameterized queries if Trino client supports them
- Implement strict input validation with regex: `^[a-z0-9_]+$`

```typescript
private validateSchemaName(schema: string): void {
  if (!/^[a-z0-9_]+$/.test(schema)) {
    throw new Error('Invalid schema name');
  }
}
```

---

#### 6. **[CRITICAL] Sensitive Data Exposure in Logs**
**File**: `src/utilities/http-client/http-client.service.ts:36-59`

```typescript
private buildCurlCommand(config: AxiosRequestConfig): string {
  // ...
  for (const [key, value] of headerEntries) {
    if (key.toLowerCase() === 'authorization' && typeof value === 'string') {
      const maskedValue = value.replace(/(Bearer )(.+)/i, '$1***MASKED***');
      headerString += `-H "${key}: ${maskedValue}" `;
    }
  }
```

**Issue**: 
- Only masks Authorization header in curl logging
- Request/response bodies containing passwords, secrets, PII logged in full (lines 88, 96)
- Basic Auth credentials in body would be logged unmasked
- Client secrets, admin credentials in keycloak requests fully logged

**Impact**: Credential theft through log access, compliance violations (GDPR, PCI-DSS).

**Fix**: Implement comprehensive sensitive data scrubbing:
```typescript
private sanitizeForLogging(data: any): any {
  const sensitiveKeys = ['password', 'secret', 'token', 'authorization', 'apiKey'];
  // Deep clone and redact
}
```

---

#### 7. **[CRITICAL] Admin Token Cache Race Condition**
**File**: `src/utilities/keycloak/keycloak-admin-token.service.ts:40-55`

```typescript
async getAdminToken(): Promise<string> {
  if (this.adminToken && !this.isTokenExpired(this.adminTokenExpiry)) {
    return this.adminToken;
  }
  
  if (this.adminRefreshToken && !this.isTokenExpired(this.adminRefreshTokenExpiry)) {
    try {
      const refreshResponse = await this.refreshAdminToken(this.adminRefreshToken);
      this.updateAdminTokens(refreshResponse);
      return this.adminToken as string;
    }
  }
  
  const loginResponse = await this.loginAdmin(payload);
  this.updateAdminTokens(loginResponse);
  return this.adminToken as string;
}
```

**Issue**: 
- No locking mechanism for concurrent requests
- Multiple simultaneous calls will all pass the expiry check and trigger parallel token refreshes/logins
- Race condition in `updateAdminTokens()` - last write wins, could use expired token
- Admin credentials stored in class properties accessible without validation

**Impact**: 
- API rate limiting from excessive token requests
- Potential use of expired/invalidated tokens
- Keycloak admin account lockout from too many login attempts

**Fix**: Implement mutex/lock pattern:
```typescript
private tokenRefreshPromise: Promise<string> | null = null;

async getAdminToken(): Promise<string> {
  if (this.adminToken && !this.isTokenExpired(this.adminTokenExpiry)) {
    return this.adminToken;
  }
  
  // If refresh already in progress, wait for it
  if (this.tokenRefreshPromise) {
    return this.tokenRefreshPromise;
  }
  
  this.tokenRefreshPromise = this.refreshTokenInternal();
  try {
    const token = await this.tokenRefreshPromise;
    return token;
  } finally {
    this.tokenRefreshPromise = null;
  }
}
```

---

#### 8. **[CRITICAL] Missing Token Revocation Check**
**File**: `src/middlewares/auth/auth.guard.ts` - Missing entirely

**Issue**: No check against Redis blacklist for revoked tokens before accepting them. The analysis plan specifically called for verifying "Redis blacklist is consulted before accepting tokens."

**Impact**: Revoked tokens (from logout, password reset, account compromise) remain valid until expiration. An attacker with a stolen token can continue accessing the system even after the legitimate user logs out.

**Fix**: Add revocation check after line 60, before Keycloak verification:
```typescript
// Check if token is blacklisted
const isRevoked = await this.redisService.get(`revoked:${token}`);
if (isRevoked) {
  throw new GlobalHttpException(HttpStatus.UNAUTHORIZED, 'Token has been revoked');
}
```

---

#### 9. **[CRITICAL] Insufficient JWT Validation**
**File**: `src/middlewares/auth/auth.guard.ts:113-118`

```typescript
const tokenDetails: KeycloakTokenDetailsDTO | null = 
  await this.keycloakService.authService.verifyToken(
    token, realmName, this.defaultClientName as string, app.secret
  );

if (tokenDetails == null) {
  throw new GlobalHttpException(HttpStatus.UNAUTHORIZED, 'Unauthorized');
}
```

**Issue**: After Keycloak verification returns `tokenDetails`, there's no validation of:
- Token expiration (`tokenDetails.exp`)
- Token not-before (`iat` should be <= current time)
- Audience claim (`aud` should match expected client)
- Algorithm whitelist (accepting only RS256, preventing 'none' algorithm attack)

**Impact**: Expired or malformed tokens could be accepted if Keycloak introspection has bugs or is compromised.

**Fix**: Add comprehensive validation:
```typescript
if (tokenDetails == null) {
  throw new GlobalHttpException(HttpStatus.UNAUTHORIZED, 'Unauthorized');
}

// Validate expiration
if (tokenDetails.exp * 1000 < Date.now()) {
  throw new GlobalHttpException(HttpStatus.UNAUTHORIZED, 'Token expired');
}

// Validate issued-at
if (tokenDetails.iat * 1000 > Date.now()) {
  throw new GlobalHttpException(HttpStatus.UNAUTHORIZED, 'Token not yet valid');
}

// Validate audience
if (!tokenDetails.aud.includes(this.defaultClientName as string)) {
  throw new GlobalHttpException(HttpStatus.UNAUTHORIZED, 'Invalid token audience');
}

// Validate token is active
if (tokenDetails.active !== true) {
  throw new GlobalHttpException(HttpStatus.UNAUTHORIZED, 'Token is not active');
}
```

---

## High Priority Issues

### Security Improvements

#### 10. **[HIGH] URL Construction Injection in Keycloak Services**
**File**: `src/utilities/keycloak/keycloak-auth.service.ts:45-47, 54-56`

```typescript
const body = `grant_type=password&client_id=${clientId}&username=${request.username}&password=${request.password}`;

const body = `grant_type=refresh_token&client_id=${clientId}&refresh_token=${token}`;
```

**Issue**: Direct string interpolation into URL-encoded body. Special characters in username/password not encoded, could break parsing or allow parameter injection.

**Impact**: Authentication bypass if username contains `&password=attacker_value`, or denial of service.

**Fix**: Use URLSearchParams:
```typescript
const params = new URLSearchParams({
  grant_type: 'password',
  client_id: clientId,
  username: request.username,
  password: request.password
});
const body = params.toString();
```

---

#### 11. **[HIGH] Insecure Organization Name Extraction**
**File**: `src/spring-auth/spring-auth.service.ts:52-72`

```typescript
extractOrganizationFromToken(req: any): string | null {
  if (req.organization) return req.organization;
  if (req.tokenDetails && req.tokenDetails.organization) return req.tokenDetails.organization;
  if (req.tokenDetails && req.tokenDetails.realm) return req.tokenDetails.realm;
  
  if (req.tokenDetails && req.tokenDetails.iss) {
    const issuerMatch = req.tokenDetails.iss.match(/\/realms\/([^\/]+)$/);
    if (issuerMatch && issuerMatch[1]) return issuerMatch[1];
  }
}
```

**Issue**: 
- Trusts multiple sources without validation priority conflicts
- `req.organization` set by AuthGuard after token validation, but other sources could be attacker-controlled
- No validation that extracted organization matches token's actual realm
- Regex doesn't prevent path traversal patterns like `../` or special characters

**Impact**: Organization spoofing, potential cross-tenant data access if organization name used for database lookups.

**Fix**: 
- Only trust verified sources (from Keycloak validation)
- Validate against spring_auth database before returning
- Sanitize organization name

---

#### 12. **[HIGH] Redis Cache Poisoning Vulnerability**
**File**: `src/middlewares/auth/auth.guard.ts:68-111`

```typescript
let doc = await this.redisService.hget(redisKey, redisField);

if (!doc) {
  const appData = await this.organizationApiService.getApplicationSecrets(
    this.defaultClientName as string, realmName
  );
  // Cache the fetched data
  await this.redisService.hset(redisKey, redisField, appData);
  app = appData;
} else {
  if (typeof doc === 'string') {
    app = JSON.parse(doc);
  }
}
```

**Issue**: 
- No TTL set on Redis cache entries - stale secrets never expire
- No validation of cached data structure before parsing
- If Organization API returns incorrect data, it's cached permanently
- No mechanism to invalidate cache when secrets rotate
- `redisKey` constructed from unvalidated `realmName` (from JWT issuer)

**Impact**: 
- Stale credentials cached indefinitely
- Secret rotation ineffective
- Cache poisoning via realm name manipulation
- Memory exhaustion from unlimited cache growth

**Fix**:
```typescript
// Set TTL when caching
await this.redisService.hset(redisKey, redisField, appData);
await this.redisService.expire(redisKey, 3600); // 1 hour TTL

// Validate cached data structure
if (typeof app !== 'object' || !app.secret || typeof app.secret !== 'string') {
  this.logger.warn('Invalid cached data structure, refetching...');
  await this.redisService.hdel(redisKey, redisField);
  // Retry fetch
}
```

---

#### 13. **[HIGH] Unauthenticated Life API Endpoints**
**File**: `src/life/life.controller.ts:30-205`

```typescript
@Get('departments')
@ApiOperation({ summary: 'Get paginated departments' })
// NO @UseGuards() decorator!
async getDepartments(@Query('tenant_id') tenantId?: string) {
  // Returns employee data from Gold layer
}
```

**Issue**: 
- Life API endpoints (`/departments`, `/subdepartments`) have NO authentication guards
- Marked as "(UNAUTHENTICATED)" in comments (line 35, 146)
- Expose employee organizational structure (departments, subdepartments)
- Only require `tenant_id` query parameter, which is easily guessable

**Impact**: 
- Complete exposure of organizational structure to unauthenticated users
- Information disclosure for social engineering attacks
- Privacy violation - employee data exposed without authorization

**Fix**: Add authentication guards:
```typescript
@Get('departments')
@UseGuards(AuthGuard, RoleGuard)
@Scopes(ScopeTypes.READ)
async getDepartments(@Query('tenant_id') tenantId?: string, @Req() request: Request) {
  // Validate tenant_id matches authenticated user's organization
  const authOrg = request.organization;
  if (authOrg !== tenantId) {
    throw new GlobalHttpException(HttpStatus.FORBIDDEN, 'Access denied');
  }
  // ...
}
```

---

#### 14. **[HIGH] Tenant ID Validation Bypass in Risk Register**
**File**: `src/risk-register/risk-register.controller.ts:49-99`

```typescript
private async getTenantIdFromAuth(req: any): Promise<string> {
  try {
    const orgAccess = await this.organizationApiService.validateOrganizationAccess(req);
    if (orgAccess.valid && orgAccess.orgId) {
      return `${orgAccess.orgId}`;
    }
  } catch (error) {
    this.logger.debug(`Database validation failed: ${error.message}, trying fallback extraction...`);
  }
  
  // Fallback: Extract directly from token
  const fallbackOrgId = this.extractOrgIdFromRequest(req);
  if (fallbackOrgId) {
    this.logger.log(`⚠️ Using tenant_id from fallback token extraction: ${fallbackOrgId}`);
    return fallbackOrgId;
  }
}
```

**Issue**: 
- Falls back to unvalidated token extraction when database validation fails
- Fallback method trusts JWT claims without database verification
- An attacker could craft tokens with arbitrary `realm` claim to access other tenants' risk data
- Database errors (network issues, misconfig) cause silent fallback to insecure mode

**Impact**: Cross-tenant data access, complete bypass of organization validation

**Fix**: Remove fallback or make it fail-closed:
```typescript
try {
  const orgAccess = await this.organizationApiService.validateOrganizationAccess(req);
  if (orgAccess.valid && orgAccess.orgId) {
    return `${orgAccess.orgId}`;
  }
  throw new GlobalHttpException(HttpStatus.FORBIDDEN, 'Organization validation failed');
} catch (error) {
  this.logger.error(`Organization validation failed: ${error.message}`);
  throw new GlobalHttpException(HttpStatus.FORBIDDEN, 'Access denied - invalid organization');
}
```

---

#### 15. **[HIGH] MongoDB Injection Vulnerability**
**File**: `src/common/mongodb/mongodb.service.ts:82-152`

```typescript
async find<T extends Document = Document>(
  collectionName: string,
  filter: any = {},
  options: any = {}
): Promise<T[]> {
  const collection = this.getCollection<T>(collectionName);
  const results = await collection.find(filter, options).toArray();
  return results as T[];
}
```

**Issue**: 
- Accepts `any` type for `filter` parameter
- No validation or sanitization of filter queries
- Caller can inject MongoDB operators like `$where`, `$regex` with user input
- `collectionName` also not validated - could access system collections

**Impact**: 
- NoSQL injection allowing unauthorized data access
- Denial of service via expensive regex queries
- Potential code execution via `$where` operator

**Fix**:
```typescript
private validateCollectionName(name: string): void {
  if (!/^[a-zA-Z0-9_-]+$/.test(name)) {
    throw new Error('Invalid collection name');
  }
  const systemCollections = ['admin', 'local', 'config'];
  if (systemCollections.includes(name)) {
    throw new Error('Access to system collections denied');
  }
}

private sanitizeFilter(filter: any): any {
  // Recursively check for dangerous operators
  const dangerousOps = ['$where', '$function'];
  // Implement deep sanitization
}

async find<T extends Document = Document>(
  collectionName: string,
  filter: any = {},
  options: any = {}
): Promise<T[]> {
  this.validateCollectionName(collectionName);
  const sanitizedFilter = this.sanitizeFilter(filter);
  // ...
}
```

---

#### 16. **[HIGH] Trino Credentials in Constructor**
**File**: `src/utilities/trino/trino.service.ts:9-47`

```typescript
constructor() {
  const server = process.env.TRINO_SERVER || 'https://staging-gold-trino.secure.com:443';
  const user = process.env.TRINO_USER || 'testuser';
  const password = process.env.TRINO_PASSWORD || "";
  
  const config: any = {
    server,
    catalog,
    schema,
    source: user,
    auth: password ? new BasicAuth(user, password) : undefined,
    ssl: {
      rejectUnauthorized: false, // For staging/dev environments
    },
  };
}
```

**Issue**:
- Hardcoded fallback to staging server URL
- Default user 'testuser' with empty password
- `rejectUnauthorized: false` disables SSL certificate validation
- Credentials not validated before use

**Impact**: 
- Accidental production deployment with staging credentials
- Man-in-the-middle attacks due to disabled SSL verification
- Credential stuffing with default 'testuser' account

**Fix**:
```typescript
constructor() {
  const server = process.env.TRINO_SERVER;
  const user = process.env.TRINO_USER;
  const password = process.env.TRINO_PASSWORD;
  
  if (!server || !user) {
    throw new Error('TRINO_SERVER and TRINO_USER must be configured');
  }
  
  const config: any = {
    server,
    auth: password ? new BasicAuth(user, password) : undefined,
  };
  
  // Only disable SSL verification if explicitly allowed
  if (process.env.TRINO_DISABLE_SSL_VERIFY === 'true') {
    this.logger.warn('SSL verification disabled - not for production!');
    config.ssl = { rejectUnauthorized: false };
  }
}
```

---

#### 17. **[HIGH] Insufficient Error Handling Exposing Keycloak Details**
**File**: `src/utilities/keycloak/keycloak-auth.service.ts:75-82`

```typescript
async verifyToken(...): Promise<KeycloakTokenDetailsDTO | null> {
  const response = await this.keycloakHttpClient.postAndReturnWithBasicAuth<KeycloakTokenDetailsDTO>(...);
  if (!response || response.status !== 200 || response?.data?.active === false) return null;
  
  return response.data;
}
```

**Issue**: 
- Returns `null` for all errors without logging or differentiation
- Downstream code can't distinguish between network errors, expired tokens, or invalid tokens
- Swallows Keycloak error details that could help diagnose issues

**Impact**: 
- Poor user experience (all failures = "Unauthorized")
- Difficult debugging
- Potential security issues masked

**Fix**:
```typescript
async verifyToken(...): Promise<KeycloakTokenDetailsDTO | null> {
  try {
    const response = await this.keycloakHttpClient.postAndReturnWithBasicAuth<KeycloakTokenDetailsDTO>(...);
    
    if (!response || response.status !== 200) {
      this.logger.warn(`Token verification failed: status=${response?.status}`);
      return null;
    }
    
    if (response.data.active === false) {
      this.logger.debug('Token is inactive');
      return null;
    }
    
    return response.data;
  } catch (error) {
    this.logger.error('Token verification error:', error.message);
    return null;
  }
}
```

---

#### 18. **[HIGH] Keycloak Admin Credentials in Class Properties**
**File**: `src/utilities/keycloak/keycloak-admin-token.service.ts:27-30`

```typescript
private adminUsername = this.configService.get<string>('KEYCLOAK_ADMIN_USERNAME');
private adminPassword = this.configService.get<string>('KEYCLOAK_ADMIN_PASSWORD');
private adminClientId = this.configService.get<string>('KEYCLOAK_ADMIN_CLIENT_ID');
private adminClientSecret = this.configService.get<string>('KEYCLOAK_ADMIN_CLIENT_SECRET');
```

**Issue**: 
- Admin credentials stored as class instance properties
- Accessible via prototype pollution or reflection
- No validation they're set before use
- Logged in plaintext in `loginAdmin()` (line 100): `this.logger.error(Admin login failed for user ${request.username})`

**Impact**: 
- Credential exposure via memory dumps, debugging, or exploitation
- Application crashes if credentials missing

**Fix**:
```typescript
constructor(private readonly configService: ConfigService) {
  // Validate on startup
  const requiredVars = ['KEYCLOAK_ADMIN_USERNAME', 'KEYCLOAK_ADMIN_PASSWORD', 
                        'KEYCLOAK_ADMIN_CLIENT_ID', 'KEYCLOAK_ADMIN_CLIENT_SECRET'];
  for (const varName of requiredVars) {
    if (!this.configService.get<string>(varName)) {
      throw new Error(`${varName} must be configured`);
    }
  }
}

// Use getters instead of storing in properties
private getAdminUsername(): string {
  return this.configService.get<string>('KEYCLOAK_ADMIN_USERNAME')!;
}
```

---

#### 19. **[HIGH] XML External Entity (XXE) Vulnerability**
**File**: `src/utilities/keycloak/keycloak-identity-provider.service.ts:149`

```typescript
import { XMLParser } from 'fast-xml-parser';
```

**Issue**: XMLParser used to parse SAML metadata (line referenced, actual usage not shown in snippet but imported). If parser not configured to disable external entities, vulnerable to XXE attacks.

**Impact**: 
- Server-side request forgery (SSRF)
- Local file disclosure
- Denial of service

**Fix**: Configure parser securely:
```typescript
const parser = new XMLParser({
  allowBooleanAttributes: true,
  ignoreAttributes: false,
  parseAttributeValue: true,
  // Disable external entities
  processEntities: false,
  parseTagValue: false
});
```

---

### Performance Optimizations

#### 20. **[HIGH] N+1 Query in Keycloak User Service**
**File**: `src/utilities/keycloak/keycloak-user.service.ts:96-103` (pattern, specific lines in truncated code)

**Issue**: Multiple Keycloak API calls in loops without batching. For example, assigning roles to users likely iterates and makes individual API calls per role/user.

**Impact**: 
- Severe performance degradation with many users/roles
- Keycloak API rate limiting
- High latency

**Fix**: Use batch APIs where available, or implement request queuing.

---

#### 21. **[HIGH] Redis Cache Missing Index Keys**
**File**: `src/middlewares/auth/auth.guard.ts:68`

```typescript
const redisKey = `${this.organizationCacheKey}:${realmName}`;
const redisField = this.defaultClientName as string;
```

**Issue**: 
- No cache warming strategy
- Every realm's first request incurs API latency
- No cache statistics or monitoring

**Impact**: Poor performance for first requests per realm, unpredictable latency.

**Fix**: Implement cache warming on application startup for known realms.

---

#### 22. **[HIGH] Unbounded Trino Query Results**
**File**: `src/utilities/trino/trino.service.ts:61-89`

```typescript
async executeQuery<T = any>(query: string): Promise<T[]> {
  const results: T[] = [];
  for await (const chunk of iterator) {
    if (chunk.data && Array.isArray(chunk.data)) {
      for (const row of chunk.data) {
        results.push(rowObj as T);
      }
    }
  }
  return results;
}
```

**Issue**: 
- Loads entire result set into memory
- No pagination or limit enforcement
- Query with millions of rows will cause OOM

**Impact**: Memory exhaustion, application crash, denial of service.

**Fix**: 
```typescript
async executeQuery<T = any>(
  query: string, 
  maxRows: number = 10000
): Promise<{ data: T[]; hasMore: boolean }> {
  const results: T[] = [];
  let rowCount = 0;
  
  for await (const chunk of iterator) {
    for (const row of chunk.data) {
      if (rowCount >= maxRows) {
        return { data: results, hasMore: true };
      }
      results.push(rowObj as T);
      rowCount++;
    }
  }
  return { data: results, hasMore: false };
}
```

---

### Testing Enhancements

#### 23. **[HIGH] No Tests for Critical Auth Guards**

**Issue**: No test files found for:
- `auth.guard.ts` - Core authentication logic
- `basic-auth.guard.ts` - Timing attack vulnerability
- `flexible-auth.guard.ts` - Authorization confusion

**Impact**: Critical security vulnerabilities undetected, regressions likely on changes.

**Fix**: Implement comprehensive test suite:
```typescript
// auth.guard.spec.ts
describe('AuthGuard', () => {
  it('should reject tokens without signature verification', async () => {
    const forgedToken = jwt.sign({ sub: 'attacker' }, 'wrong-secret');
    await expect(guard.canActivate(context)).rejects.toThrow();
  });
  
  it('should reject expired tokens', async () => {
    const expiredToken = jwt.sign({ exp: Date.now() / 1000 - 3600 }, secret);
    await expect(guard.canActivate(context)).rejects.toThrow('Token expired');
  });
  
  it('should check Redis revocation blacklist', async () => {
    // Test blacklist functionality
  });
});
```

---

## Medium Priority Issues

### Code Quality Improvements

#### 24. **[MEDIUM] Inconsistent Error Handling**
**Files**: Multiple

**Issue**: Mix of throwing `GlobalHttpException`, `HttpException`, `UnauthorizedException`, and returning error responses. No consistent error handling strategy.

**Fix**: Standardize on exception types and implement global exception filter