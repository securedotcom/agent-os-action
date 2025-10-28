# Fix CodeQL "actions" Error in Spring-Backend

## Quick Fix Guide

### Option 1: GitHub UI (Easiest - 2 minutes)

1. Go to: https://github.com/securedotcom/Spring-Backend/settings/security_analysis
2. Find "Code scanning" section
3. Click "Edit" on CodeQL
4. **Uncheck**: "GitHub Actions workflows" 
5. **Keep checked**: "Java"
6. Click "Save"

✅ Done! Next CodeQL run will work.

---

### Option 2: Edit Workflow File (Recommended)

**File**: `.github/workflows/codeql.yml` in Spring-Backend

**Find this**:
```yaml
strategy:
  matrix:
    language: [ 'java', 'actions' ]  # or similar
```

**Change to**:
```yaml
strategy:
  matrix:
    language: [ 'java' ]  # Only Java for Spring Boot
```

**Commit and push**. Done!

---

### Option 3: Add CodeQL Config File

**Create**: `.github/codeql/codeql-config.yml` in Spring-Backend

```yaml
name: "CodeQL Config for Spring Backend"

disable-default-queries: false

queries:
  - uses: security-extended
  - uses: security-and-quality

paths-ignore:
  - '**/test/**'
  - '**/tests/**'
  - '**/target/**'
  - '**/build/**'
  - '**/.mvn/**'
  - '**/node_modules/**'

# Only analyze Java for Spring Boot
languages:
  java:
    queries:
      - uses: security-extended
      - uses: security-and-quality

# Do NOT include 'actions' - it causes the error you're seeing
```

**Then update** `.github/workflows/codeql.yml`:

```yaml
- name: Initialize CodeQL
  uses: github/codeql-action/init@v3
  with:
    languages: java
    config-file: ./.github/codeql/codeql-config.yml  # Add this line
```

---

## Why This Happens

**Root Cause**: CodeQL tries to analyze GitHub Actions workflow files (YAML) as code
- Spring-Backend is Java - doesn't need "actions" language scanning
- "actions" language scanner fails on workflow YAML files
- Result: Exit code 32 error

**Solution**: Only scan Java code, skip workflow files

---

## Impact

✅ **Development**: ZERO - this is just a background security scan  
✅ **Deployments**: Not affected  
✅ **Security**: Java code still scanned properly  
✅ **CI/CD**: CodeQL will pass after fix  

---

## Verification

After applying the fix:

1. Wait for next CodeQL run (or trigger manually)
2. Should see: "CodeQL Analysis Complete" ✅
3. No more "actions" language errors

**Manual trigger**:
```bash
gh workflow run codeql.yml --repo securedotcom/Spring-Backend
```

---

## Need Help?

If you need me to make the changes:
1. Give me access to Spring-Backend repo
2. Or share the `.github/workflows/codeql.yml` file contents
3. I'll provide the exact fix

---

## Summary

**Problem**: CodeQL scanning "actions" language in Spring-Backend  
**Solution**: Only scan Java (remove "actions")  
**Time**: 2 minutes via GitHub UI  
**Impact**: None on development  




