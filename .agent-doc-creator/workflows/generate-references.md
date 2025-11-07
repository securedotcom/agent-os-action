# Generate References Workflow

This workflow creates configuration and environment variable reference documentation.

## Prerequisites

- Repository scan completed
- Write permissions to `docs/references/` directory

## Workflow Steps

### 1. Identify Configuration Files

From scan results, find:
- Application config files (YAML, JSON, TOML)
- Infrastructure config (Docker, K8s, Terraform)
- Build config (package.json, tsconfig.json)
- CI/CD config (.github/workflows, .gitlab-ci.yml)

### 2. Extract Environment Variables

Search codebase for environment variable usage:

**Node.js**:
```bash
grep -r "process\.env\." --include="*.js" --include="*.ts"
```

**Python**:
```bash
grep -r "os\.getenv\|os\.environ" --include="*.py"
```

**Go**:
```bash
grep -r "os\.Getenv" --include="*.go"
```

**Config files**:
```bash
grep -r "\${.*}" --include="*.yml" --include="*.yaml"
```

### 3. Identify Secrets

Flag variables that appear to be secrets:
- Contains: PASSWORD, SECRET, KEY, TOKEN, PRIVATE
- API keys, auth tokens, credentials

**Critical**: Never expose actual secret values!

### 4. Generate Configuration Index

Create `docs/references/config-index.md`:
- Overview of configuration approach
- List of all config files with:
  - Purpose
  - Location
  - Format
  - Key settings
  - Environment variables used
  - Related documentation

### 5. Generate Environment Variables Reference

Create `docs/references/env-vars.md`:
- Overview
- Required variables (grouped by category)
- Optional variables with defaults
- Environment-specific values
- Setting instructions (local, Docker, K8s, CI/CD)
- Security best practices
- Troubleshooting

**Categories**:
- Database
- Cache
- External Services
- Authentication
- Application Settings
- Performance
- Feature Flags

### 6. Redact Secrets

For all secret values:
- Replace with `[REDACTED]`
- Mark type as "secret"
- Add security warnings
- Never show actual values

### 7. Generate Additional References (Optional)

If applicable:

**API Reference** (`docs/references/api.md`):
- API endpoints
- Request/response schemas
- Authentication
- Rate limiting
- Error codes

**CLI Reference** (`docs/references/cli.md`):
- Command-line tools
- Commands and options
- Usage examples

**Error Codes** (`docs/references/errors.md`):
- Error code catalog
- Descriptions
- Resolution steps

### 8. Update Sidebars

Add references to `sidebars.js`:
```javascript
{
  type: 'category',
  label: 'References',
  items: [
    'references/config-index',
    'references/env-vars',
    'references/api',
    'references/cli',
  ],
}
```

### 9. Validate References

- Verify no secrets exposed
- Check file paths are correct
- Ensure variable names match code
- Validate examples are accurate

## Output Files

- `docs/references/config-index.md` - Configuration catalog
- `docs/references/env-vars.md` - Environment variables
- `docs/references/api.md` - API reference (optional)
- `docs/references/cli.md` - CLI reference (optional)
- Updated `sidebars.js`

## Security Guidelines

1. **Never expose secrets**: Always redact
2. **Mark sensitive vars**: Flag as "secret" type
3. **Add warnings**: Remind about security
4. **Validate output**: Double-check no leaks

## Quality Guidelines

- **Be comprehensive**: List all variables
- **Be accurate**: Match actual code usage
- **Be helpful**: Provide examples (non-sensitive)
- **Be organized**: Group logically

## Error Handling

- **Config file malformed**: Log error, document what's parseable
- **Variable detection incomplete**: Note in docs
- **Secret detection uncertain**: Be conservative, redact if unsure

## Next Steps

After successful generation:
1. Security review for exposed secrets
2. Validate variable names and descriptions
3. Proceed to update sidebars

