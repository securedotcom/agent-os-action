# Validate Documentation Workflow

This workflow validates generated documentation for errors and quality issues.

## Prerequisites

- Documentation generated
- Docusaurus configured
- Node.js and npm available

## Workflow Steps

### 1. Validate Internal Links

Check all markdown links:
```bash
find docs/ -name "*.md" -exec grep -H "\[.*\](.*\.md)" {} \;
```

For each link:
- Verify target file exists
- Check relative path is correct
- Validate anchor links

**Report**: List of broken internal links

### 2. Validate External Links

Extract and check external URLs:
```bash
grep -roh "http[s]*://[^)]*" docs/
```

For each URL:
- Send HEAD request
- Check HTTP status code
- Record response time

**Thresholds**:
- 200-299: ✅ Success
- 300-399: ⚠️  Redirect
- 400-499: ❌ Client error
- 500-599: ❌ Server error
- Timeout (>10s): ⚠️  Warning

**Report**: List of broken/slow external links

### 3. Validate Code Examples

Extract and validate code blocks:

**JavaScript/TypeScript**:
```bash
node --check code-snippet.js
```

**Python**:
```bash
python -m py_compile code-snippet.py
```

**YAML**:
```bash
python -c "import yaml; yaml.safe_load(open('snippet.yml'))"
```

**JSON**:
```bash
jq empty snippet.json
```

**Report**: List of invalid code examples

### 4. Validate Mermaid Diagrams

Extract and validate Mermaid:
```bash
mmdc -i diagram.mmd -o /dev/null
```

**Report**: List of invalid diagrams

### 5. Validate Frontmatter

Check all docs have required frontmatter:
- `title` (required)
- `sidebar_position` (optional, must be number)
- `ai_generated` (optional, must be boolean)
- Valid YAML syntax

**Report**: List of frontmatter errors

### 6. Check Formatting

Look for common issues:
- Headers without space after `#`
- Code blocks without language
- Trailing whitespace
- Multiple blank lines

**Report**: List of formatting issues

### 7. Check Accessibility

Validate:
- Images have alt text
- Links have descriptive text
- Heading hierarchy is correct
- No skipped heading levels

**Report**: List of accessibility issues

### 8. Run Docusaurus Build

```bash
npm run docs:build
```

Capture:
- Build success/failure
- Build warnings
- Build time

**Report**: Build results

### 9. Generate Validation Report

Compile all results:

```markdown
# Documentation Validation Report

**Generated**: 2024-11-07 10:30:00
**Total Files**: 45
**Status**: ✅ PASS | ⚠️  WARNINGS | ❌ FAIL

## Summary

- ✅ Internal Links: 123/123 valid
- ⚠️  External Links: 45/50 valid (5 timeouts)
- ✅ Code Examples: 67/67 valid
- ✅ Mermaid Diagrams: 10/10 valid
- ✅ Frontmatter: 45/45 valid
- ⚠️  Formatting: 3 warnings
- ⚠️  Accessibility: 2 warnings
- ✅ Docusaurus Build: Success

## Critical Issues (0)

None ✅

## Warnings (10)

### External Link Timeouts (5)
- docs/references/api.md:45 - https://slow-api.com
- ...

### Formatting Issues (3)
- docs/playbooks/deployment.md:23 - Code block without language
- ...

### Accessibility Issues (2)
- docs/architecture/overview.md:67 - Image without alt text
- ...

## Recommendations

1. Update slow external links
2. Add language to code blocks
3. Add alt text to images
```

### 10. Determine Pass/Fail

**Fail PR if**:
- Broken internal links
- Invalid code examples
- Invalid Mermaid diagrams
- Docusaurus build fails

**Warn but pass if**:
- External link timeouts
- Formatting issues
- Accessibility concerns

### 11. Save Validation Results

Save to:
- `docs/.validation-report.md` - Full report
- `docs/.validation-results.json` - Machine-readable results

### 12. Add to PR Description

Include validation summary in PR description

## Output

- Validation report (markdown)
- Validation results (JSON)
- Exit code (0 = pass, 1 = fail)
- PR comment with results

## Validation Levels

### Critical (Fail PR)
- Broken internal links
- Invalid code syntax
- Invalid Mermaid diagrams
- Missing required frontmatter
- Build failures

### Warnings (Don't Fail)
- External link issues
- Formatting problems
- Accessibility concerns
- Missing optional frontmatter

## Configuration

From `config.yml`:

```yaml
validate_links: true
validate_code_examples: true
run_docusaurus_build_check: true
fail_on_warnings: false
```

## Error Handling

- **Validation tool missing**: Install or skip that check
- **Timeout**: Continue with other checks
- **Unexpected error**: Log and continue

## Next Steps

After validation:
1. Review validation report
2. Fix critical issues
3. Consider addressing warnings
4. Re-run validation if changes made
5. Proceed to create PR if passing

