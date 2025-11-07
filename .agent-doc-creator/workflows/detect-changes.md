# Detect Changes Workflow

This workflow implements incremental documentation updates by detecting what changed since last scan.

## Prerequisites

- Previous scan results exist (`docs/.docs-metadata.json`)
- Git repository with history
- Read permissions to all files

## Workflow Steps

### 1. Load Previous Scan

Read `docs/.docs-metadata.json`:
- Last scan timestamp
- File hashes
- Component mappings
- Generated documentation list

### 2. Calculate Current Hashes

For all key files, calculate SHA-256 hash:
```bash
sha256sum file.ts
```

**Key files include**:
- Source code files
- Configuration files
- Infrastructure files
- Database migrations
- API specifications

### 3. Compare Hashes

For each file:
```javascript
if (current_hash !== previous_hash) {
  changed_files.push(file);
}
```

### 4. Map Changes to Components

Using component-to-file mappings:
```json
{
  "api-service": ["services/api/**"],
  "auth-service": ["services/auth/**"]
}
```

Determine which components changed:
```javascript
for (file of changed_files) {
  component = find_component_for_file(file);
  changed_components.add(component);
}
```

### 5. Identify Documentation to Regenerate

Based on changed components:

**Architecture docs**:
- Regenerate overview if system structure changed
- Regenerate component docs for changed components

**ADRs**:
- Check if new decisions detected
- Don't regenerate existing ADRs

**RFCs**:
- Check for new refactoring opportunities
- Update existing RFCs if relevant code changed

**Runbooks**:
- Regenerate for changed services
- Update if deployment config changed

**ML docs**:
- Regenerate if model files changed
- Update if training code changed

**References**:
- Regenerate if config files changed
- Update if env vars added/removed

### 6. Check for Human Edits

For each file to regenerate:
- Check `human_reviewed: true` flag
- Check for edit markers
- Load from `.human-edits.json`

**If human edited**:
- Skip regeneration (unless forced)
- Or preserve human edits during regeneration

### 7. Generate Change Report

```markdown
# Change Detection Report

**Scan Date**: 2024-11-07 10:30:00
**Previous Scan**: 2024-11-01 09:15:00
**Days Since Last Scan**: 6

## Changed Files (15)

### Source Code (10)
- services/api/src/routes.ts
- services/api/src/controllers/users.ts
- services/auth/main.go
- ...

### Configuration (3)
- config/app.yml
- k8s/deployment.yml
- .github/workflows/ci.yml

### Infrastructure (2)
- docker-compose.yml
- terraform/main.tf

## Changed Components (2)

- **api-service**: 8 files changed
- **auth-service**: 2 files changed

## Documentation to Regenerate

### Architecture (2 files)
- ✅ docs/architecture/api-service.md
- ✅ docs/architecture/auth-service.md
- ⏭️  docs/architecture/overview.md (no changes)

### ADRs (0 files)
- No new decisions detected

### RFCs (1 file)
- ✅ docs/rfcs/rfc-0001-api-refactor-draft.md (related code changed)

### Runbooks (2 files)
- ✅ docs/playbooks/api-service.md
- ✅ docs/playbooks/auth-service.md

### ML Docs (0 files)
- No ML components changed

### References (1 file)
- ✅ docs/references/config-index.md (config changed)

## Human-Edited Files (2)

These files will be preserved:
- docs/architecture/api-service.md (deployment section)
- docs/adrs/0001-database.md (entire file)

## Summary

- **Total files to regenerate**: 6
- **Files to preserve**: 2
- **Estimated time**: 2 minutes
```

### 8. Update Metadata

After regeneration, update `docs/.docs-metadata.json`:
```json
{
  "last_scan": "2024-11-07T10:30:00Z",
  "file_hashes": {
    "services/api/src/routes.ts": "new_hash...",
    "services/auth/main.go": "new_hash..."
  },
  "changed_components": ["api-service", "auth-service"],
  "docs_regenerated": [
    "docs/architecture/api-service.md",
    "docs/architecture/auth-service.md",
    "docs/playbooks/api-service.md",
    "docs/playbooks/auth-service.md",
    "docs/references/config-index.md",
    "docs/rfcs/rfc-0001-api-refactor-draft.md"
  ]
}
```

### 9. Skip Unchanged Components

For components with no changes:
- Skip architecture doc regeneration
- Skip runbook regeneration
- Preserve existing documentation

### 10. Force Full Regeneration (Optional)

If `--force-full-regeneration` flag:
- Ignore change detection
- Regenerate all documentation
- Update all file hashes

## Output

- Change detection report
- List of files to regenerate
- Updated metadata file
- Preserved human edits

## Configuration

From `config.yml`:

```yaml
incremental_updates: true
force_full_regeneration: false
respect_human_edits: true
```

## Benefits of Incremental Updates

1. **Faster**: Only regenerate what changed
2. **Safer**: Preserves human edits
3. **Efficient**: Reduces unnecessary changes
4. **Targeted**: Focused PRs with relevant changes

## Error Handling

- **No previous scan**: Run full scan
- **Metadata corrupted**: Run full scan
- **Hash calculation fails**: Log warning, assume changed

## Next Steps

After change detection:
1. Review change report
2. Proceed with targeted regeneration
3. Skip unchanged documentation
4. Preserve human edits

