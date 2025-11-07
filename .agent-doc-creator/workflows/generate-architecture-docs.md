# Generate Architecture Documentation Workflow

This workflow creates comprehensive architecture documentation based on repository scan results.

## Prerequisites

- Repository scan completed (`docs/.docs-metadata.json` exists)
- Docusaurus installed and configured
- Write permissions to `docs/architecture/` directory

## Workflow Steps

### 1. Load Scan Results

Read `docs/.docs-metadata.json` to get:
- Component list
- Dependencies
- Technology stack
- Infrastructure setup

### 2. Check for Existing Docs

For each document to generate:
- Check if file exists
- Check for `human_reviewed: true` flag
- Check for human edit markers
- Load existing content if preserving edits

### 3. Generate Architecture Overview

Create `docs/architecture/overview.md` with:
- System purpose and context
- Key components list
- High-level architecture diagram (Mermaid)
- Technology stack summary
- Data flow overview
- External dependencies
- Security considerations
- Scalability approach

**Include**:
- Clear AI-generated disclaimer
- Frontmatter with metadata
- Mermaid diagram showing system architecture
- Links to component docs

### 4. Generate Component Documentation

For each major component, create `docs/architecture/{component-name}.md`:
- Component overview and responsibility
- Key files and entry points
- Internal and external dependencies
- Data model (if applicable)
- API endpoints (if applicable)
- Configuration requirements
- Observability setup
- Development instructions
- Known issues and TODOs

### 5. Create Architecture Diagrams

Generate Mermaid diagrams for:
- System architecture (high-level)
- Component relationships
- Data flow
- Deployment architecture

### 6. Preserve Human Edits

If `respect_human_edits: true`:
- Preserve content between `<!-- HUMAN_EDIT_START/END -->` markers
- Skip files with `human_reviewed: true` (unless forced)
- Merge preserved content into new docs
- Update `.human-edits.json`

### 7. Update Frontmatter

Ensure all docs have:
```yaml
---
title: Component Name
sidebar_position: 1
ai_generated: true
last_updated: 2024-11-07
component_type: backend-service
tags: [architecture, component]
---
```

### 8. Update Sidebars

Add new architecture docs to `sidebars.js`:
```javascript
{
  type: 'category',
  label: 'Architecture',
  items: [
    'architecture/overview',
    'architecture/api-service',
    'architecture/auth-service',
    // ... more components
  ],
}
```

### 9. Validate Generated Docs

- Check for broken internal links
- Verify Mermaid diagrams are valid
- Ensure frontmatter is correct
- Test that docs build successfully

### 10. Generate Summary

Create summary of generated docs:
- Number of files created/updated
- Components documented
- Diagrams generated
- Any warnings or issues

## Output Files

- `docs/architecture/overview.md` - System overview
- `docs/architecture/{component}.md` - Component docs (one per component)
- Updated `sidebars.js`
- Updated `docs/.human-edits.json` (if edits preserved)

## Incremental Updates

If `incremental_updates: true`:
1. Load previous scan results
2. Compare file hashes
3. Identify changed components
4. Only regenerate docs for changed components
5. Update `last_updated` timestamp

## Error Handling

- **Scan data missing**: Run scan-repository workflow first
- **Component info incomplete**: Generate with TODO markers
- **Diagram generation fails**: Include text description instead
- **File write fails**: Log error, continue with other files

## Next Steps

After successful generation:
1. Review generated architecture docs
2. Proceed to generate ADRs
3. Continue with other documentation types

