# Refresh Architecture Documentation

Update architecture documentation only, without regenerating other doc types.

## What This Command Does

1. Scans the repository for changes
2. Identifies changed components
3. Regenerates architecture overview (if system changed)
4. Updates component documentation for changed components
5. Preserves human edits
6. Updates sidebars
7. Creates a focused PR with architecture changes

## When to Use

Use this command when:
- Code architecture has changed
- New services or components added
- Component responsibilities changed
- System diagram needs updating
- Architecture docs are out of date

## Usage

Run this command to update only architecture documentation, skipping ADRs, RFCs, runbooks, and other doc types.

## Workflow

{{workflows/scan-repository}}

{{workflows/detect-changes}}

{{workflows/generate-architecture-docs}}

{{workflows/update-sidebars}}

{{workflows/validate-docs}}

{{workflows/create-docs-pr}}

## Output

- Updated `docs/architecture/overview.md`
- Updated component docs in `docs/architecture/`
- Updated sidebars
- Focused PR with architecture changes only

## Benefits

- Faster than full documentation generation
- Focused changes easier to review
- Preserves other documentation types
- Incremental updates only regenerate what changed

