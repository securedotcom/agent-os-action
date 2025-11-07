# Generate Documentation

Generate comprehensive documentation for this repository including architecture docs, ADRs, RFCs, runbooks, ML documentation, and configuration references.

## What This Command Does

1. Scans the repository to discover components and dependencies
2. Bootstraps Docusaurus if not present
3. Generates architecture documentation with diagrams
4. Creates ADRs for detected technical decisions
5. Drafts RFCs for improvement opportunities
6. Generates operational runbooks
7. Creates ML documentation (if ML components detected)
8. Builds configuration and environment variable references
9. Updates Docusaurus sidebars
10. Validates generated documentation
11. Creates a pull request with all changes

## Prerequisites

- Repository is a Git repository
- Node.js 18+ installed (for Docusaurus)
- Write permissions to create branches and PRs

## Usage

Simply run this command in your project directory. The agent will:
- Analyze your codebase
- Generate appropriate documentation
- Create a PR for review

## Configuration

The documentation generation can be configured via `docs.agent.config.json` in your project root or the base `config.yml`.

Key settings:
- `docs_root`: Where docs are stored (default: `docs`)
- `bootstrap_docusaurus`: Auto-setup Docusaurus (default: `true`)
- `sections`: Which doc types to generate
- `incremental_updates`: Only regenerate changed docs (default: `true`)
- `respect_human_edits`: Preserve manual edits (default: `true`)

## Workflow

{{workflows/scan-repository}}

{{workflows/bootstrap-docusaurus}}

{{workflows/generate-architecture-docs}}

{{workflows/generate-adrs}}

{{workflows/generate-rfcs}}

{{workflows/generate-runbooks}}

{{workflows/generate-ml-docs}}

{{workflows/generate-references}}

{{workflows/update-sidebars}}

{{workflows/validate-docs}}

{{workflows/create-docs-pr}}

## Output

- Generated documentation in `docs/` directory
- Updated `docusaurus.config.js` and `sidebars.js`
- Git branch with changes
- Pull request ready for review

## Review

All generated documentation includes an AI disclaimer and should be reviewed before merging:
- Verify architecture docs accurately reflect the system
- Validate ADR decisions and reasoning
- Review RFC proposals for feasibility
- Test runbook procedures
- Check ML documentation metrics
- Ensure no secrets are exposed in configuration references

## Next Steps

After the PR is created:
1. Review the generated documentation
2. Test any procedures or commands
3. Validate technical accuracy
4. Approve and merge the PR
5. Deploy the documentation site

