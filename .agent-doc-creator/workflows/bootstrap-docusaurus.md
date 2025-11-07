# Bootstrap Docusaurus Workflow

This workflow initializes Docusaurus in a project that doesn't have it yet.

## When to Run

- Docusaurus not detected in project
- `bootstrap_docusaurus: true` in configuration
- Manual request to initialize docs

## Prerequisites

- Node.js 18+ installed
- npm or yarn available
- Write permissions to project directory

## Workflow Steps

### 1. Check for Existing Installation

**Check for**:
- `docusaurus.config.js` (or `.ts`, `.cjs`, `.mjs`)
- `sidebars.js` (or `.ts`, `.cjs`, `.mjs`)
- `@docusaurus/core` in `package.json`

**If found**: Skip bootstrap, proceed to configuration update

### 2. Install Docusaurus Dependencies

```bash
# Add Docusaurus packages
npm install @docusaurus/core @docusaurus/preset-classic @docusaurus/theme-mermaid

# Or with yarn
yarn add @docusaurus/core @docusaurus/preset-classic @docusaurus/theme-mermaid
```

### 3. Create Docusaurus Configuration

Create `docusaurus.config.js` with:
- Basic site metadata
- Docs-only mode (no blog)
- Mermaid diagram support
- Dark/light theme
- Sidebar configuration

### 4. Create Initial Sidebars

Create `sidebars.js` with categories for:
- Architecture
- ADRs
- RFCs
- Runbooks
- ML & Models
- References

### 5. Create Intro Page

Create `docs/intro.md` as the landing page

### 6. Add npm Scripts

Add to `package.json`:
```json
{
  "scripts": {
    "docs:start": "docusaurus start",
    "docs:build": "docusaurus build",
    "docs:serve": "docusaurus serve"
  }
}
```

### 7. Create .gitignore Entries

Add to `.gitignore`:
```
# Docusaurus
.docusaurus/
build/
node_modules/
```

### 8. Verify Installation

```bash
# Test build
npm run docs:build

# Check for errors
echo $?
```

### 9. Create README Section

Add documentation section to project README

## Output Files

- `docusaurus.config.js` - Main configuration
- `sidebars.js` - Sidebar structure
- `docs/intro.md` - Landing page
- `package.json` - Updated with scripts and dependencies
- `.gitignore` - Updated with Docusaurus entries

## Error Handling

- **Node.js not found**: Prompt to install Node.js 18+
- **npm install fails**: Check network, try with --legacy-peer-deps
- **Build fails**: Check for conflicting dependencies

## Next Steps

After successful bootstrap:
1. Verify Docusaurus starts: `npm run docs:start`
2. Proceed with documentation generation
3. Commit Docusaurus configuration to git

