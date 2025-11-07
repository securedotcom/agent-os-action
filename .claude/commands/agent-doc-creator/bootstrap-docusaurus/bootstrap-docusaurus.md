# Bootstrap Docusaurus

Initialize Docusaurus documentation site in this project.

## What This Command Does

1. Checks if Docusaurus is already installed
2. If not present:
   - Installs Docusaurus dependencies
   - Creates configuration files
   - Sets up initial sidebar structure
   - Creates intro page
   - Adds npm scripts
   - Updates .gitignore
3. Verifies installation with test build

## When to Use

Use this command when:
- Project doesn't have Docusaurus yet
- Want to set up documentation site
- Need to initialize docs infrastructure
- Starting documentation from scratch

## What Gets Created

### Configuration Files
- `docusaurus.config.js` - Main Docusaurus configuration
- `sidebars.js` - Sidebar structure with doc categories
- `docs/intro.md` - Landing page

### Package Updates
- Adds Docusaurus dependencies to `package.json`
- Adds documentation scripts:
  - `docs:start` - Start dev server
  - `docs:build` - Build for production
  - `docs:serve` - Serve built site

### Directory Structure
```
docs/
├── intro.md
├── architecture/
├── adrs/
├── rfcs/
├── playbooks/
├── ml/
└── references/
```

## Workflow

{{workflows/bootstrap-docusaurus}}

## Output

- Docusaurus installed and configured
- Initial documentation structure
- npm scripts for documentation
- Test build completed successfully

## Next Steps

After bootstrapping:
1. Customize `docusaurus.config.js` with your project details
2. Run `npm run docs:start` to view the site locally
3. Run the `generate-docs` command to populate with content
4. Deploy to GitHub Pages, Netlify, or Vercel

## Configuration

The bootstrap process creates a minimal configuration. You can customize:
- Site title and tagline
- Theme colors
- Navbar items
- Footer content
- Plugins and features

See [Docusaurus documentation](https://docusaurus.io/) for full customization options.

## Requirements

- Node.js 18 or higher
- npm or yarn
- Git repository

## Troubleshooting

### Installation Fails
- Check Node.js version: `node --version`
- Try with `--legacy-peer-deps`: `npm install --legacy-peer-deps`
- Clear npm cache: `npm cache clean --force`

### Build Fails
- Check for conflicting dependencies
- Review error messages in console
- Verify all required files are present

