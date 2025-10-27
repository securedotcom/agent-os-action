# Enable GitHub Code Scanning

This guide explains how to enable GitHub Code Scanning to view Agent OS security findings in the Security tab.

## 📋 Prerequisites

- Repository admin access
- GitHub Advanced Security enabled (for private repos)

## 🚀 Quick Setup (2 Minutes)

### Step 1: Enable Code Scanning

1. Go to your repository on GitHub
2. Click **Settings** → **Code security and analysis**
3. Scroll to **Code scanning**
4. Click **Set up** → **Default**

GitHub will automatically:
- Detect your languages
- Schedule weekly scans
- Enable SARIF uploads

### Step 2: Verify Setup

After the next Agent OS workflow run:

1. Go to **Security** → **Code scanning**
2. You should see findings from `agent-os-code-review`
3. Findings will also appear in PR checks

## 📊 What You'll Get

Once enabled, Agent OS findings will appear in:

- ✅ **Security Tab** - All findings in one place
- ✅ **Pull Requests** - Inline annotations on changed code
- ✅ **Security Overview** - Organization-wide dashboard
- ✅ **Dependency Graph** - Integration with other security tools

## 🔧 Advanced Configuration

### Custom CodeQL Configuration

If you want to customize CodeQL analysis alongside Agent OS:

Create `.github/codeql/codeql-config.yml`:

```yaml
name: "CodeQL Config"

# Exclude test files from analysis
paths-ignore:
  - '**/test/**'
  - '**/tests/**'
  - '**/*_test.go'
  - '**/*.test.js'

# Include additional queries
queries:
  - uses: security-extended
  - uses: security-and-quality
```

Update your workflow:

```yaml
- name: Initialize CodeQL
  uses: github/codeql-action/init@v3
  with:
    config-file: .github/codeql/codeql-config.yml
```

### SARIF Upload Customization

The Agent OS action outputs SARIF files. You can customize the upload:

```yaml
- name: Run Agent OS Code Review
  id: agent
  uses: securedotcom/agent-os-action@v2
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}

- name: Upload SARIF to Code Scanning
  if: always() && steps.agent.outputs.sarif-path != ''
  continue-on-error: true  # Don't fail if Code Scanning not enabled
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ${{ steps.agent.outputs.sarif-path }}
    category: agent-os-code-review
    # Optional: Add checkout path for monorepos
    # checkout_path: ${{ github.workspace }}/services/backend
```

## 🏢 Enterprise Setup

### For Organization Admins

Enable Code Scanning for all repositories:

1. Go to **Organization Settings** → **Code security and analysis**
2. Enable **Code scanning** for all repositories
3. Choose **Default setup** or **Advanced setup**
4. Select which repositories to include

### For Private Repositories

Code Scanning requires **GitHub Advanced Security**:

1. Go to **Settings** → **Billing and plans**
2. Enable **GitHub Advanced Security**
3. Costs: Free for public repos, $49/committer/month for private repos

## 🐛 Troubleshooting

### Error: "Code Security must be enabled"

**Solution**: Follow Step 1 above to enable Code Scanning.

### SARIF Upload Fails

**Check**:
1. Code Scanning is enabled (Settings → Code security)
2. Workflow has `security-events: write` permission
3. SARIF file exists and is valid JSON

**Workflow permissions**:
```yaml
permissions:
  contents: read
  security-events: write  # Required for SARIF upload
  pull-requests: write
```

### Findings Not Appearing

**Verify**:
1. Workflow completed successfully
2. SARIF file was uploaded (check workflow logs)
3. Go to **Security** → **Code scanning** → **Tool** → Select "agent-os-code-review"

### "No analysis found" Message

This means no security issues were found - that's good! 🎉

## 📚 Additional Resources

- [GitHub Code Scanning Docs](https://docs.github.com/en/code-security/code-scanning)
- [SARIF Specification](https://sarifweb.azurewebsites.net/)
- [CodeQL Documentation](https://codeql.github.com/docs/)
- [GitHub Advanced Security](https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security)

## 🆘 Need Help?

- **Agent OS Issues**: [GitHub Issues](https://github.com/securedotcom/agent-os-action/issues)
- **Code Scanning Issues**: [GitHub Support](https://support.github.com/)
- **Enterprise Support**: enterprise@agent-os.dev

---

**Next Steps**: Once Code Scanning is enabled, run your Agent OS workflow again to see findings in the Security tab!

