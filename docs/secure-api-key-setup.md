# Secure API Key Setup Guide

## ⚠️ Security Warning

**NEVER commit API keys to Git!** Always use environment variables or secure secret management.

---

## Quick Start (Recommended)

### Option 1: Using .env File (Local Development)

1. **Create your .env file**:
   ```bash
   cd /Users/waseem.ahmed/Repos/agent-os
   cp .env.example .env
   ```

2. **Add your API key** (edit .env):
   ```bash
   nano .env
   # or
   code .env
   ```

   Replace `your_api_key_here` with your actual key from:
   https://console.anthropic.com/settings/keys

3. **Load environment variables**:
   ```bash
   source setup-env.sh
   ```

4. **Verify it's set**:
   ```bash
   echo ${#ANTHROPIC_API_KEY}  # Should show key length (not the actual key)
   ```

✅ **Pros**: Easy for local development, git-ignored by default
⚠️ **Cons**: Must source before each session

---

### Option 2: Shell Profile (Persistent)

Add to your shell profile for automatic loading:

**For Zsh (macOS default)**:
```bash
echo 'export ANTHROPIC_API_KEY="sk-ant-api03-..."' >> ~/.zshrc
source ~/.zshrc
```

**For Bash**:
```bash
echo 'export ANTHROPIC_API_KEY="sk-ant-api03-..."' >> ~/.bashrc
source ~/.bashrc
```

✅ **Pros**: Automatic, always available
⚠️ **Cons**: Available to all projects (less isolation)

---

### Option 3: Direnv (Project-Specific, Auto-Loading)

1. **Install direnv**:
   ```bash
   brew install direnv
   ```

2. **Add to shell profile**:
   ```bash
   # For Zsh
   echo 'eval "$(direnv hook zsh)"' >> ~/.zshrc
   source ~/.zshrc

   # For Bash
   echo 'eval "$(direnv hook bash)"' >> ~/.bashrc
   source ~/.bashrc
   ```

3. **Create .envrc** (project root):
   ```bash
   echo 'export ANTHROPIC_API_KEY="sk-ant-api03-..."' > .envrc
   direnv allow
   ```

4. **Add to .gitignore**:
   ```bash
   echo ".envrc" >> .gitignore
   ```

✅ **Pros**: Auto-loads when entering directory, project-specific
✅ **Best for**: Multiple projects with different keys

---

### Option 4: macOS Keychain (Most Secure)

Store in macOS Keychain and load dynamically:

1. **Store in Keychain**:
   ```bash
   security add-generic-password -a "$USER" \
     -s "ANTHROPIC_API_KEY" \
     -w "sk-ant-api03-..."
   ```

2. **Create loader script** (`~/.load-anthropic-key.sh`):
   ```bash
   #!/bin/bash
   export ANTHROPIC_API_KEY=$(security find-generic-password \
     -a "$USER" -s "ANTHROPIC_API_KEY" -w)
   ```

3. **Add to shell profile**:
   ```bash
   echo 'source ~/.load-anthropic-key.sh' >> ~/.zshrc
   ```

✅ **Pros**: Most secure, encrypted storage
⚠️ **Cons**: macOS only, requires keychain access

---

## For GitHub Actions (CI/CD)

### Setting Repository Secrets

1. Go to: `https://github.com/YOUR_USERNAME/agent-os/settings/secrets/actions`
2. Click "New repository secret"
3. Name: `ANTHROPIC_API_KEY`
4. Value: Your API key
5. Click "Add secret"

**Usage in workflow**:
```yaml
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run AI Audit
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: python3 scripts/run_ai_audit.py
```

---

## Verification

### Check if API key is set (safely):
```bash
# Show length only (never echo the actual key!)
echo "API Key length: ${#ANTHROPIC_API_KEY} chars"

# Expected output for valid key:
# API Key length: 108 chars
```

### Test API connection:
```bash
python3 -c "
import os
import anthropic

client = anthropic.Anthropic(api_key=os.environ.get('ANTHROPIC_API_KEY'))
response = client.messages.create(
    model='claude-3-5-sonnet-20241022',
    max_tokens=10,
    messages=[{'role': 'user', 'content': 'Hi'}]
)
print('✅ API key is valid and working!')
print(f'Response: {response.content[0].text}')
"
```

---

## Security Best Practices

### ✅ DO:
- Use environment variables
- Add `.env`, `.env.local` to `.gitignore`
- Rotate keys if they're ever exposed
- Use different keys for dev/staging/prod
- Set key permissions to read-only in Anthropic Console

### ❌ DON'T:
- Commit keys to Git (even in "private" repos)
- Share keys in Slack/email
- Hardcode keys in source code
- Store keys in `.claude/settings.local.json`
- Use the same key for multiple projects/teams

---

## Key Rotation (If Exposed)

If your API key was accidentally exposed:

1. **Immediately revoke the old key**:
   - Go to: https://console.anthropic.com/settings/keys
   - Delete the exposed key

2. **Generate a new key**:
   - Click "Create Key"
   - Give it a descriptive name
   - Copy the new key

3. **Update everywhere**:
   ```bash
   # Update .env
   sed -i '' 's/ANTHROPIC_API_KEY=.*/ANTHROPIC_API_KEY=NEW_KEY_HERE/' .env

   # Update GitHub secrets
   # (Go to repo settings → Secrets → Edit ANTHROPIC_API_KEY)

   # Update shell profile if used
   # Edit ~/.zshrc or ~/.bashrc
   ```

4. **Verify new key works**:
   ```bash
   source .env  # or restart shell
   python3 -c "import os; print('Key starts with:', os.getenv('ANTHROPIC_API_KEY')[:15])"
   ```

---

## Troubleshooting

### "ANTHROPIC_API_KEY not set" error

**Check if loaded**:
```bash
env | grep ANTHROPIC
```

**If empty, load it**:
```bash
# Option 1: From .env
source setup-env.sh

# Option 2: Manual export
export ANTHROPIC_API_KEY="sk-ant-api03-..."

# Option 3: From shell profile
source ~/.zshrc  # or ~/.bashrc
```

### "Invalid API key" error (401)

- Check for typos (API keys are case-sensitive)
- Verify key hasn't been revoked
- Confirm organization access in Anthropic Console

### "Model not found" error (404)

- Check API key has access to the model
- Try fallback model: `claude-3-opus-20240229`
- Contact Anthropic support to enable model access

---

## Summary

**Recommended setup for this project**:

1. ✅ Use `.env` file (already git-ignored)
2. ✅ Run `source setup-env.sh` before working
3. ✅ Store production key in GitHub Secrets
4. ✅ Rotate key if ever exposed

**Current status**:
- `.env.example` created ✅
- `.env` in `.gitignore` ✅
- `setup-env.sh` script ready ✅
- `.claude/settings.local.json` secured ✅
