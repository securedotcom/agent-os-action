#!/usr/bin/env python3
"""Enhanced diagnostic script to test Anthropic API key and find working model"""

import os
import sys
import subprocess

try:
    import anthropic
except ImportError:
    print("Installing anthropic package...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "anthropic"])
        import anthropic
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install anthropic package: {e}")
        print("Please install manually: pip install anthropic")
        sys.exit(1)

# Get API key from environment or prompt
api_key = os.environ.get('ANTHROPIC_API_KEY')

if not api_key:
    print("❌ ANTHROPIC_API_KEY not found in environment")
    print("Please set it: export ANTHROPIC_API_KEY='sk-ant-...'")
    sys.exit(1)

print("🔑 API Key found (starts with: {}...)".format(api_key[:15]))
print(f"📦 Anthropic SDK Version: {anthropic.__version__}")
print("🧪 Testing Anthropic API connection with model fallback chain...\n")

# Try models in order of preference (most universally available first)
MODEL_FALLBACK_CHAIN = [
    # Claude 3 Haiku - Most lightweight and universally available
    ("claude-3-haiku-20240307", "Claude 3 Haiku (March 2024) - Most lightweight"),

    # Claude 3 Sonnet - Balanced performance
    ("claude-3-sonnet-20240229", "Claude 3 Sonnet (February 2024) - Balanced"),

    # Claude 3.5 Sonnet variants
    ("claude-3-5-sonnet-20241022", "Claude 3.5 Sonnet (October 2024) - Latest"),
    ("claude-3-5-sonnet-20240620", "Claude 3.5 Sonnet (June 2024) - Stable"),

    # Claude 3 Opus - Most powerful
    ("claude-3-opus-20240229", "Claude 3 Opus (February 2024) - Most powerful"),

    # Alternative naming patterns (if available)
    ("claude-3-5-sonnet-latest", "Claude 3.5 Sonnet (Latest alias)"),
    ("claude-3-haiku-latest", "Claude 3 Haiku (Latest alias)"),
]

client = anthropic.Anthropic(api_key=api_key)
working_model = None
error_log = []

for model_id, description in MODEL_FALLBACK_CHAIN:
    try:
        print(f"🔄 Trying: {description}")
        print(f"   Model ID: {model_id}")

        # Simple test message - minimal tokens to save credits
        message = client.messages.create(
            model=model_id,
            max_tokens=10,
            messages=[
                {"role": "user", "content": "Say 'Hello' in 1 word"}
            ]
        )

        # Success!
        working_model = model_id
        print(f"\n✅ SUCCESS! Found working model: {model_id}")
        print(f"📝 Response: {message.content[0].text}")
        print(f"🎯 Model: {message.model}")
        print(f"💰 Tokens used: {message.usage.input_tokens} input + {message.usage.output_tokens} output")
        print(f"💵 Estimated cost: ~$0.0001")
        print(f"\n✨ Your Anthropic API key is working with: {description}")
        break

    except anthropic.NotFoundError as e:
        print(f"   ❌ 404 Not Found - Model not accessible with this API key")
        error_log.append((model_id, "404 NotFoundError", str(e)))
    except anthropic.AuthenticationError as e:
        print(f"   ❌ Authentication failed - Check API key")
        error_log.append((model_id, "401 AuthenticationError", str(e)))
        print(f"\n🔴 FATAL: API key authentication failed")
        print(f"Error: {e}")
        sys.exit(1)
    except anthropic.PermissionDeniedError as e:
        print(f"   ❌ 403 Permission Denied - API key lacks permissions")
        error_log.append((model_id, "403 PermissionDeniedError", str(e)))
    except anthropic.APIError as e:
        print(f"   ❌ API Error: {e}")
        error_log.append((model_id, f"{type(e).__name__}", str(e)))
    except Exception as e:
        print(f"   ❌ Unexpected Error: {e}")
        error_log.append((model_id, f"{type(e).__name__}", str(e)))

    print()  # Blank line for readability

# Summary
if working_model:
    print("\n" + "="*70)
    print("✅ DIAGNOSTIC COMPLETE - WORKING MODEL FOUND")
    print("="*70)
    print(f"\n🎯 Use this model ID in your configuration: {working_model}")
    print("\nTo update Agent OS configuration:")
    print(f"1. Edit scripts/run_ai_audit.py line 166")
    print(f"2. Change 'anthropic' default to: '{working_model}'")
    sys.exit(0)
else:
    print("\n" + "="*70)
    print("❌ DIAGNOSTIC COMPLETE - NO WORKING MODEL FOUND")
    print("="*70)
    print("\n🔍 Detailed Error Log:")
    for model_id, error_type, error_msg in error_log:
        print(f"\n  Model: {model_id}")
        print(f"  Error: {error_type}")
        print(f"  Details: {error_msg[:200]}")

    print("\n" + "="*70)
    print("🚨 TROUBLESHOOTING STEPS:")
    print("="*70)
    print("""
1. ✅ API Key Format Check:
   - Your API key starts with: {}...
   - Should start with: sk-ant-api03-...
   - Length should be ~108 characters

2. 🔑 Verify API Key Permissions:
   - Login to: https://console.anthropic.com/
   - Check "API Keys" section
   - Ensure key has "Messages API" access
   - Check if key is tied to organization with model access

3. 📋 Check Workspace/Organization:
   - Some API keys are workspace-specific
   - Try creating a NEW API key from your workspace
   - Ensure workspace has Claude 3 model access enabled

4. 🌍 Regional Availability:
   - Claude models may have regional restrictions
   - Check if your account is in supported region

5. 🎫 Beta Access:
   - Claude 3.5 models may require beta access
   - Apply at: https://www.anthropic.com/earlyaccess

6. 💳 Billing Status:
   - Ensure account has valid payment method
   - Check if account is in good standing
   - Some features require billing to be active

7. 🆕 Try Creating New API Key:
   - Old keys might have different permissions
   - Create new key with full permissions
   - Update ANTHROPIC_API_KEY environment variable

If ALL models return 404:
   → This indicates the API key doesn't have access to ANY models
   → Contact Anthropic support: support@anthropic.com
   → Reference error: "All model IDs return 404 NotFoundError"
""".format(api_key[:15]))

    sys.exit(1)
