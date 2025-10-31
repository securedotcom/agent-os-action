#!/usr/bin/env python3
"""Quick test script to verify Anthropic API key"""

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
print("🧪 Testing Anthropic API connection...\n")

try:
    client = anthropic.Anthropic(api_key=api_key)
    
    # Simple test message - minimal tokens to save credits
    message = client.messages.create(
        model="claude-3-5-sonnet-20241022",
        max_tokens=10,
        messages=[
            {"role": "user", "content": "Say 'Hello' in 1 word"}
        ]
    )
    
    print("✅ API Connection Successful!")
    print(f"📝 Response: {message.content[0].text}")
    print(f"🎯 Model: {message.model}")
    print(f"💰 Tokens used: {message.usage.input_tokens} input + {message.usage.output_tokens} output")
    print(f"💵 Estimated cost: ~$0.0001")
    print("\n✨ Your Anthropic API key is working perfectly!")
    
except anthropic.APIError as e:
    print(f"❌ API Error: {e}")
    sys.exit(1)
except Exception as e:
    print(f"❌ Error: {e}")
    sys.exit(1)
