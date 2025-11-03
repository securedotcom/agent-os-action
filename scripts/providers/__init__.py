"""
Agent OS AI Providers Package

Supported providers:
- Foundation-Sec-8B: Cisco's security-optimized LLM (local, zero-cost)
- Anthropic Claude: Cloud API ($3-15/1M tokens)
- OpenAI GPT-4: Cloud API ($10-30/1M tokens)
- Ollama: Local LLM server (zero-cost)
"""

from .foundation_sec import (
    FoundationSecProvider,
    get_foundation_sec_client,
    call_foundation_sec_api
)

__all__ = [
    'FoundationSecProvider',
    'get_foundation_sec_client',
    'call_foundation_sec_api'
]
