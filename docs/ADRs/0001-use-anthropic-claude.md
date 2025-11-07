---
title: ADR-0001: Use Anthropic Claude for AI Analysis
sidebar_position: 1
ai_generated: true
status: Accepted
date: 2024-11-07
tags: [adr, ai, llm, anthropic]
---

> ⚠️ **AI-Generated Documentation**
> This ADR was generated based on codebase analysis.
> Please review and validate the context and reasoning.

# ADR-0001: Use Anthropic Claude for AI Analysis

## Status

**Accepted**

Date: 2024-11-07

## Context

The code review system requires a Large Language Model (LLM) for analyzing code quality, security vulnerabilities, performance issues, and generating actionable insights. The system needs to:

- Analyze complex code patterns and identify security vulnerabilities
- Provide detailed explanations and remediation guidance
- Support large context windows for analyzing multiple files
- Balance cost and quality
- Provide reliable API access

Evidence from codebase:
- Default model is `claude-sonnet-4-20250514` in `action.yml`
- Primary API key configuration is `anthropic-api-key`
- Cost calculations in `run_ai_audit.py` optimized for Claude pricing ($3/1M input, $15/1M output)
- Retry logic and error handling specifically tuned for Anthropic API

## Decision

We will use **Anthropic Claude** (specifically Claude Sonnet 4) as the primary AI provider for code analysis.

## Consequences

### Positive

- **High Quality Analysis**: Claude Sonnet 4 excels at code understanding and security analysis
- **Cost Effective**: At $3/1M input tokens and $15/1M output tokens, provides excellent value
  - Typical run: ~45K input + ~5K output = ~$0.30
- **Long Context Window**: Supports analyzing large codebases in single requests
- **Security Focus**: Strong performance on vulnerability detection and exploit analysis
- **Reliable API**: Stable API with good uptime and clear error messages
- **Rate Limiting**: Reasonable rate limits for CI/CD use cases

### Negative

- **External Dependency**: Requires internet access and Anthropic API availability
- **API Costs**: Not free (vs local Ollama), though costs are reasonable
- **Rate Limits**: Subject to Anthropic's rate limiting (mitigated with retry logic)
- **Vendor Lock-in**: Some dependency on Anthropic's API stability and pricing

### Neutral

- **Alternative Providers Supported**: System also supports OpenAI and Ollama as fallbacks
- **Model Flexibility**: Can switch to other Claude models via configuration
- **Cost Monitoring**: Built-in cost tracking and guardrails

## Alternatives Considered

### Alternative 1: OpenAI GPT-4
- **Pros**: 
  - Well-known and widely adopted
  - Good code analysis capabilities
  - Strong ecosystem and tooling
- **Cons**: 
  - More expensive: $10/1M input, $30/1M output (3x cost)
  - Typical run would cost ~$0.90 vs $0.30 for Claude
- **Why not chosen**: Higher cost for similar or slightly lower quality on code analysis tasks

### Alternative 2: Local Ollama (llama3, codellama)
- **Pros**: 
  - Free (no API costs)
  - No external API dependency
  - Complete privacy (data never leaves infrastructure)
  - No rate limits
- **Cons**: 
  - Requires local infrastructure (GPU recommended)
  - Lower quality analysis compared to Claude/GPT-4
  - Smaller context windows
  - More maintenance overhead
- **Why not chosen**: Quality tradeoff not acceptable for default configuration, but supported as option

### Alternative 3: GitHub Copilot / Azure OpenAI
- **Pros**:
  - Integrated with GitHub ecosystem
  - Enterprise support options
- **Cons**:
  - Similar or higher cost to OpenAI
  - Less flexible API
  - Requires additional setup
- **Why not chosen**: No significant advantages over direct Anthropic integration

## Implementation Notes

### Configuration

In `action.yml`:
```yaml
inputs:
  anthropic-api-key:
    description: 'Anthropic API key for Claude AI analysis'
    required: false
    default: ''
  model:
    description: 'AI model to use'
    required: false
    default: 'claude-sonnet-4-20250514'
```

### Usage in Code

In `scripts/run_ai_audit.py`:
```python
# Cost calculation for Claude
if provider == 'anthropic':
    # Claude Sonnet 4: $3/1M input, $15/1M output
    input_cost = (input_tokens / 1_000_000) * 3.0
    output_cost = (output_tokens / 1_000_000) * 15.0
```

### API Integration

```python
import anthropic

client = anthropic.Anthropic(api_key=os.environ['ANTHROPIC_API_KEY'])

response = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=8192,
    messages=[{"role": "user", "content": prompt}]
)
```

### Retry Logic

Uses `tenacity` library for resilient API calls:
- Exponential backoff
- Max 3 retry attempts
- Handles rate limiting and transient errors

## References

- [Anthropic Pricing](https://www.anthropic.com/pricing)
- [Claude Sonnet 4 Documentation](https://docs.anthropic.com/)
- [Claude API Reference](https://docs.anthropic.com/claude/reference)
- Implementation: `scripts/run_ai_audit.py` lines 80-98

## Review Notes

**TODO**: Validate that Claude Sonnet 4 remains the best choice as new models are released. Consider periodic benchmarking against alternatives.

