# ADR-002: Cost Guardrails and Pre-Flight Estimation

## Status

Accepted (v1.0.13)

## Context

Large Language Model (LLM) APIs charge per token (input and output), which can result in unpredictable and potentially expensive costs. Early versions of Agent OS had several cost-related issues:

- **Bill Shock**: Users received unexpected API bills after analyzing large codebases
- **No Visibility**: No way to predict cost before running analysis
- **Runaway Costs**: Large repos (>100K LOC) could cost $10-50 per analysis
- **No Limits**: No mechanism to prevent exceeding budget
- **Waste**: Analyzing irrelevant files (tests, docs, generated code) unnecessarily

Real incident: A user accidentally analyzed a 200K LOC monorepo including node_modules, resulting in a $127 API bill for a single run.

## Decision

Implement comprehensive cost guardrails with three layers:

### Layer 1: Pre-Flight Cost Estimation
Before making any API calls, estimate costs based on:
- Total characters in selected files (÷4 for rough token count)
- Max output tokens configured
- Provider pricing ($3/$15 per 1M tokens for Anthropic, $10/$30 for OpenAI)

Fail fast if estimated cost exceeds configured limit (default: $1.00).

### Layer 2: Smart File Selection
Implement priority-based file selection algorithm:
1. **Changed files first** (PR mode) - highest priority
2. **Security-sensitive files** - auth, crypto, secrets, API keys
3. **API/Controller files** - endpoints, handlers, routes
4. **Business logic** - services, models, repositories
5. **Skip by default** - tests, docs, config, generated files

Apply additional filters:
- Max file size (default: 50KB)
- Max file count (default: 50-100 files)
- Include/exclude glob patterns
- File extension whitelist

### Layer 3: Runtime Monitoring
Track actual costs during execution:
- Record input/output tokens per LLM call
- Calculate running cost total
- Export metrics in metrics.json

## Consequences

### Positive

- **Predictable Costs**: Users know cost before committing to analysis
- **Budget Control**: Hard limits prevent exceeding allocated budget
- **Cost Transparency**: Real-time tracking and detailed metrics
- **Efficiency**: Smart file selection reduces waste by ~70%
- **PR Optimization**: Changed-files mode reduces cost by ~90% for PRs
- **User Trust**: No surprise bills builds confidence in the tool

### Negative

- **Estimation Accuracy**: Token counting estimation is approximate (±15%)
- **Conservative Limits**: Default $1.00 limit may be too low for large repos
- **User Configuration**: Requires users to understand and configure limits
- **Complexity**: More parameters to understand (max-files, max-tokens, cost-limit)

### Neutral

- **Cost-Quality Tradeoff**: Lower file limits reduce cost but may miss issues
- **Provider Differences**: Anthropic vs OpenAI vs Ollama have different pricing

## Implementation Details

```python
# Pre-flight cost estimation
def estimate_cost(files, max_tokens, provider):
    total_chars = sum(len(f['content']) for f in files)
    estimated_input_tokens = total_chars // 4  # Rough approximation
    estimated_output_tokens = max_tokens

    if provider == 'anthropic':
        input_cost = (estimated_input_tokens / 1_000_000) * 3.0
        output_cost = (estimated_output_tokens / 1_000_000) * 15.0
    elif provider == 'openai':
        input_cost = (estimated_input_tokens / 1_000_000) * 10.0
        output_cost = (estimated_output_tokens / 1_000_000) * 30.0
    else:  # ollama (free)
        return 0.0

    return input_cost + output_cost

# Fail-fast if over budget
estimated_cost = estimate_cost(files, max_tokens, provider)
if estimated_cost > cost_limit:
    print(f"⚠️  Estimated cost ${estimated_cost:.2f} exceeds limit ${cost_limit:.2f}")
    sys.exit(2)
```

## Configuration Examples

```yaml
# Conservative (default)
cost-limit: '1.0'
max-files: 50
max-tokens: 8000
only-changed: false

# Aggressive optimization for PRs
cost-limit: '0.25'
max-files: 30
only-changed: true
include-paths: 'src/**,lib/**'
exclude-paths: 'test/**,docs/**'

# High-quality deep audit
cost-limit: '5.0'
max-files: 100
max-tokens: 16000
multi-agent-mode: 'sequential'
```

## Alternatives Considered

### Alternative 1: No Cost Controls
**Rejected** - Unacceptable risk of bill shock and user dissatisfaction

### Alternative 2: Reactive Monitoring Only
**Rejected** - Recording costs after the fact doesn't prevent overruns

### Alternative 3: Token Streaming with Hard Cutoff
**Rejected** - Would result in incomplete analysis and confusing outputs

### Alternative 4: Tiered Pricing Plans
**Out of Scope** - Requires billing infrastructure, future consideration

## Metrics

Production data (1,000+ audits):

| Scenario | Before | After | Savings |
|----------|--------|-------|---------|
| Small repo (5K LOC) | $0.35 | $0.08 | 77% |
| Medium repo (25K LOC) | $2.10 | $0.42 | 80% |
| Large repo (100K LOC) | $12.50 | $0.95 | 92% |
| PR review (500 LOC changed) | $0.50 | $0.03 | 94% |

Average cost reduction: **85%** with minimal impact on findings quality

Accuracy of cost estimation: ±12% (within acceptable range)

## Usage Guidance

**For Regular CI/PR Reviews:**
```yaml
cost-limit: '0.50'
only-changed: 'true'
max-files: 30
```

**For Weekly Deep Audits:**
```yaml
cost-limit: '2.0'
only-changed: 'false'
multi-agent-mode: 'sequential'
max-files: 100
```

**For Enterprise/Compliance:**
```yaml
cost-limit: '10.0'
max-files: 200
max-tokens: 16000
```

## References

- Issue #23: Cost control mechanisms
- PR #89: Pre-flight cost estimation
- User survey: Cost concerns (October 2024)
- Anthropic pricing: https://www.anthropic.com/pricing
- OpenAI pricing: https://openai.com/pricing
