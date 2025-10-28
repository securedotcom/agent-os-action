# ADR-001: Multi-Agent Architecture

## Status

Accepted (v1.0.14)

## Context

Code review is a complex task requiring expertise across multiple domains: security, performance, testing, and code quality. Early versions of Agent OS used a single generalist AI agent to perform all review tasks, which led to:

- **Shallow analysis**: A single agent couldn't deeply analyze all aspects simultaneously
- **Generic findings**: Lack of specialized expertise resulted in generic, non-actionable feedback
- **Missed issues**: Important domain-specific vulnerabilities were often overlooked
- **Conflicting priorities**: The agent struggled to balance different concerns (security vs. performance, etc.)

## Decision

We implement a **multi-agent sequential architecture** with five specialized agents:

1. **Security Reviewer**: Focuses exclusively on security vulnerabilities (SQL injection, XSS, auth flaws, secrets, crypto)
2. **Performance Reviewer**: Analyzes performance issues (N+1 queries, memory leaks, algorithmic efficiency)
3. **Testing Reviewer**: Evaluates test coverage and quality (critical paths, edge cases, integration tests)
4. **Code Quality Reviewer**: Assesses maintainability (complexity, documentation, error handling, duplication)
5. **Review Orchestrator**: Deduplicates findings, prioritizes by business impact, and synthesizes final report

Each agent runs sequentially with its own specialized prompt, then the orchestrator combines and refines their findings.

## Consequences

### Positive

- **Deeper Analysis**: Each agent focuses on its domain of expertise, resulting in more thorough analysis
- **Actionable Findings**: Specialized agents provide specific, actionable recommendations with code examples
- **Better Coverage**: Domain-specific knowledge reduces false negatives (missed issues)
- **Deduplication**: Orchestrator eliminates redundant findings reported by multiple agents
- **Business Context**: Orchestrator prioritizes findings by actual business impact, not just severity
- **Extensibility**: Easy to add new specialized agents (e.g., accessibility, compliance) without affecting existing ones

### Negative

- **Higher Cost**: Running 5 agents costs ~5x more than single agent (~$0.75 vs ~$0.15 per run)
- **Longer Duration**: Sequential execution takes 5-10 minutes vs 1-2 minutes for single agent
- **Complexity**: More moving parts to maintain and debug
- **Potential Redundancy**: Without orchestrator, findings could be duplicated across agents

### Neutral

- **Mode Selection**: Users choose between single-agent (fast/cheap) and multi-agent (deep/expensive) based on needs
- **Reports**: Multi-agent mode generates 6 reports (5 agent + 1 orchestrated) vs 1 report in single-agent mode

## Alternatives Considered

### Alternative 1: Single Generalist Agent
**Rejected** - Original approach, suffered from shallow analysis and generic findings

### Alternative 2: Parallel Multi-Agent Execution
**Deferred** - Could reduce duration from 5-10 min to 2-3 min, but:
- Requires more complex orchestration
- Higher API rate limit requirements
- More difficult to debug
- Cost savings minimal (still 5 agents)
- May be implemented in future version

### Alternative 3: Hybrid Single Agent with Domain-Specific Prompts
**Rejected** - Middle ground where single agent gets multiple domain-specific prompts:
- Still suffers from lack of deep specialization
- Doesn't reduce cost (still multiple LLM calls)
- More complex than single-agent, less effective than multi-agent

### Alternative 4: Rule-Based + AI Augmentation
**Complementary** - Use static analysis tools (CodeQL, Semgrep) alongside AI:
- Implemented as complementary, not replacement
- Static tools catch known patterns
- AI agents catch logic flaws and complex issues
- Best of both worlds approach

## Implementation Details

```python
# Sequential execution flow
agents = ['security', 'performance', 'testing', 'quality']

for agent in agents:
    report = run_agent_with_specialized_prompt(agent)
    agent_reports[agent] = report

# Orchestrator synthesizes all findings
final_report = run_orchestrator(agent_reports)
```

## Metrics

Based on production data (v1.0.14-v1.0.15):

| Metric | Single-Agent | Multi-Agent | Improvement |
|--------|-------------|-------------|-------------|
| Avg findings per run | 8 | 23 | +187% |
| False positives | 20% | 12% | -40% |
| Actionable findings | 65% | 82% | +26% |
| Critical issues found | 1.2 | 3.8 | +217% |
| Cost per run | $0.15 | $0.75 | +400% |
| Duration | 1.5 min | 7 min | +367% |

## Usage Guidance

**Use Single-Agent Mode for:**
- Pull request reviews (fast feedback)
- Daily CI checks
- Cost-conscious teams
- Small codebases (<10K LOC)

**Use Multi-Agent Sequential for:**
- Weekly/monthly audits
- Pre-release security reviews
- Compliance audits (SOC 2, HIPAA)
- Large codebases (>50K LOC)
- High-stakes production code

## References

- Issue #42: Multi-agent architecture proposal
- PR #156: Initial multi-agent implementation
- User feedback survey (December 2024)
- Claude documentation on multi-turn conversations
- "Multi-Agent Systems for Software Engineering" (research paper)
