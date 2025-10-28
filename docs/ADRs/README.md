# Architecture Decision Records (ADRs)

This directory contains Architecture Decision Records (ADRs) for the Agent OS Code Reviewer project.

## What is an ADR?

An Architecture Decision Record (ADR) is a document that captures an important architectural decision made along with its context and consequences.

## ADR Index

- [ADR-001: Multi-Agent Architecture](001-multi-agent-architecture.md) - Decision to use specialized agents instead of single generalist agent
- [ADR-002: Cost Guardrails](002-cost-guardrails.md) - Implementation of pre-flight cost estimation and fail-fast mechanisms

### Planned ADRs
- ADR-003: Provider Abstraction - Design of AI provider abstraction layer (Coming soon)
- ADR-004: SARIF Output Format - Choice of SARIF 2.1.0 for security findings (Coming soon)
- ADR-005: File Selection Algorithm - Priority-based file selection strategy (Coming soon)

## ADR Format

Each ADR follows this structure:

```markdown
# ADR-XXX: [Title]

## Status

[Proposed | Accepted | Deprecated | Superseded]

## Context

[What is the issue we're facing? What factors are influencing this decision?]

## Decision

[What is the change we're proposing and/or doing?]

## Consequences

### Positive
- [List positive consequences]

### Negative
- [List negative consequences]

### Neutral
- [List neutral consequences]

## Alternatives Considered

[What other options were considered?]

## References

[Links to related resources, discussions, or documents]
```

## When to Write an ADR

Write an ADR when making decisions about:
- Architecture patterns and system design
- Technology choices (frameworks, libraries, tools)
- Integration approaches
- Security mechanisms
- Performance optimization strategies
- User experience trade-offs
- Operational concerns

## How to Create a New ADR

1. Copy the template: `cp 000-template.md XXX-your-title.md`
2. Fill in all sections
3. Get review from team members
4. Update status from "Proposed" to "Accepted" after approval
5. Add entry to this README's index
