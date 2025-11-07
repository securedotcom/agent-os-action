---
title: Architecture Decision Records
sidebar_position: 1
---

# Architecture Decision Records (ADRs)

This directory contains Architecture Decision Records documenting significant architectural and technical decisions made in the Agent OS Code Reviewer project.

## What are ADRs?

Architecture Decision Records (ADRs) are documents that capture important architectural decisions along with their context and consequences. They help teams:

- Understand why decisions were made
- Avoid revisiting settled decisions
- Onboard new team members
- Track the evolution of the system

## Active ADRs

### AI & LLM
- [ADR-0001: Use Anthropic Claude for AI Analysis](./0001-use-anthropic-claude.md) - **Accepted**

### Architecture & Design
- [ADR-0002: Multi-Agent Architecture](./001-multi-agent-architecture.md) - **Accepted** (existing)

### Cost & Performance
- [ADR-0003: Cost Guardrails](./002-cost-guardrails.md) - **Accepted** (existing)

## ADR Status Definitions

- **Draft**: Under discussion, not yet decided
- **Accepted**: Decision made and being implemented
- **Deprecated**: No longer relevant or recommended
- **Superseded**: Replaced by another ADR (with link)

## Creating New ADRs

When making significant technical decisions:

1. Copy the ADR template
2. Number it sequentially (next available number)
3. Fill in all sections with context and reasoning
4. Get team review and approval
5. Mark as "Accepted" when implemented

## ADR Template

```markdown
---
title: ADR-NNNN: Title
status: Draft
date: YYYY-MM-DD
---

# ADR-NNNN: Title

## Status
[Draft | Accepted | Deprecated | Superseded]

## Context
[What is the issue we're facing?]

## Decision
[What decision did we make?]

## Consequences
### Positive
- [Benefit 1]

### Negative
- [Tradeoff 1]

## Alternatives Considered
### Alternative 1
- Pros: ...
- Cons: ...
- Why not chosen: ...

## References
- [Links to relevant documentation]
```

## Learn More

- [ADR GitHub Organization](https://adr.github.io/)
- [Documenting Architecture Decisions](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions)
