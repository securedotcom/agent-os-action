---
title: Request for Comments (RFCs)
sidebar_position: 1
---

# Request for Comments (RFCs)

This directory contains RFC (Request for Comments) documents proposing significant changes, new features, or architectural improvements to the Agent OS Code Reviewer project.

## What are RFCs?

RFCs are design documents that:
- Propose new features or significant changes
- Describe the problem, solution, and tradeoffs
- Gather feedback before implementation
- Document the decision-making process

## Active RFCs

### Performance & Cost
- [RFC-0001: Incremental Analysis for Cost Optimization](./rfc-0001-incremental-analysis-draft.md) - **Draft** 🤖 AI-Generated

## RFC Status Definitions

- **Draft**: Under discussion, seeking feedback
- **Accepted**: Approved for implementation
- **Implemented**: Feature has been built and released
- **Rejected**: Decided not to pursue
- **Superseded**: Replaced by another RFC

## Creating an RFC

### When to Write an RFC

Write an RFC for:
- New major features
- Breaking changes
- Significant architecture changes
- Changes affecting users or API
- Complex technical decisions

Don't write an RFC for:
- Bug fixes
- Minor improvements
- Documentation updates
- Refactoring (unless significant)

### RFC Process

1. **Draft**: Create RFC document using template below
2. **Discussion**: Share in GitHub Discussions for feedback
3. **Revision**: Update based on feedback
4. **Review**: Team reviews and discusses
5. **Decision**: Accept, reject, or request more changes
6. **Implementation**: If accepted, implement and track progress
7. **Closure**: Mark as implemented or rejected

### RFC Template

```markdown
---
title: RFC-NNNN: Title
status: Draft
date: YYYY-MM-DD
---

# RFC-NNNN: Title

## Status
[Draft | Accepted | Implemented | Rejected | Superseded]

## Context
[What problem are we trying to solve? Why now?]

## Problem Statement
[Clear statement of the problem]

## Proposal
### Overview
[High-level description of the solution]

### Implementation Details
[Technical details, architecture, code examples]

### Configuration
[Any new configuration options]

## Impact
### Positive
- [Benefits]

### Negative
- [Tradeoffs, costs, complexity]

## Risks & Mitigations
### Risk 1: [Description]
**Mitigation**: [How to address]

## Alternatives Considered
### Alternative 1
- Pros: ...
- Cons: ...
- Why not chosen: ...

## Open Questions
1. [Question 1]
2. [Question 2]

## Success Metrics
[How will we measure success?]

## Implementation Plan
### Phase 1: [Name]
- [ ] Task 1
- [ ] Task 2

## References
- [Links to related docs, issues, discussions]

## Review & Approval
**TODO**: Requires review from:
- [ ] Team/person 1
- [ ] Team/person 2
```

## AI-Generated RFCs

Some RFCs in this directory are marked as AI-generated (🤖). These are:
- Automatically generated based on codebase analysis
- Identified opportunities for improvement
- **Require human review and validation**
- May contain inaccuracies or infeasible suggestions

**Always review AI-generated RFCs critically** before accepting or implementing.

## Discussion

Discuss RFCs in:
- **GitHub Discussions**: [RFCs Category](https://github.com/securedotcom/agent-os-action/discussions/categories/rfcs)
- **Issues**: For specific implementation questions
- **Pull Requests**: For RFC document updates

## Learn More

- [RFC Process (Rust)](https://github.com/rust-lang/rfcs)
- [Python PEPs](https://peps.python.org/)
- [IETF RFCs](https://www.ietf.org/standards/rfcs/)

