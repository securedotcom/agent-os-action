# RFC Format Standard

Standard format for Request for Comments documents.

## RFC Template

````markdown
---
title: RFC-{number}: {Title}
sidebar_position: {number}
ai_generated: true
status: Draft
date: 2024-11-07
authors: [ai-agent]
reviewers: []
tags: [category, priority]
---

> ⚠️ **AI-Generated RFC Draft**
> This RFC was drafted by an AI agent based on codebase analysis.
> It requires human review, validation, and discussion before implementation.

# RFC-{number}: {Title}

## Summary

[One paragraph summary of the proposal]

## Status

**Draft** | Under Review | Accepted | Rejected | Implemented

## Metadata

- **Created**: 2024-11-07
- **Authors**: AI Agent (requires human ownership)
- **Reviewers**: [To be assigned]
- **Target Version**: [Version]
- **Estimated Effort**: [Small | Medium | Large]
- **Priority**: [Critical | High | Medium | Low]

## Context & Problem

### Current State

[Describe the current situation]

### The Problem

[Clearly state the problem this RFC addresses]

### Evidence

[Data, metrics, or incidents supporting the need for change]

## Proposal

### Overview

[High-level description of the proposed solution]

### Detailed Design

[Technical details of the implementation]

### Success Metrics

[How will we measure success?]

## Alternatives Considered

### Alternative 1: [Name]
- **Pros**: ...
- **Cons**: ...
- **Why not chosen**: ...

### Do Nothing
- **Pros**: No implementation cost
- **Cons**: Problem persists

## Impact Analysis

### User Impact
[How will this affect end users?]

### Developer Impact
[How will this affect the development team?]

### Performance Impact
[Expected performance changes]

### Cost Impact
[Financial implications]

### Security Impact
[Security considerations]

## Risks & Mitigation

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| [Risk 1] | High/Med/Low | High/Med/Low | [Strategy] |

## Open Questions

1. **Question 1**: [Details]
2. **Question 2**: [Details]

## Timeline

- **RFC Review Period**: 2 weeks
- **Implementation**: [Estimate]
- **Testing & Validation**: [Estimate]
- **Rollout**: [Estimate]

## Dependencies

[What needs to happen before this can be implemented?]

## References

- [Related ADRs]
- [External documentation]
- [Similar implementations]

## Review Checklist

- [ ] Problem statement is clear
- [ ] Proposed solution is technically sound
- [ ] Alternatives adequately considered
- [ ] Impact analysis is comprehensive
- [ ] Risks identified with mitigation
- [ ] Timeline is realistic
- [ ] Success metrics are measurable
````

## Frontmatter Fields

Required:
- `title`: RFC-NNNN: Title format
- `status`: Current status
- `date`: Creation date

Optional:
- `ai_generated`: true (if AI-generated)
- `authors`: List of authors
- `reviewers`: List of reviewers
- `tags`: Categorization
- `priority`: Critical/High/Medium/Low
- `target_version`: Target release

## Numbering

Format: `rfc-NNNN-kebab-title-draft.md`

Examples:
- `rfc-0001-migrate-kubernetes-draft.md`
- `rfc-0002-graphql-api-draft.md`
- `rfc-0010-improve-performance-draft.md`

Rules:
- Zero-padded to 4 digits
- Include `-draft` suffix for AI-generated
- Remove `-draft` when human-owned
- Sequential numbering

## Status Values

### Draft
- Initial proposal
- Needs human ownership
- Gathering requirements

### Under Review
- Being discussed by team
- Receiving feedback
- May be revised

### Accepted
- Approved for implementation
- Ready to start work
- Committed to timeline

### Rejected
- Not moving forward
- Document reasons
- Keep for reference

### Implemented
- Work completed
- Deployed to production
- Mark as historical

## Writing Guidelines

### Summary
- One paragraph
- Explain what and why
- Make it scannable

### Context & Problem
- Explain current pain points
- Provide evidence (metrics, incidents)
- Make the case for change
- Help readers understand urgency

### Proposal
- Be specific about implementation
- Include architecture diagrams
- Show code examples if helpful
- Describe rollout strategy

### Alternatives
- Show you've done homework
- Be fair to each option
- Explain tradeoffs clearly
- Include "do nothing" option

### Impact Analysis
- Consider all stakeholders
- Think broadly (users, devs, ops, cost)
- Be honest about negatives
- Quantify when possible

### Risks
- Identify what could go wrong
- Assess likelihood and impact
- Provide mitigation strategies
- Don't hide problems

### Open Questions
- List unknowns
- Identify who can answer
- Don't proceed without answers
- Update as questions resolved

## RFC Triggers

Create RFCs for:

### Code Quality
- Large refactoring
- Architecture changes
- Breaking API changes
- Major dependency updates

### Performance
- Significant optimizations
- Scaling improvements
- Infrastructure changes

### Infrastructure
- Cloud migrations
- Platform changes
- Deployment process changes
- Monitoring/logging overhauls

### Security
- Auth/authz changes
- Encryption updates
- Compliance requirements
- Security improvements

### Developer Experience
- Tooling changes
- Build process updates
- Development workflow changes
- Testing strategy changes

## Priority Levels

### Critical
- Security vulnerabilities
- Production outages
- Blocking issues
- Compliance requirements

### High
- Performance problems
- Major technical debt
- User-impacting issues
- Team productivity blockers

### Medium
- Code quality improvements
- Developer experience
- Nice-to-have features
- Incremental improvements

### Low
- Cosmetic changes
- Minor optimizations
- Future considerations
- Exploratory proposals

## AI-Generated RFCs

### Requirements
1. Must be marked as Draft
2. Must include AI disclaimer
3. Must request human ownership
4. Must mark uncertainty
5. Must have evidence

### Uncertainty Handling
```markdown
## Context & Problem

Based on code analysis, the current architecture **may have** scalability
limitations.

**TODO**: Validate with load testing and gather actual performance metrics.
```

### Evidence Requirements
- Link to specific code
- Reference metrics/logs
- Cite incidents
- Show patterns

## Review Process

### Review Period
- Minimum 2 weeks for major RFCs
- 1 week for minor RFCs
- Extend if needed for discussion

### Reviewers
- Technical leads
- Affected team members
- Security team (if applicable)
- Operations team (if applicable)

### Discussion
- Use PR comments
- Schedule review meetings
- Document decisions
- Update RFC with feedback

## Implementation

### After Acceptance
1. Assign owner
2. Break into tasks
3. Create implementation plan
4. Track progress
5. Update RFC status

### During Implementation
- Reference RFC in PRs
- Update RFC if design changes
- Document deviations
- Keep stakeholders informed

### After Implementation
- Mark as Implemented
- Document actual vs. planned
- Capture lessons learned
- Link to related docs

## Review Checklist

Before submitting RFC:
- [ ] Title is clear and specific
- [ ] Summary is concise
- [ ] Problem is well-defined
- [ ] Evidence supports need
- [ ] Proposal is detailed
- [ ] Alternatives considered
- [ ] Impact analysis complete
- [ ] Risks identified
- [ ] Timeline is realistic
- [ ] Success metrics defined
- [ ] Open questions listed
- [ ] References included
- [ ] No secrets exposed

## Related Standards

- [Documentation Style Guide](./doc-style.md)
- [ADR Format](./adr-format.md)
- [Frontmatter Standards](./frontmatter-standards.md)

