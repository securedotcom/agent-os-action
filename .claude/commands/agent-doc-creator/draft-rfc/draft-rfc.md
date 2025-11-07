# Draft RFC

Generate RFC drafts for identified improvement opportunities.

## What This Command Does

1. Analyzes codebase for improvement opportunities
2. Identifies refactoring needs, technical debt, and optimization opportunities
3. Drafts RFC documents with problem statement and proposed solutions
4. Prioritizes RFCs by impact and urgency
5. Marks as drafts requiring human ownership
6. Creates PR with RFC drafts

## When to Use

Use this command when:
- Looking for improvement opportunities
- Want to document technical debt
- Planning major refactoring
- Need RFC drafts to discuss with team
- Want AI suggestions for system improvements

## What Gets Identified

The agent looks for:
- **Code Complexity**: Large files, high complexity, duplication
- **Performance Issues**: Slow queries, N+1 problems, inefficient algorithms
- **Infrastructure Debt**: Outdated dependencies, legacy infrastructure
- **Security Concerns**: Outdated auth, missing encryption, validation gaps
- **Scalability Limits**: Single points of failure, bottlenecks
- **Developer Experience**: Complex setup, slow builds, poor tooling

## Workflow

{{workflows/scan-repository}}

{{workflows/generate-rfcs}}

{{workflows/update-sidebars}}

{{workflows/validate-docs}}

{{workflows/create-docs-pr}}

## Output

- RFC draft files in `docs/rfcs/`
- Updated `docs/rfcs/README.md` index
- Updated sidebars
- PR with RFC drafts

## Review

RFC drafts are starting points for discussion. Review for:
- Validity of identified problems
- Feasibility of proposed solutions
- Completeness of impact analysis
- Accuracy of risk assessment
- Assign human owners to promising RFCs
- Schedule RFC review meetings

## Next Steps

After review:
1. Assign owners to RFCs
2. Gather additional requirements
3. Revise based on team feedback
4. Move promising RFCs to "Under Review" status
5. Accept or reject based on discussion

