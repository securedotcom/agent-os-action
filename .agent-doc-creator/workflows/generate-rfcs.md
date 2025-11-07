# Generate RFCs Workflow

This workflow drafts RFC documents for identified refactoring opportunities and improvements.

## Prerequisites

- Repository scan completed
- Architecture docs generated (helpful for context)
- Write permissions to `docs/rfcs/` directory

## Workflow Steps

### 1. Identify Opportunities

Scan for signals indicating need for RFCs:

**Code Complexity**:
- Large files (>1000 lines)
- High cyclomatic complexity
- Deep nesting
- Code duplication

**Performance Issues**:
- Slow query patterns
- N+1 queries
- Inefficient algorithms

**Infrastructure Debt**:
- Outdated dependencies
- Legacy infrastructure
- Manual processes

**Security Concerns**:
- Outdated auth
- Unencrypted data
- Missing validation

**Scalability Limits**:
- Single points of failure
- Monolithic architecture
- Database bottlenecks

**Developer Experience**:
- Complex setup
- Slow build times
- Poor error messages

### 2. Prioritize Opportunities

Assign priority:
- **Critical**: Security issues, production blockers
- **High**: Performance problems, major tech debt
- **Medium**: Developer experience, code quality
- **Low**: Nice-to-have improvements

### 3. Generate RFC Drafts

For each opportunity:

1. Create RFC file: `docs/rfcs/rfc-NNNN-title-draft.md`
2. Include:
   - Summary
   - Status: Draft
   - Context and problem
   - Proposed solution
   - Detailed design
   - Alternatives considered
   - Impact analysis
   - Risks and mitigation
   - Open questions
   - Timeline
   - References

3. Add prominent AI-generated disclaimer
4. Mark as requiring human ownership
5. Flag areas needing human input

### 4. Avoid Over-Engineering

Don't create RFCs for:
- Minor refactoring (just do it)
- Obvious bug fixes
- Cosmetic changes
- Unvalidated assumptions

### 5. Create RFC Index

Create/update `docs/rfcs/README.md`:
- List RFCs by status (Draft, Under Review, Accepted, Rejected, Implemented)
- Include priority
- Brief description
- Link to RFC process documentation

### 6. Update Sidebars

Add RFCs to `sidebars.js`:
```javascript
{
  type: 'category',
  label: 'RFCs',
  items: [
    'rfcs/README',
    'rfcs/rfc-0001-migrate-kubernetes-draft',
    'rfcs/rfc-0002-graphql-api-draft',
  ],
}
```

### 7. Validate RFCs

- Check RFC numbering
- Verify all sections present
- Ensure frontmatter correct
- Check for broken links

## Output Files

- `docs/rfcs/rfc-NNNN-title-draft.md` - Individual RFC drafts
- `docs/rfcs/README.md` - RFC index
- Updated `sidebars.js`

## RFC Numbering

- Format: `rfc-NNNN-kebab-title-draft.md`
- Numbers are zero-padded (0001, 0002, etc.)
- Include `-draft` suffix for AI-generated drafts

## Quality Guidelines

- **Be realistic**: Don't propose unrealistic changes
- **Be specific**: Include technical details
- **Be balanced**: Show pros and cons
- **Be humble**: Acknowledge this is a draft needing review

## Error Handling

- **No opportunities found**: Create empty RFC directory with README
- **Weak evidence**: Mark as low priority, add many TODOs
- **Uncertain impact**: Clearly mark uncertainty

## Next Steps

After successful generation:
1. Review RFC drafts
2. Assign human owners
3. Schedule RFC review meetings
4. Proceed to generate runbooks

