# Generate ADRs Workflow

This workflow creates Architecture Decision Records based on detected technical decisions.

## Prerequisites

- Repository scan completed
- Architecture docs generated (optional but helpful)
- Write permissions to `docs/adrs/` directory

## Workflow Steps

### 1. Load Scan Results

Extract decision signals from scan data:
- Database choice
- Framework selection
- Authentication strategy
- Message broker
- Cloud provider
- Logging approach
- API design
- Testing strategy

### 2. Check Existing ADRs

- List files in `docs/adrs/`
- Parse existing ADR numbers
- Identify next available number
- Check for duplicate decisions

### 3. Detect Decisions

For each category, look for evidence:

**Database**: Check for database clients, migrations, connection strings
**Framework**: Check for framework imports, project structure
**Auth**: Check for auth libraries, JWT usage, OAuth config
**Messaging**: Check for Kafka, RabbitMQ, SQS clients
**Cloud**: Check for AWS/GCP/Azure SDKs, IaC files
**Logging**: Check for logging libraries, log config
**API**: Check for REST/GraphQL/gRPC implementations
**Testing**: Check for test frameworks, test config

### 4. Generate ADRs

For each detected decision:

1. Create ADR file: `docs/adrs/NNNN-kebab-title.md`
2. Include:
   - Title and status
   - Context (why this decision was needed)
   - Decision (what was chosen)
   - Consequences (positive, negative, neutral)
   - Alternatives considered
   - Implementation notes
   - References

3. Add AI-generated disclaimer
4. Mark uncertainty with TODO if evidence is weak
5. Link to relevant code files

### 5. Avoid Hallucination

- Only create ADRs with clear evidence
- Mark uncertain information
- Link to specific files as proof
- Add TODO sections for human input
- Request validation in disclaimer

### 6. Create ADR Index

Create/update `docs/adrs/README.md`:
- List all ADRs by status
- Group by category
- Include brief descriptions
- Link to ADR resources

### 7. Update Sidebars

Add ADRs to `sidebars.js`:
```javascript
{
  type: 'category',
  label: 'ADRs',
  items: [
    'adrs/README',
    'adrs/0001-use-postgresql',
    'adrs/0002-use-express',
    // ... more ADRs
  ],
}
```

### 8. Validate ADRs

- Check ADR numbering is sequential
- Verify frontmatter is correct
- Ensure all sections are present
- Check for broken links

## Output Files

- `docs/adrs/NNNN-title.md` - Individual ADRs
- `docs/adrs/README.md` - ADR index
- Updated `sidebars.js`

## ADR Numbering

- Format: `NNNN-kebab-case-title.md`
- Numbers are zero-padded (0001, 0002, etc.)
- Sequential numbering
- No gaps in sequence

## Quality Guidelines

- **Be specific**: Reference actual files and code
- **Be honest**: Mark uncertainty clearly
- **Be complete**: Include all ADR sections
- **Be helpful**: Provide context for future readers

## Error Handling

- **No decisions detected**: Create placeholder ADR index
- **Weak evidence**: Create draft ADR with TODOs
- **Numbering conflict**: Find next available number

## Next Steps

After successful generation:
1. Review generated ADRs
2. Validate technical accuracy
3. Proceed to generate RFCs

