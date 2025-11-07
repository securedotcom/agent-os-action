# Create ADR

Generate a new Architecture Decision Record.

## What This Command Does

1. Scans repository for technical decisions
2. Identifies decisions not yet documented
3. Creates new ADRs with proper numbering
4. Includes context, decision, consequences, and alternatives
5. Marks with AI disclaimer for review
6. Updates ADR index
7. Creates PR with new ADRs

## When to Use

Use this command when:
- New technical decisions have been made
- Existing decisions need documentation
- ADRs are missing or out of date
- Want to document architecture choices

## Usage

Run this command to generate ADRs for detected technical decisions.

## What Gets Documented

The agent looks for evidence of decisions in:
- Database choices (connection strings, migrations, ORMs)
- Framework selections (imports, project structure)
- Authentication strategies (auth libraries, JWT, OAuth)
- Message brokers (Kafka, RabbitMQ, SQS clients)
- Cloud providers (AWS/GCP/Azure SDKs, IaC)
- Logging approaches (logging libraries, configuration)
- API design (REST/GraphQL/gRPC)
- Testing strategies (test frameworks, coverage)

## Workflow

{{workflows/scan-repository}}

{{workflows/generate-adrs}}

{{workflows/update-sidebars}}

{{workflows/validate-docs}}

{{workflows/create-docs-pr}}

## Output

- New ADR files in `docs/adrs/`
- Updated `docs/adrs/README.md` index
- Updated sidebars
- PR with new ADRs

## Review

Review generated ADRs for:
- Accuracy of detected decisions
- Completeness of context
- Validity of alternatives considered
- Correctness of consequences
- Any TODOs that need filling in

