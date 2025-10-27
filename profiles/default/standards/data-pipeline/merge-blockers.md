# Data Pipeline Merge Blockers

## Security
- **[BLOCKER]** Hardcoded credentials
- **[BLOCKER]** Unencrypted PII
- **[BLOCKER]** Missing access logging
- **[BLOCKER]** Production data in non-prod environments

## Data Quality
- **[BLOCKER]** No schema validation
- **[BLOCKER]** Data loss in pipeline
- **[BLOCKER]** No deduplication logic
- **[BLOCKER]** Missing data quality checks

## Performance & Reliability
- **[BLOCKER]** Full dataset in memory
- **[BLOCKER]** No retry logic
- **[BLOCKER]** Missing idempotency
- **[BLOCKER]** No dead letter queue for failures

## Testing
- **[BLOCKER]** No end-to-end tests
- **[BLOCKER]** Missing error handling tests
- **[BLOCKER]** No data accuracy validation

