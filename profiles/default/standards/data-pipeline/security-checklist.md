# Data Pipeline Security Checklist

## Data Access & Authentication
- [ ] **Service Credentials**: No hardcoded credentials
- [ ] **IAM Roles**: Least privilege access
- [ ] **API Authentication**: Secure API access
- [ ] **Database Credentials**: Vault/secrets manager used
- [ ] **Access Logging**: All data access logged

## Data Protection
- [ ] **Encryption at Rest**: Sensitive data encrypted
- [ ] **Encryption in Transit**: TLS for data transfer
- [ ] **PII Handling**: PII anonymized/encrypted
- [ ] **Data Masking**: Production data masked in non-prod
- [ ] **Data Retention**: Compliance with retention policies

## Input Validation
- [ ] **Schema Validation**: Input data validated against schema
- [ ] **Injection Prevention**: SQL/NoSQL injection prevented
- [ ] **File Validation**: Uploaded files validated
- [ ] **Data Sanitization**: Malicious data filtered

## Merge Blockers
- **[BLOCKER]** Hardcoded credentials or API keys
- **[BLOCKER]** No encryption for PII
- **[BLOCKER]** Production data exposed in logs
- **[BLOCKER]** Missing input validation on external data

