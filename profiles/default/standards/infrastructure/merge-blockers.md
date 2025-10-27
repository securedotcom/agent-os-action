# Infrastructure Merge Blockers

## Security
- **[BLOCKER]** Hardcoded secrets or credentials
- **[BLOCKER]** Overly permissive security groups (0.0.0.0/0)
- **[BLOCKER]** Missing encryption at rest
- **[BLOCKER]** No MFA for admin access
- **[BLOCKER]** Exposed management ports

## Configuration
- **[BLOCKER]** Terraform plan fails
- **[BLOCKER]** Default/weak passwords
- **[BLOCKER]** No resource tagging
- **[BLOCKER]** Missing backup configuration
- **[BLOCKER]** No monitoring/alerting

## Compliance & Governance
- **[BLOCKER]** Non-compliant with security policies
- **[BLOCKER]** Missing audit logging
- **[BLOCKER]** No disaster recovery plan
- **[BLOCKER]** Unapproved cloud regions

## Cost & Efficiency
- **[BLOCKER]** No resource limits
- **[BLOCKER]** Missing auto-scaling
- **[BLOCKER]** Unused resources not cleaned up

