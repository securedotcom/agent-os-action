# Generate Runbooks Workflow

This workflow creates operational runbooks and troubleshooting guides.

## Prerequisites

- Repository scan completed
- Architecture docs generated
- Write permissions to `docs/playbooks/` directory

## Workflow Steps

### 1. Identify Services

From scan results, identify:
- Deployable services
- Critical components
- Services requiring operations

### 2. Detect Operational Info

For each service, gather:

**Deployment**:
- CI/CD configuration
- Deployment scripts
- Kubernetes manifests
- Docker files

**Monitoring**:
- Prometheus/Grafana config
- CloudWatch alarms
- Datadog monitors
- Log aggregation setup

**Database**:
- Migration files
- Backup scripts
- Connection pooling config

**Dependencies**:
- External APIs
- Message queues
- Cache systems

### 3. Generate Service Runbooks

For each service, create `docs/playbooks/{service-name}.md`:
- Service overview and owner
- Quick links (logs, metrics, alerts)
- Health check endpoints
- Key metrics and thresholds
- Running locally
- Deployment procedures
- Rollback procedures
- Common operations (scaling, restart, logs)
- Database operations
- Troubleshooting guides
- Alert response procedures
- Configuration reference
- Security procedures
- Maintenance tasks

### 4. Generate General Playbooks

Create general operational docs:

**On-Call Playbook** (`docs/playbooks/oncall.md`):
- On-call responsibilities
- Escalation procedures
- Common scenarios
- Communication channels

**Incident Response** (`docs/playbooks/incident-response.md`):
- Incident severity levels
- Response procedures
- Communication templates
- Post-mortem process

### 5. Integrate External Tools

If detected, integrate with:

**PagerDuty**:
- Link to on-call rotations
- Reference PagerDuty runbooks
- Include escalation procedures

**Monitoring Tools**:
- Link to dashboards
- Include alert thresholds
- Document metric meanings

### 6. Add Troubleshooting Guides

For common issues:
- High error rate
- High response time
- Service won't start
- Database connection failures
- Memory leaks
- Disk space issues

Include:
- Symptoms
- Investigation steps
- Resolution procedures
- Prevention strategies

### 7. Update Sidebars

Add runbooks to `sidebars.js`:
```javascript
{
  type: 'category',
  label: 'Runbooks',
  items: [
    'playbooks/oncall',
    'playbooks/incident-response',
    'playbooks/api-service',
    'playbooks/auth-service',
  ],
}
```

### 8. Validate Runbooks

- Check all commands are valid
- Verify links work
- Ensure procedures are actionable
- Test that examples are correct

## Output Files

- `docs/playbooks/{service}.md` - Service runbooks
- `docs/playbooks/oncall.md` - On-call procedures
- `docs/playbooks/incident-response.md` - Incident management
- Updated `sidebars.js`

## Quality Guidelines

- **Be actionable**: Provide copy-paste commands
- **Be specific**: Include actual URLs and paths
- **Be complete**: Cover common scenarios
- **Be current**: Mark sections that may become stale

## Error Handling

- **Deployment info missing**: Create runbook with TODOs
- **Monitoring not detected**: Add placeholder sections
- **Commands unverified**: Add warning to verify before use

## Next Steps

After successful generation:
1. Review runbooks with ops team
2. Test procedures in staging
3. Proceed to generate ML docs (if applicable)

