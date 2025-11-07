# Update Runbooks

Refresh operational runbooks and troubleshooting guides.

## What This Command Does

1. Scans repository for deployment and operational configuration
2. Identifies services requiring runbooks
3. Generates or updates runbooks with:
   - Deployment procedures
   - Health checks and monitoring
   - Common operations (scaling, restart, logs)
   - Troubleshooting guides
   - Alert response procedures
4. Preserves human edits
5. Creates PR with runbook updates

## When to Use

Use this command when:
- Deployment procedures have changed
- New services need runbooks
- Monitoring setup has changed
- Troubleshooting procedures need updating
- Runbooks are out of date

## What Gets Generated

For each service:
- Service overview and ownership
- Quick links (logs, metrics, dashboards)
- Health check endpoints
- Key metrics and alert thresholds
- Local development setup
- Deployment and rollback procedures
- Common operations (scaling, restart, database ops)
- Troubleshooting guides for common issues
- Configuration reference
- Maintenance procedures

## Workflow

{{workflows/scan-repository}}

{{workflows/detect-changes}}

{{workflows/generate-runbooks}}

{{workflows/update-sidebars}}

{{workflows/validate-docs}}

{{workflows/create-docs-pr}}

## Output

- Updated runbooks in `docs/playbooks/`
- Updated on-call and incident response guides
- Updated sidebars
- PR with runbook changes

## Review

**Critical**: Review runbooks carefully before using in production:
- Test all commands in staging first
- Verify health check endpoints
- Validate metric thresholds
- Check troubleshooting procedures
- Ensure rollback procedures are safe
- Confirm links to dashboards and logs work

## Integration

If you use:
- **PagerDuty**: Link to on-call rotations
- **Datadog/New Relic**: Link to dashboards
- **Slack**: Add notification channels
- **Jira**: Link to incident tickets

