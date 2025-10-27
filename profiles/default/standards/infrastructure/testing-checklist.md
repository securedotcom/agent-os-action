# Infrastructure Testing Checklist

## Infrastructure as Code Testing
- [ ] **Syntax Validation**: Terraform validate/plan passes
- [ ] **Linting**: tflint/checkov checks pass
- [ ] **Unit Tests**: Terratest for critical resources
- [ ] **Policy Validation**: OPA/Sentinel policies enforced

## Security Testing
- [ ] **Security Scanning**: Container images scanned
- [ ] **Vulnerability Assessment**: Known CVEs identified
- [ ] **Compliance Checks**: CIS benchmarks validated
- [ ] **Penetration Testing**: External pen test completed

## Disaster Recovery Testing
- [ ] **Backup Testing**: Restore procedures tested
- [ ] **Failover Testing**: HA failover validated
- [ ] **Chaos Engineering**: Failure scenarios tested
- [ ] **RTO/RPO**: Recovery objectives met

## Integration Testing
- [ ] **Deployment Pipeline**: CI/CD tested
- [ ] **Service Dependencies**: Integration validated
- [ ] **Network Connectivity**: Routes/firewall rules tested
- [ ] **Smoke Tests**: Post-deployment validation

## Merge Blockers
- **[BLOCKER]** Terraform plan fails
- **[BLOCKER]** Security scan failures
- **[BLOCKER]** No backup/restore tests
- **[BLOCKER]** Untested disaster recovery procedures

