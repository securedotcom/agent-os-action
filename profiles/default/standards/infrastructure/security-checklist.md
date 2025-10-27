# Infrastructure Security Checklist

## Secrets & Credentials
- [ ] **No Hardcoded Secrets**: Vault/secrets manager used
- [ ] **SSH Keys**: No private keys in repository
- [ ] **API Tokens**: Tokens managed securely
- [ ] **Certificate Management**: Certs properly managed
- [ ] **Credential Rotation**: Regular rotation implemented

## Network Security
- [ ] **Network Segmentation**: Proper VLAN/subnet isolation
- [ ] **Firewall Rules**: Least privilege network access
- [ ] **Security Groups**: Minimal port exposure
- [ ] **VPN/Bastion**: Secure remote access
- [ ] **TLS/SSL**: Encryption for all communication

## Access Control
- [ ] **IAM Policies**: Least privilege access
- [ ] **Role-Based Access**: RBAC implemented
- [ ] **MFA**: Multi-factor auth for critical access
- [ ] **Service Accounts**: Minimal permissions
- [ ] **Audit Logging**: All access logged

## Configuration Security
- [ ] **Secure Defaults**: No default passwords
- [ ] **Security Updates**: Automated patching
- [ ] **Container Security**: Base images scanned
- [ ] **Compliance**: SOC2/HIPAA requirements met
- [ ] **Encryption**: Data encrypted at rest and in transit

## Merge Blockers
- **[BLOCKER]** Hardcoded credentials or secrets
- **[BLOCKER]** Overly permissive security groups (0.0.0.0/0)
- **[BLOCKER]** Missing encryption configuration
- **[BLOCKER]** Root/admin access without MFA
- **[BLOCKER]** Exposed management ports (22, 3389, 3306)

