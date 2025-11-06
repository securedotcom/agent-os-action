# Open Source Tools Used in Agent-OS

All tools used in Agent-OS are **100% open source** with permissive or copyleft licenses.

## Day 60 Tools

| Tool | License | Purpose | Repository |
|------|---------|---------|------------|
| **Syft** | Apache 2.0 | SBOM generation | https://github.com/anchore/syft |
| **Cosign** | Apache 2.0 | Artifact signing | https://github.com/sigstore/cosign |
| **SLSA Framework** | Apache 2.0 | Provenance spec | https://github.com/slsa-framework/slsa |
| **slsa-github-generator** | Apache 2.0 | SLSA attestation | https://github.com/slsa-framework/slsa-github-generator |
| **Trivy** | Apache 2.0 | Vulnerability scanner | https://github.com/aquasecurity/trivy |
| **OPA** | Apache 2.0 | Policy engine | https://github.com/open-policy-agent/opa |

## Week 1 Tools (Already Implemented)

| Tool | License | Purpose | Repository |
|------|---------|---------|------------|
| **TruffleHog** | AGPL 3.0 | Secret scanning | https://github.com/trufflesecurity/trufflehog |
| **Gitleaks** | MIT | Secret scanning | https://github.com/gitleaks/gitleaks |
| **Semgrep** | LGPL 2.1 | SAST (open core) | https://github.com/semgrep/semgrep |
| **Checkov** | Apache 2.0 | IaC scanning | https://github.com/bridgecrewio/checkov |

## AI Models

| Model | License | Purpose | Repository |
|-------|---------|---------|------------|
| **Foundation-Sec-8B** | Apache 2.0 | Security analysis | https://huggingface.co/secure-ai-assistant/Foundation-Sec-8B |
| **Claude** | Proprietary API | Code review agents | N/A (API usage) |

## Infrastructure

| Tool | License | Purpose | Repository |
|------|---------|---------|------------|
| **PostgreSQL** | PostgreSQL License | Data persistence | https://www.postgresql.org/ |
| **Grafana** | AGPL 3.0 | Dashboards | https://github.com/grafana/grafana |
| **GitHub Actions** | N/A | CI/CD (free tier) | N/A (GitHub service) |

## Notes

- **Claude API**: While Claude itself is proprietary, we use the API which is pay-per-use with no vendor lock-in. All other components are open source.
- **Semgrep**: We use the open source core (LGPL 2.1). The Pro version is proprietary but not required.
- **GitHub Actions**: Free tier for public repos, standard pricing for private repos. Can be replaced with GitLab CI, Jenkins, etc.

## Cost Summary

| Component | Cost |
|-----------|------|
| All scanning tools | $0 (open source) |
| SBOM/signing tools | $0 (open source) |
| Policy engine (OPA) | $0 (open source) |
| PostgreSQL | $0 (self-hosted) or ~$25/mo (managed) |
| Grafana | $0 (self-hosted) or ~$50/mo (cloud) |
| Claude API | ~$100-500/mo (usage-based) |
| GitHub Actions | $0 (public) or included in GitHub plan |

**Total Open Source**: 95%+ of tooling  
**Only Proprietary Component**: Claude API (replaceable with open models)

