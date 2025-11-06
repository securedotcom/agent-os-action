# Agent-OS: Security Control Plane

**Enterprise-Grade Security Analysis Platform**  
Combines deterministic scanning + AI analysis + supply chain security

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

---

## 🎯 What is Agent-OS?

Agent-OS is a **complete security control plane** that transforms how organizations secure their software:

- **Deterministic Scanning**: TruffleHog, Gitleaks, Semgrep, Trivy, Checkov
- **Dual AI Analysis**: Claude (Anthropic) + Foundation-Sec-8B (SageMaker)
- **Supply Chain Security**: SBOM generation, SLSA provenance, artifact signing
- **Policy Enforcement**: Rego-based PR/release gates
- **Risk-Based Prioritization**: CVSS × Exploitability × Reachability × Business Impact

**Result**: Find 8 critical CVEs in 11 minutes for $0.35

---

## 🚀 Quick Start (5 Minutes)

### Prerequisites
- Python 3.9+
- Git
- API key: [Anthropic Claude](https://console.anthropic.com/) (optional: AWS for Foundation-Sec)

### Installation

   ```bash
# Clone repository
git clone https://github.com/securedotcom/agent-os.git
cd agent-os

# Install dependencies
pip install -r requirements.txt

# Install scanners (macOS)
brew install trufflehog gitleaks semgrep trivy checkov syft cosign opa

# Set API key
export ANTHROPIC_API_KEY="your-key-here"

# Run analysis
python3 scripts/run_ai_audit.py /path/to/your/repo audit
```

**That's it!** Results in `.agent-os/reviews/audit-report.md`

---

## 📊 What You Get

### Comprehensive Security Analysis

| Component | What It Does | Cost |
|-----------|--------------|------|
| **Secret Scanning** | TruffleHog + Gitleaks | $0 |
| **SAST** | Semgrep (p/security-audit) | $0 |
| **CVE Detection** | Trivy vulnerability scanner | $0 |
| **IaC Security** | Checkov for infrastructure | $0 |
| **AI Analysis** | Claude + Foundation-Sec-8B | $0.35 |
| **Threat Modeling** | STRIDE methodology | Included |
| **SBOM** | Syft + CycloneDX | $0 |
| **Provenance** | SLSA L2 attestation | $0 |
| **Policy Gates** | OPA/Rego enforcement | $0 |

**Total**: $0.35 per analysis (or $0 with Foundation-Sec only)

### Example Output

```
📊 Analysis Results:
   - 0 verified secrets ✅
   - 4 SAST findings ⚠️
   - 8 critical CVEs 🔴
   - 28 total vulnerabilities
   - 25 threats identified (STRIDE)
   - 1,458 SBOM components
   - SLSA L2 provenance ✅
   
💰 Cost: $0.35
⏱️  Duration: 11 minutes
```

---

## 🏗️ Architecture

### Hybrid Security Analysis

```
┌─────────────────────────────────────────────────────────────┐
│                    Agent-OS Control Plane                    │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Deterministic│  │  AI Analysis │  │Supply Chain  │      │
│  │   Scanning   │  │              │  │   Security   │      │
│  ├──────────────┤  ├──────────────┤  ├──────────────┤      │
│  │ TruffleHog   │  │ Claude AI    │  │ SBOM (Syft)  │      │
│  │ Gitleaks     │  │ Foundation-  │  │ SLSA L2      │      │
│  │ Semgrep      │  │   Sec-8B     │  │ Cosign       │      │
│  │ Trivy        │  │ 7 AI Agents  │  │ Signing      │      │
│  │ Checkov      │  │ Aardvark     │  │              │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│           │                │                  │              │
│           └────────────────┴──────────────────┘              │
│                            │                                 │
│                  ┌─────────▼─────────┐                       │
│                  │  Normalization    │                       │
│                  │  (35+ fields)     │                       │
│                  └─────────┬─────────┘                       │
│                            │                                 │
│                  ┌─────────▼─────────┐                       │
│                  │  Risk Scoring     │                       │
│                  │  (PRD Formula)    │                       │
│                  └─────────┬─────────┘                       │
│                            │                                 │
│                  ┌─────────▼─────────┐                       │
│                  │  Policy Gates     │                       │
│                  │  (OPA/Rego)       │                       │
│                  └─────────┬─────────┘                       │
│                            │                                 │
│                  ┌─────────▼─────────┐                       │
│                  │   Reports         │                       │
│                  │   SARIF/JSON/MD   │                       │
│                  └───────────────────┘                       │
└─────────────────────────────────────────────────────────────┘
```

---

## 🎓 Core Concepts

### 1. Deterministic + AI Hybrid

**Why Both?**
- **Deterministic**: Fast, objective, free (TruffleHog, Semgrep, Trivy)
- **AI**: Context-aware, finds edge cases (Claude, Foundation-Sec-8B)
- **Combined**: Best security coverage

**Example**:
- Deterministic: Found 28 CVEs
- AI: Upgraded 4 to CRITICAL based on context
- Result: Better prioritization

### 2. Risk-Based Prioritization

**Formula**: `Risk = CVSS × Exploitability × Reachability × Business Impact`

**Not all CVEs are equal**:
- CVSS 9.0 in unused library = LOW risk
- CVSS 7.0 in public API with PoC = CRITICAL risk

### 3. Policy as Code

**Rego-based gates**:
```rego
# Block PRs with verified secrets
critical_secret(f) if {
    f.category == "SECRETS"
    f.secret_verified == "true"
}

# Block releases without SBOM
release_requires_sbom if {
    input.sbom_present == true
}
```

### 4. Supply Chain Security

**SBOM + SLSA + Signing**:
- Know what's in your software (SBOM)
- Prove where it came from (SLSA provenance)
- Verify it hasn't been tampered with (Cosign signing)

---

## 📚 Documentation

### Getting Started
- [Quick Start Guide](docs/QUICK_START.md)
- [Installation](docs/INSTALLATION.md)
- [Configuration](docs/CONFIGURATION.md)

### Features
- [Deterministic Scanning](docs/DETERMINISTIC_SCANNING.md)
- [AI Analysis](docs/AI_ANALYSIS.md)
- [Supply Chain Security](docs/SUPPLY_CHAIN.md)
- [Policy Gates](docs/POLICY_GATES.md)
- [Risk Scoring](docs/RISK_SCORING.md)

### Advanced
- [SageMaker Setup](docs/SAGEMAKER_SETUP.md)
- [Multi-Repo Coordination](docs/MULTI_REPO.md)
- [GitHub Actions Integration](docs/GITHUB_ACTIONS.md)
- [API Reference](docs/API.md)

### Operations
- [Roadmap](ROADMAP_30_60_90.md) - 30/60/90 day plan
- [Execution Summary](EXECUTION_SUMMARY.md) - Progress tracking
- [Changelog](CHANGELOG.md)

---

## 🔧 Usage Examples

### 1. Basic Security Audit

```bash
# Run complete audit
python3 scripts/run_ai_audit.py /path/to/repo audit

# Results in:
# - .agent-os/reviews/audit-report.md
# - .agent-os/reviews/results.sarif
# - .agent-os/threat-model.json
```

### 2. Hybrid Analysis (Deterministic + AI)

```bash
# With Foundation-Sec-8B (FREE!)
export SAGEMAKER_ENDPOINT="your-endpoint"
export AWS_ACCESS_KEY_ID="your-key"
export AWS_SECRET_ACCESS_KEY="your-secret"

python3 scripts/hybrid_analyzer.py /path/to/repo \
  --enable-semgrep \
  --enable-trivy \
  --enable-foundation-sec \
  --severity-filter critical,high
```

### 3. Generate SBOM

```bash
# Create Software Bill of Materials
python3 scripts/sbom_generator.py /path/to/repo \
  --version v1.0.0 \
  -o sbom.json

# Generate SLSA provenance
python3 scripts/sign_release.py provenance sbom.json \
  --repo org/repo \
  --commit $COMMIT_SHA \
  --level L2 \
  -o provenance.json
```

### 4. Policy Enforcement

```bash
# Normalize findings
python3 scripts/agentos normalize \
  --tool all \
  --input findings_*.json \
  -o normalized.json

# Calculate risk scores
python3 scripts/risk_scorer.py normalized.json \
  --business-impact high \
  -o scored.json

# Apply PR gate
python3 scripts/gate.py \
  --stage pr \
  --input scored.json
# Output: PASS/FAIL decision
```

### 5. Multi-Repo Scanning

```bash
# Create config
cat > repos.json << 'EOF'
{
  "repositories": [
    {
      "repo_url": "https://github.com/org/repo1",
      "repo_name": "org/repo1",
      "branch": "main",
      "scan_types": ["secrets", "sast", "vuln"]
    }
  ]
}
EOF

# Scan multiple repos
python3 scripts/multi_repo_coordinator.py repos.json \
  --concurrent 3 \
  --timeout 600 \
  -o scan_results/
```

---

## 🎯 Use Cases

### 1. Pre-Commit Security Check
```bash
# Fast local scan (<1 min)
python3 scripts/run_ai_audit.py . audit --only-changed
```

### 2. PR Security Gate
```yaml
# .github/workflows/pr-gate.yml
- name: Security Scan
  run: |
    python3 scripts/run_ai_audit.py . audit
    python3 scripts/gate.py --stage pr --input findings.json
```

### 3. Release Validation
```yaml
# .github/workflows/release.yml
- name: Generate SBOM
  run: python3 scripts/sbom_generator.py . -o sbom.json
  
- name: SLSA Provenance
  run: python3 scripts/sign_release.py provenance sbom.json

- name: Release Gate
  run: python3 scripts/gate.py --stage release --input findings.json
```

### 4. Nightly Security Scan
```bash
# Scan all repos
python3 scripts/multi_repo_coordinator.py repos.json

# Deduplicate findings
python3 scripts/deduplicator.py scan_results/ -o deduped.json

# Generate dashboard
python3 scripts/generate_dashboard.py deduped.json
```

---

## 🏆 Success Metrics

### Real-World Results (spring_auth analysis)

| Metric | Result |
|--------|--------|
| **Secrets Found** | 0 (excellent!) |
| **Critical CVEs** | 8 identified |
| **AI Findings** | 28 code quality issues |
| **Threats** | 25 (STRIDE) |
| **SBOM Components** | 1,458 |
| **Cost** | $0.35 |
| **Duration** | 11 minutes |
| **False Positives** | <5% |

### PRD Compliance

| Metric | Target | Achieved |
|--------|--------|----------|
| PR scan time (p50) | <3 min | ✅ <2 min |
| PR scan time (p95) | <7 min | ✅ <5 min |
| Secret block rate | 90%+ | ✅ 100% |
| SBOM coverage | 90%+ | ✅ 100% |
| SLSA provenance | L1-L2 | ✅ L2 |

---

## 💰 Cost Analysis

### Per-Analysis Cost

| Scenario | Tools | Cost |
|----------|-------|------|
| **Deterministic Only** | TruffleHog, Gitleaks, Semgrep, Trivy | $0 |
| **With Claude AI** | + Claude | $0.35 |
| **With Foundation-Sec** | + Foundation-Sec-8B (SageMaker) | $0 |
| **Dual AI** | Claude + Foundation-Sec | $0.35 |

### Monthly Cost (100 repos, daily scans)

| Scenario | Cost/Month |
|----------|------------|
| Deterministic only | $0 |
| Claude AI | ~$1,050 (3,000 scans × $0.35) |
| Foundation-Sec only | $0 + SageMaker (~$1,000) |
| Hybrid (smart routing) | ~$500-750 |

**Optimization**: Use deterministic for PRs, AI for releases

---

## 🛠️ Technology Stack

### 100% Open Source Tools

| Tool | License | Purpose |
|------|---------|---------|
| **TruffleHog** | AGPL 3.0 | Verified secrets |
| **Gitleaks** | MIT | Secret patterns |
| **Semgrep** | LGPL 2.1 | SAST |
| **Trivy** | Apache 2.0 | CVE scanning |
| **Checkov** | Apache 2.0 | IaC security |
| **Syft** | Apache 2.0 | SBOM generation |
| **Cosign** | Apache 2.0 | Artifact signing |
| **OPA** | Apache 2.0 | Policy engine |

### AI Providers

| Provider | Type | Cost |
|----------|------|------|
| **Anthropic Claude** | API | ~$0.35/analysis |
| **Foundation-Sec-8B** | SageMaker/Local | Free (after setup) |
| **OpenAI GPT-4** | API | ~$0.50/analysis |
| **Ollama** | Local | Free |

---

## 🔐 Security & Privacy

### Data Handling
- **Code**: Never leaves your infrastructure (except AI API calls)
- **Secrets**: Detected but never logged
- **Results**: Stored locally in `.agent-os/`
- **API**: Only code snippets sent to AI (configurable)

### Compliance
- **SOC 2**: Compatible architecture
- **GDPR**: No PII collection
- **SLSA**: L2 provenance support
- **SBOM**: CycloneDX standard

### Best Practices
- Store API keys in environment variables
- Use `.gitignore` for `.agent-os/` results
- Enable signing for production releases
- Rotate AWS credentials regularly

---

## 🚀 Roadmap

### ✅ Completed (Day 60)
- Unified finding schema (35+ fields)
- Policy engine (OPA/Rego)
- Verified secrets (TruffleHog + Gitleaks)
- IaC scanning (Checkov)
- SBOM generation (Syft)
- SLSA provenance (L1-L2)
- Risk scoring engine
- Multi-repo coordinator
- Deduplication
- Dual AI support (Claude + Foundation-Sec)

### 🔄 In Progress (Day 90)
- Data lake (PostgreSQL)
- Dashboards (Grafana)
- Pre-commit hooks
- SLA tracking
- Auto-remediation suggestions

### 🔮 Future (Beyond Day 90)
- SLSA L3 provenance
- Kubernetes operator
- VS Code extension
- Slack/Teams integration
- Custom rule engine

See [ROADMAP_30_60_90.md](ROADMAP_30_60_90.md) for details.

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Quick Contribution Guide

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/agent-os.git
cd agent-os

# Create branch
git checkout -b feature/your-feature

# Make changes and test
python3 -m pytest tests/

# Submit PR
git push origin feature/your-feature
```

---

## 📞 Support

### Community
- **GitHub Issues**: Bug reports and feature requests
- **Discussions**: Questions and community support
- **Discord**: Real-time chat (coming soon)

### Enterprise
- **Email**: enterprise@agent-os.dev
- **Slack**: Private channel for customers
- **SLA**: 24/7 support available

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

### Open Source Tools
- Anchore (Syft, Grype)
- Sigstore (Cosign)
- SLSA Framework
- Aqua Security (Trivy)
- Semgrep
- TruffleHog
- Open Policy Agent

### AI Providers
- Anthropic (Claude)
- Cisco (Foundation-Sec-8B)
- OpenAI (GPT-4)

---

## 📊 Stats

![GitHub stars](https://img.shields.io/github/stars/securedotcom/agent-os)
![GitHub forks](https://img.shields.io/github/forks/securedotcom/agent-os)
![GitHub issues](https://img.shields.io/github/issues/securedotcom/agent-os)
![GitHub license](https://img.shields.io/github/license/securedotcom/agent-os)

**Built with ❤️ by the Agent-OS team**

---

## 🎯 TL;DR

**Agent-OS** = Deterministic scanning + AI analysis + Supply chain security

**Install**: `brew install trufflehog gitleaks semgrep trivy checkov syft cosign opa`  
**Run**: `python3 scripts/run_ai_audit.py /path/to/repo audit`  
**Cost**: $0.35 per analysis (or $0 with Foundation-Sec)  
**Time**: 11 minutes  
**Result**: 8 critical CVEs found, 25 threats identified, 1,458 SBOM components

**Production-ready. Enterprise-grade. Open source.**

---

*Last updated: November 6, 2025*  
*Version: Day 60 Complete*
