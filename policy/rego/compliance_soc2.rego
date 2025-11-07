# SOC 2 Compliance Policy Pack - Phase 2.5
# Maps security findings to SOC 2 Trust Service Criteria
# Reference: https://us.aicpa.org/content/dam/aicpa/interestareas/frc/assuranceadvisoryservices/downloadabledocuments/trust-services-criteria.pdf

package compliance.soc2

import future.keywords.if
import future.keywords.in

# ========================================
# SOC 2 CONTROL MAPPINGS
# ========================================

# CC6.1: Logical and Physical Access Controls
# "The entity implements logical access security software, infrastructure, and architectures"
cc6_1_controls := {
    "secrets_verified": {
        "description": "All secrets must be verified before merge",
        "severity": "critical",
        "requirement": "No verified secrets in code"
    },
    "weak_auth": {
        "description": "Authentication mechanisms must be secure",
        "severity": "high",
        "requirement": "No weak authentication patterns"
    }
}

# CC6.6: Logical and Physical Access Controls - Encryption
# "The entity implements logical access security measures to protect against threats from sources outside its system boundaries"
cc6_6_controls := {
    "sbom_present": {
        "description": "All releases must have SBOM + signature",
        "severity": "critical",
        "requirement": "SBOM with valid signature required"
    },
    "encryption": {
        "description": "Data must be encrypted in transit and at rest",
        "severity": "high",
        "requirement": "No unencrypted sensitive data"
    }
}

# CC7.2: System Monitoring
# "The entity monitors system components and the operation of those components for anomalies"
cc7_2_controls := {
    "vuln_remediation": {
        "description": "Critical CVEs must be fixed within 30 days",
        "severity": "critical",
        "requirement": "MTTR <= 30 days for critical"
    },
    "continuous_monitoring": {
        "description": "Security scanning must be continuous",
        "severity": "medium",
        "requirement": "Daily scans for production systems"
    }
}

# CC7.3: System Monitoring - Evaluation and Management
# "The entity evaluates security events to determine whether they could or have resulted in a failure"
cc7_3_controls := {
    "incident_response": {
        "description": "Security incidents must be tracked and resolved",
        "severity": "high",
        "requirement": "All P0/P1 findings must be triaged within 24h"
    }
}

# ========================================
# COMPLIANCE EVALUATION
# ========================================

# CC6.1: Check for verified secrets and weak auth
cc6_1_violations := violations if {
    verified_secrets := [f | 
        f := input.findings[_]
        f.category == "SECRETS"
        f.secret_verified == "true"
    ]
    
    weak_auth := [f |
        f := input.findings[_]
        f.category == "SAST"
        contains(lower(f.rule_name), "auth")
        f.severity in ["high", "critical"]
    ]
    
    violations := array.concat(verified_secrets, weak_auth)
}

cc6_1_compliant := count(cc6_1_violations) == 0

# CC6.6: Check for SBOM and encryption
cc6_6_compliant := compliant if {
    # Check if SBOM is present and signed
    input.sbom_present == true
    input.sbom_signed == true
    
    # Check for encryption issues
    encryption_issues := [f |
        f := input.findings[_]
        f.category in ["SAST", "IAC"]
        contains(lower(f.rule_name), "encrypt")
        f.severity in ["high", "critical"]
    ]
    
    compliant := count(encryption_issues) == 0
} else := false

# CC7.2: Check vulnerability remediation SLA
cc7_2_compliant := compliant if {
    # Check for overdue critical vulnerabilities
    overdue_vulns := [f |
        f := input.findings[_]
        f.severity == "critical"
        f.status == "open"
        days_open(f) > 30
    ]
    
    compliant := count(overdue_vulns) == 0
} else := false

# CC7.3: Check incident response
cc7_3_compliant := compliant if {
    # Check for untriaged high-severity findings
    untriaged := [f |
        f := input.findings[_]
        f.severity in ["critical", "high"]
        f.status == "open"
        hours_open(f) > 24
    ]
    
    compliant := count(untriaged) == 0
} else := false

# ========================================
# HELPER FUNCTIONS
# ========================================

# Calculate days since finding was opened
days_open(finding) := days if {
    # Parse ISO timestamp
    first_seen := time.parse_rfc3339_ns(finding.first_seen_at)
    now := time.now_ns()
    days := (now - first_seen) / 86400000000000  # nanoseconds to days
}

# Calculate hours since finding was opened
hours_open(finding) := hours if {
    first_seen := time.parse_rfc3339_ns(finding.first_seen_at)
    now := time.now_ns()
    hours := (now - first_seen) / 3600000000000  # nanoseconds to hours
}

# ========================================
# OVERALL COMPLIANCE STATUS
# ========================================

compliance_status := {
    "CC6.1": {
        "compliant": cc6_1_compliant,
        "violations": count(cc6_1_violations),
        "description": "Logical and Physical Access Controls"
    },
    "CC6.6": {
        "compliant": cc6_6_compliant,
        "description": "Encryption and SBOM Requirements"
    },
    "CC7.2": {
        "compliant": cc7_2_compliant,
        "description": "Vulnerability Remediation SLA"
    },
    "CC7.3": {
        "compliant": cc7_3_compliant,
        "description": "Incident Response Timeliness"
    }
}

# Overall compliance (all controls must pass)
overall_compliant := cc6_1_compliant and cc6_6_compliant and cc7_2_compliant and cc7_3_compliant

# Compliance decision
decision := {
    "compliant": overall_compliant,
    "status": compliance_status,
    "summary": summary_message
}

summary_message := "✅ SOC 2 compliant" if overall_compliant
summary_message := sprintf("❌ SOC 2 non-compliant: %d control(s) failing", [failing_controls]) if not overall_compliant

failing_controls := count([c | 
    c := compliance_status[_]
    c.compliant == false
])

# ========================================
# REMEDIATION GUIDANCE
# ========================================

remediation_steps := steps if {
    not overall_compliant
    
    steps_list := []
    
    # CC6.1 remediation
    steps_list := array.concat(steps_list, cc6_1_remediation) if not cc6_1_compliant
    
    # CC6.6 remediation
    steps_list := array.concat(steps_list, cc6_6_remediation) if not cc6_6_compliant
    
    # CC7.2 remediation
    steps_list := array.concat(steps_list, cc7_2_remediation) if not cc7_2_compliant
    
    # CC7.3 remediation
    steps_list := array.concat(steps_list, cc7_3_remediation) if not cc7_3_compliant
    
    steps := steps_list
} else := []

cc6_1_remediation := [
    "1. Remove all verified secrets from code",
    "2. Rotate compromised credentials",
    "3. Implement secret management (Vault/AWS Secrets Manager)",
    "4. Add pre-commit hooks to prevent future leaks"
]

cc6_6_remediation := [
    "1. Generate SBOM using Syft: syft scan . -o cyclonedx-json",
    "2. Sign SBOM with Cosign: cosign sign-blob --key cosign.key sbom.json",
    "3. Enable encryption for sensitive data paths",
    "4. Review IaC for encryption misconfigurations"
]

cc7_2_remediation := [
    "1. Triage all critical vulnerabilities immediately",
    "2. Create remediation plan with 30-day SLA",
    "3. Enable automated dependency updates",
    "4. Schedule daily security scans"
]

cc7_3_remediation := [
    "1. Triage all high-severity findings within 24 hours",
    "2. Assign owners to open security findings",
    "3. Set up alerting for new critical findings",
    "4. Document incident response procedures"
]

