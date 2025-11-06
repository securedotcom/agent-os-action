# Agent-OS PR Policy
# Purpose: Deterministic gates for pull requests
# Decision: pass/fail based on verified secrets, critical IaC, exploitable SAST

package agentos.pr

import future.keywords.if
import future.keywords.in

# Default decision (pass if no critical findings)
default decision := {
    "decision": "pass",
    "reasons": [],
    "blocks": [],
    "warnings": []
}

# ========================================
# CRITICAL FINDINGS (MUST BLOCK)
# ========================================

# 1. Verified Secrets (cross-validated by TruffleHog + Gitleaks)
critical_secret(f) if {
    f.category == "SECRETS"
    f.secret_verified == "true"  # MUST be verified via API
}

# 2. Critical IaC with public exposure
critical_iac(f) if {
    f.category == "IAC"
    f.severity in ["critical", "high"]
    f.service_tier == "public"  # Only block if publicly exposed
}

# 3. Exploitable SAST (trivial exploitability)
critical_sast(f) if {
    f.category == "SAST"
    f.severity == "critical"
    f.exploitability == "trivial"  # Easy to exploit
}

# 4. High CVSS with reachability
critical_deps(f) if {
    f.category == "DEPS"
    f.cvss >= 9.0  # CVSS >= 9.0
    f.reachability == "yes"  # Code is actually reachable
}

# Helper: Check if finding is critical
is_critical(f) if critical_secret(f)
is_critical(f) if critical_iac(f)
is_critical(f) if critical_sast(f)
is_critical(f) if critical_deps(f)

# Collect all blocking findings
blocking_findings := [f | f := input.findings[_]; is_critical(f)]
block_ids := [f.id | f := blocking_findings[_]]

# ========================================
# WARNING FINDINGS (DON'T BLOCK, BUT ALERT)
# ========================================

# Unverified secrets (warn but don't block)
warning_secret(f) if {
    f.category == "SECRETS"
    f.secret_verified == "false"  # Not verified
}

# Medium/High severity without reachability
warning_deps(f) if {
    f.category == "DEPS"
    f.severity in ["medium", "high"]
    f.reachability == "unknown"
}

# High severity SAST with complex exploitability
warning_sast(f) if {
    f.category == "SAST"
    f.severity == "high"
    f.exploitability in ["complex", "theoretical"]
}

is_warning(f) if warning_secret(f)
is_warning(f) if warning_deps(f)
is_warning(f) if warning_sast(f)

warning_findings := [f | f := input.findings[_]; is_warning(f)]
warning_ids := [f.id | f := warning_findings[_]]

# ========================================
# FINAL DECISION
# ========================================

# Block if any critical findings
decision := result if {
    count(block_ids) > 0
    reasons_list := array.concat(
        critical_reasons,
        [sprintf("See full report for %d warnings", [count(warning_ids)])]
    )
    result := {
        "decision": "fail",
        "reasons": reasons_list,
        "blocks": block_ids,
        "warnings": warning_ids
    }
}

# Critical reasons breakdown
critical_reasons := r if {
    secrets := [f | f := blocking_findings[_]; critical_secret(f)]
    iac := [f | f := blocking_findings[_]; critical_iac(f)]
    sast := [f | f := blocking_findings[_]; critical_sast(f)]
    deps := [f | f := blocking_findings[_]; critical_deps(f)]
    
    r := array.concat(
        array.concat(
            secret_reasons(secrets),
            iac_reasons(iac)
        ),
        array.concat(
            sast_reasons(sast),
            deps_reasons(deps)
        )
    )
}

secret_reasons(secrets) := [sprintf("🔴 %d verified secret(s) detected - MUST FIX", [count(secrets)])] if count(secrets) > 0
secret_reasons(secrets) := [] if count(secrets) == 0

iac_reasons(iac) := [sprintf("🔴 %d critical IaC misconfiguration(s) with public exposure - MUST FIX", [count(iac)])] if count(iac) > 0
iac_reasons(iac) := [] if count(iac) == 0

sast_reasons(sast) := [sprintf("🔴 %d critical SAST finding(s) with trivial exploitability - MUST FIX", [count(sast)])] if count(sast) > 0
sast_reasons(sast) := [] if count(sast) == 0

deps_reasons(deps) := [sprintf("🔴 %d critical CVE(s) with confirmed reachability - MUST FIX", [count(deps)])] if count(deps) > 0
deps_reasons(deps) := [] if count(deps) == 0

# Pass with warnings if only warnings exist
decision := result if {
    count(block_ids) == 0
    count(warning_ids) > 0
    result := {
        "decision": "pass",
        "reasons": [sprintf("✅ No blockers, but %d warning(s) found - review recommended", [count(warning_ids)])],
        "blocks": [],
        "warnings": warning_ids
    }
}

# Clean pass if no findings
decision := result if {
    count(block_ids) == 0
    count(warning_ids) == 0
    result := {
        "decision": "pass",
        "reasons": ["✅ No security issues detected"],
        "blocks": [],
        "warnings": []
    }
}

