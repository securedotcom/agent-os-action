#!/usr/bin/env python3
"""
Example: Using SAST-DAST Correlation Engine

This example demonstrates how to use the SAST-DAST correlator to verify
if static analysis findings are exploitable via dynamic testing results.
"""

import json
import sys
from pathlib import Path

# Add scripts directory to path
scripts_dir = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(scripts_dir))

from sast_dast_correlator import SASTDASTCorrelator, CorrelationStatus


def example_1_basic_usage():
    """Example 1: Basic correlation with sample findings"""
    print("=" * 70)
    print("Example 1: Basic SAST-DAST Correlation")
    print("=" * 70)
    print()

    # Sample SAST findings (from Semgrep, for example)
    sast_findings = [
        {
            "id": "semgrep-001",
            "path": "src/api/users.py",
            "line": 42,
            "rule_id": "python.django.security.injection.sql.sql-injection-using-db-cursor-execute",
            "rule_name": "SQL Injection via cursor.execute()",
            "severity": "high",
            "cwe": "CWE-89",
            "evidence": {
                "message": "User input is used directly in SQL query without parameterization",
                "snippet": "cursor.execute('SELECT * FROM users WHERE id = ' + user_id)"
            }
        },
        {
            "id": "semgrep-002",
            "path": "src/views/dashboard.py",
            "line": 15,
            "rule_id": "python.flask.security.xss.template-autoescape-off",
            "rule_name": "XSS via autoescape=False",
            "severity": "medium",
            "cwe": "CWE-79",
            "evidence": {
                "message": "Template rendering with autoescape disabled",
                "snippet": "render_template_string(user_content, autoescape=False)"
            }
        }
    ]

    # Sample DAST findings (from OWASP ZAP, Burp, or similar)
    dast_findings = [
        {
            "id": "zap-001",
            "path": "/api/users",
            "rule_id": "40018",  # ZAP SQL Injection rule
            "rule_name": "SQL Injection",
            "severity": "high",
            "cwe": "CWE-89",
            "evidence": {
                "url": "http://localhost:8000/api/users?id=1' OR '1'='1",
                "method": "GET",
                "message": "SQL injection vulnerability detected via error-based testing",
                "poc": "GET /api/users?id=1' OR '1'='1 HTTP/1.1\nHost: localhost:8000"
            }
        }
    ]

    # Initialize correlator
    correlator = SASTDASTCorrelator()

    # Run correlation (without AI for this example)
    results = correlator.correlate(
        sast_findings=sast_findings,
        dast_findings=dast_findings,
        use_ai=False  # Set to True to enable AI verification
    )

    # Print results
    for result in results:
        print(f"\nSAST Finding: {result.sast_finding_id}")
        print(f"  Status: {result.status.value}")
        print(f"  Confidence: {result.confidence:.2%}")
        print(f"  Exploitability: {result.exploitability}")
        print(f"  Reasoning: {result.reasoning}")

        if result.dast_finding_id:
            print(f"  ✓ Confirmed by DAST finding: {result.dast_finding_id}")
            if result.poc_exploit:
                print(f"  PoC: {result.poc_exploit[:80]}...")

    print("\n" + "=" * 70 + "\n")


def example_2_filtering_confirmed():
    """Example 2: Filter to confirmed exploitable findings"""
    print("=" * 70)
    print("Example 2: Filtering Confirmed Exploitable Findings")
    print("=" * 70)
    print()

    # Larger set of SAST findings
    sast_findings = [
        {
            "id": f"sast-{i:03d}",
            "path": f"src/api/endpoint_{i}.py",
            "line": 10 + i,
            "rule_id": "sql-injection" if i % 2 == 0 else "xss",
            "rule_name": "SQL Injection" if i % 2 == 0 else "XSS",
            "severity": "high" if i % 2 == 0 else "medium",
            "cwe": "CWE-89" if i % 2 == 0 else "CWE-79",
            "evidence": {"message": f"Vulnerability in endpoint {i}"}
        }
        for i in range(10)
    ]

    # Only some DAST findings (simulating incomplete DAST coverage)
    dast_findings = [
        {
            "id": f"dast-{i:03d}",
            "path": f"/api/endpoint_{i}",
            "rule_id": "sql-injection",
            "rule_name": "SQL Injection",
            "severity": "high",
            "cwe": "CWE-89",
            "evidence": {
                "url": f"http://localhost/api/endpoint_{i}?id=1'",
                "method": "GET",
                "message": "SQL injection confirmed",
                "poc": f"curl 'http://localhost/api/endpoint_{i}?id=1%27'"
            }
        }
        for i in range(0, 10, 2)  # Only even endpoints
    ]

    correlator = SASTDASTCorrelator()
    results = correlator.correlate(sast_findings, dast_findings, use_ai=False)

    # Filter to confirmed findings
    confirmed = [r for r in results if r.status == CorrelationStatus.CONFIRMED]
    partial = [r for r in results if r.status == CorrelationStatus.PARTIAL]
    no_coverage = [r for r in results if r.status == CorrelationStatus.NO_DAST_COVERAGE]

    print(f"Total SAST findings: {len(results)}")
    print(f"  ✓ Confirmed exploitable: {len(confirmed)}")
    print(f"  ≈ Partial matches: {len(partial)}")
    print(f"  ∅ No DAST coverage: {len(no_coverage)}")
    print()

    print("High-priority findings (confirmed exploitable):")
    for result in confirmed[:3]:  # Show top 3
        print(f"  - {result.sast_finding_id} (confidence: {result.confidence:.2%})")

    print("\n" + "=" * 70 + "\n")


def example_3_export_results():
    """Example 3: Export correlation results to JSON"""
    print("=" * 70)
    print("Example 3: Export Correlation Results")
    print("=" * 70)
    print()

    sast_findings = [
        {
            "id": "sast-critical-001",
            "path": "src/api/auth.py",
            "line": 99,
            "rule_id": "authentication-bypass",
            "rule_name": "Authentication Bypass",
            "severity": "critical",
            "cwe": "CWE-287",
            "evidence": {
                "message": "Authentication check can be bypassed",
                "snippet": "if user_id: return True"
            }
        }
    ]

    dast_findings = [
        {
            "id": "dast-critical-001",
            "path": "/api/auth/login",
            "rule_id": "authentication-bypass",
            "rule_name": "Authentication Bypass",
            "severity": "critical",
            "cwe": "CWE-287",
            "evidence": {
                "url": "http://localhost/api/auth/login",
                "method": "POST",
                "message": "Successfully bypassed authentication",
                "poc": "POST /api/auth/login HTTP/1.1\nContent-Type: application/json\n\n{\"user_id\": \"1\"}"
            }
        }
    ]

    correlator = SASTDASTCorrelator()
    results = correlator.correlate(sast_findings, dast_findings, use_ai=False)

    # Export to JSON
    output_file = "/tmp/correlation_results.json"
    correlator.export_results(results, output_file, format="json")
    print(f"✓ Results exported to: {output_file}")

    # Show exported data
    with open(output_file) as f:
        data = json.load(f)

    print(f"\nExported data structure:")
    print(f"  - Metadata: {data['metadata']}")
    print(f"  - Correlations: {len(data['correlations'])} items")

    # Export to Markdown
    md_file = "/tmp/correlation_report.md"
    correlator.export_results(results, md_file, format="markdown")
    print(f"✓ Markdown report exported to: {md_file}")

    print("\n" + "=" * 70 + "\n")


def example_4_ci_cd_integration():
    """Example 4: CI/CD integration pattern"""
    print("=" * 70)
    print("Example 4: CI/CD Integration Pattern")
    print("=" * 70)
    print()

    print("Typical CI/CD workflow:")
    print("1. Run SAST scans (Semgrep, TruffleHog, etc.)")
    print("2. Run DAST scans (ZAP, Burp, Nuclei, etc.)")
    print("3. Correlate findings to identify confirmed exploitables")
    print("4. Fail build if confirmed critical/high severity findings")
    print()

    # Simulate findings
    sast_findings = [
        {"id": "s1", "path": "src/api/v1.py", "line": 10, "rule_id": "sqli", "rule_name": "SQLi", "severity": "critical", "cwe": "CWE-89", "evidence": {}},
        {"id": "s2", "path": "src/api/v2.py", "line": 20, "rule_id": "xss", "rule_name": "XSS", "severity": "high", "cwe": "CWE-79", "evidence": {}},
        {"id": "s3", "path": "src/internal/admin.py", "line": 30, "rule_id": "sqli", "rule_name": "SQLi", "severity": "critical", "cwe": "CWE-89", "evidence": {}},
    ]

    dast_findings = [
        {"id": "d1", "path": "/api/v1", "rule_id": "sqli", "rule_name": "SQLi", "severity": "critical", "cwe": "CWE-89", "evidence": {"url": "http://localhost/api/v1", "method": "GET", "poc": "curl test"}},
        {"id": "d2", "path": "/api/v2", "rule_id": "xss", "rule_name": "XSS", "severity": "high", "cwe": "CWE-79", "evidence": {"url": "http://localhost/api/v2", "method": "GET", "poc": "curl test"}},
    ]

    correlator = SASTDASTCorrelator()
    results = correlator.correlate(sast_findings, dast_findings, use_ai=False)

    # Check for blocking conditions
    blocking_findings = [
        r for r in results
        if r.status == CorrelationStatus.CONFIRMED
        and r.confidence >= 0.7
        and r.sast_summary
        and r.sast_summary.get("severity") in ["critical", "high"]
    ]

    print(f"Correlation complete:")
    print(f"  - Total SAST findings: {len(sast_findings)}")
    print(f"  - Total DAST findings: {len(dast_findings)}")
    print(f"  - Confirmed exploitable: {len([r for r in results if r.status == CorrelationStatus.CONFIRMED])}")
    print(f"  - Blocking findings (critical/high + confirmed): {len(blocking_findings)}")
    print()

    if blocking_findings:
        print("❌ BUILD FAILED: Confirmed exploitable critical/high severity findings detected!")
        for finding in blocking_findings:
            print(f"   - {finding.sast_finding_id}: {finding.reasoning}")
        print("\nCI/CD would exit with code 1")
    else:
        print("✅ BUILD PASSED: No confirmed exploitable critical/high findings")
        print("CI/CD would exit with code 0")

    print("\n" + "=" * 70 + "\n")


def main():
    """Run all examples"""
    print("\n" + "🔒 SAST-DAST Correlation Engine Examples\n")

    example_1_basic_usage()
    example_2_filtering_confirmed()
    example_3_export_results()
    example_4_ci_cd_integration()

    print("✓ All examples complete!")
    print("\nNext steps:")
    print("  - Enable AI verification by setting ANTHROPIC_API_KEY or OPENAI_API_KEY")
    print("  - Integrate with your CI/CD pipeline")
    print("  - Use correlation results to prioritize security remediation")
    print()


if __name__ == "__main__":
    main()
