#!/usr/bin/env python3
"""
Security Test Generator Example

Demonstrates how to use the Security Test Generator to automatically
create security regression tests from vulnerability findings.
"""

import json
from pathlib import Path

# Import the generator (adjust path if running from different location)
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from security_test_generator import SecurityTestGenerator


def example_basic_usage():
    """Basic usage example"""
    print("\n" + "=" * 60)
    print("Example 1: Basic Test Generation")
    print("=" * 60 + "\n")

    # Sample findings from security scanners
    findings = [
        {
            "id": "semgrep-sql-001",
            "type": "sql-injection",
            "severity": "high",
            "path": "app/users/views.py",
            "description": "SQL injection vulnerability in user search endpoint",
            "code_snippet": """
def search_users(username):
    query = f"SELECT * FROM users WHERE name = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()
""",
        },
        {
            "id": "semgrep-xss-002",
            "type": "xss",
            "severity": "medium",
            "path": "frontend/src/components/UserProfile.jsx",
            "description": "XSS vulnerability due to unescaped user input",
            "code_snippet": """
const UserProfile = ({ name }) => {
    return <div dangerouslySetInnerHTML={{ __html: name }} />;
};
""",
        },
    ]

    # Initialize generator
    generator = SecurityTestGenerator(debug=True)

    # Generate test suite
    suite = generator.generate_test_suite(findings=findings, output_path="/tmp/security_tests/")

    print(f"\n✅ Generated {suite.test_count()} tests")
    print(f"   Language: {suite.language}")
    print(f"   Framework: {suite.framework}")

    # Print statistics
    generator.print_stats()


def example_regression_tests():
    """Example of generating regression tests for fixed vulnerabilities"""
    print("\n" + "=" * 60)
    print("Example 2: Regression Test Generation")
    print("=" * 60 + "\n")

    generator = SecurityTestGenerator()

    # Fixed vulnerability that should have a regression test
    fixed_finding = {
        "id": "sql-injection-fixed-20250115",
        "type": "sql-injection",
        "description": "SQL injection in user authentication - FIXED",
        "path": "app/auth/login.py",
    }

    # Generate regression test for Python
    python_regression = generator.generate_regression_test(fixed_finding, language="python")

    print("Generated Python Regression Test:")
    print("-" * 60)
    print(python_regression[:500] + "...")  # Show first 500 chars

    # Generate regression test for JavaScript
    js_regression = generator.generate_regression_test(fixed_finding, language="javascript")

    print("\nGenerated JavaScript Regression Test:")
    print("-" * 60)
    print(js_regression[:500] + "...")  # Show first 500 chars


def example_mixed_languages():
    """Example with findings from multiple languages"""
    print("\n" + "=" * 60)
    print("Example 3: Mixed Language Detection")
    print("=" * 60 + "\n")

    # Python findings
    python_findings = [
        {
            "id": "py-001",
            "type": "path-traversal",
            "severity": "high",
            "path": "app/files/download.py",
            "description": "Path traversal in file download",
            "code_snippet": "filename = request.args.get('file')\nopen(f'/uploads/{filename}')",
        }
    ]

    # JavaScript findings
    js_findings = [
        {
            "id": "js-001",
            "type": "xss",
            "severity": "medium",
            "path": "src/components/Comment.jsx",
            "description": "XSS in comment rendering",
            "code_snippet": "return <div>{unsafeHtml}</div>",
        }
    ]

    generator = SecurityTestGenerator()

    # Generate tests for Python findings
    py_suite = generator.generate_test_suite(python_findings, output_path="/tmp/py_tests/")
    print(f"Python: {py_suite.test_count()} tests generated ({py_suite.framework})")

    # Generate tests for JavaScript findings
    generator2 = SecurityTestGenerator()  # Fresh instance for clean stats
    js_suite = generator2.generate_test_suite(js_findings, output_path="/tmp/js_tests/")
    print(f"JavaScript: {js_suite.test_count()} tests generated ({js_suite.framework})")


def example_from_json_file():
    """Example loading findings from JSON file"""
    print("\n" + "=" * 60)
    print("Example 4: Loading from JSON File")
    print("=" * 60 + "\n")

    # Create sample findings file
    findings_data = {
        "findings": [
            {
                "id": "trivy-cve-2024-001",
                "type": "command-injection",
                "severity": "critical",
                "path": "app/utils/system.py",
                "description": "Command injection in system utility",
                "code_snippet": "os.system(f'ping {host}')",
            },
            {
                "id": "checkov-secrets-001",
                "type": "hardcoded-secret",
                "severity": "high",
                "path": "config/database.py",
                "description": "Hardcoded database credentials",
                "code_snippet": "DB_PASSWORD = 'supersecret123'",
            },
        ]
    }

    # Write to temp file
    findings_file = Path("/tmp/sample_findings.json")
    findings_file.write_text(json.dumps(findings_data, indent=2))

    print(f"Created sample findings file: {findings_file}")

    # Load and generate tests (simulating CLI usage)
    with open(findings_file) as f:
        data = json.load(f)

    generator = SecurityTestGenerator()
    suite = generator.generate_test_suite(data["findings"], output_path="/tmp/json_tests/")

    print(f"\n✅ Generated {suite.test_count()} tests from JSON file")


def example_vulnerability_patterns():
    """Example showing different vulnerability type patterns"""
    print("\n" + "=" * 60)
    print("Example 5: Vulnerability Pattern Coverage")
    print("=" * 60 + "\n")

    generator = SecurityTestGenerator()

    # Show supported vulnerability patterns
    print("Supported vulnerability patterns and payloads:\n")

    for vuln_type, pattern_data in generator.VULN_PATTERNS.items():
        print(f"{vuln_type}:")
        print(f"  Test Type: {pattern_data['test_type']}")
        print(f"  Sample Payloads:")
        for payload in pattern_data["payloads"][:2]:  # Show first 2 payloads
            print(f"    - {payload}")
        print()


def example_custom_output():
    """Example with custom output filename"""
    print("\n" + "=" * 60)
    print("Example 6: Custom Output Filename")
    print("=" * 60 + "\n")

    findings = [
        {
            "id": "custom-001",
            "type": "sql-injection",
            "path": "app.py",
            "description": "SQL injection",
            "code_snippet": "query = f'SELECT * FROM users WHERE id={user_id}'",
        }
    ]

    generator = SecurityTestGenerator()

    # Generate with custom filename
    suite = generator.generate_test_suite(
        findings=findings, output_path="/tmp/custom_tests/", filename="test_sql_injection_suite.py"
    )

    print(f"✅ Generated tests with custom filename:")
    print(f"   /tmp/custom_tests/test_sql_injection_suite.py")


def example_programmatic_filtering():
    """Example of filtering findings before test generation"""
    print("\n" + "=" * 60)
    print("Example 7: Programmatic Finding Filtering")
    print("=" * 60 + "\n")

    all_findings = [
        {"id": "001", "type": "sql-injection", "severity": "high", "path": "app.py", "description": "SQL injection"},
        {"id": "002", "type": "xss", "severity": "low", "path": "views.py", "description": "XSS"},
        {"id": "003", "type": "command-injection", "severity": "critical", "path": "utils.py", "description": "RCE"},
        {"id": "004", "type": "path-traversal", "severity": "medium", "path": "files.py", "description": "Path traversal"},
    ]

    generator = SecurityTestGenerator()

    # Generate tests only for high/critical severity
    high_severity = [f for f in all_findings if f["severity"] in ["high", "critical"]]

    print(f"Total findings: {len(all_findings)}")
    print(f"High/Critical severity: {len(high_severity)}")

    suite = generator.generate_test_suite(high_severity, output_path="/tmp/filtered_tests/")

    print(f"\n✅ Generated {suite.test_count()} tests for high/critical findings only")


def main():
    """Run all examples"""
    print("\n" + "=" * 60)
    print("SECURITY TEST GENERATOR - EXAMPLES")
    print("=" * 60)

    try:
        example_basic_usage()
        example_regression_tests()
        example_mixed_languages()
        example_from_json_file()
        example_vulnerability_patterns()
        example_custom_output()
        example_programmatic_filtering()

        print("\n" + "=" * 60)
        print("All examples completed successfully!")
        print("=" * 60 + "\n")

    except Exception as e:
        print(f"\n❌ Error running examples: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    main()
