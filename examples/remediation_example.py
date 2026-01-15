#!/usr/bin/env python3
"""
Example: Using the Remediation Engine programmatically

This example demonstrates how to:
1. Load findings from a scanner
2. Generate fix suggestions
3. Export reports in different formats
4. Access individual suggestion details
"""

import json
import sys
from pathlib import Path

# Add scripts to path
scripts_dir = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(scripts_dir))

from remediation_engine import RemediationEngine, RemediationSuggestion


def example_basic_usage():
    """Basic usage: load findings and generate fixes"""
    print("=" * 60)
    print("EXAMPLE 1: Basic Usage")
    print("=" * 60)

    # Sample findings (from a scanner)
    findings = [
        {
            "id": "sql-001",
            "type": "sql_injection",
            "path": "app/database.py",
            "line": 45,
            "severity": "high",
            "code_snippet": 'cursor.execute(f"SELECT * FROM users WHERE id={user_id}")',
        },
        {
            "id": "xss-001",
            "type": "xss",
            "path": "app/views.js",
            "line": 78,
            "severity": "high",
            "code_snippet": "element.innerHTML = userInput;",
        },
    ]

    # Initialize engine
    engine = RemediationEngine()

    # Generate fixes
    suggestions = engine.generate_batch_fixes(findings)

    # Print summary
    print(f"\nGenerated {len(suggestions)} fix suggestions:\n")
    for i, suggestion in enumerate(suggestions, 1):
        print(f"{i}. {suggestion.vulnerability_type} in {suggestion.file_path}")
        print(f"   Confidence: {suggestion.confidence}")
        print(f"   CWE: {', '.join(suggestion.cwe_references)}")
        print()


def example_single_finding():
    """Process a single finding and inspect details"""
    print("=" * 60)
    print("EXAMPLE 2: Single Finding Processing")
    print("=" * 60)

    finding = {
        "id": "cmd-001",
        "type": "command_injection",
        "path": "utils/system.py",
        "line": 23,
        "severity": "critical",
        "code_snippet": "subprocess.run(f'ls {user_path}', shell=True)",
    }

    engine = RemediationEngine()
    suggestion = engine.suggest_fix(finding)

    print(f"\nVulnerability: {suggestion.vulnerability_type}")
    print(f"File: {suggestion.file_path}:{suggestion.line_number}")
    print(f"\nExplanation:\n{suggestion.explanation}")
    print(f"\nOriginal Code:\n{suggestion.original_code}")
    print(f"\nFixed Code:\n{suggestion.fixed_code}")
    print(f"\nTesting Recommendations:")
    for i, rec in enumerate(suggestion.testing_recommendations, 1):
        print(f"  {i}. {rec}")


def example_export_formats():
    """Export suggestions in different formats"""
    print("=" * 60)
    print("EXAMPLE 3: Export Formats")
    print("=" * 60)

    findings = [
        {
            "id": "secret-001",
            "type": "hard_coded_secrets",
            "path": "config/settings.py",
            "line": 12,
            "code_snippet": 'API_KEY = "sk_live_secret123"',
        }
    ]

    engine = RemediationEngine()
    suggestions = engine.generate_batch_fixes(findings)

    # Export as markdown
    engine.export_as_markdown(suggestions, "/tmp/remediation.md")
    print("✓ Exported markdown report to /tmp/remediation.md")

    # Export as JSON
    engine.export_as_json(suggestions, "/tmp/remediation.json")
    print("✓ Exported JSON to /tmp/remediation.json")

    # Access data programmatically
    print("\n📊 Suggestion data:")
    print(json.dumps(suggestions[0].to_dict(), indent=2))


def example_filtering_by_confidence():
    """Filter suggestions by confidence level"""
    print("=" * 60)
    print("EXAMPLE 4: Filtering by Confidence")
    print("=" * 60)

    findings = [
        {"id": "1", "type": "sql_injection", "path": "a.py", "line": 1, "code_snippet": "code"},
        {"id": "2", "type": "unknown_vuln", "path": "b.py", "line": 2, "code_snippet": "code"},
    ]

    engine = RemediationEngine()
    suggestions = engine.generate_batch_fixes(findings)

    # Filter high confidence suggestions
    high_confidence = [s for s in suggestions if s.confidence == "high"]
    medium_confidence = [s for s in suggestions if s.confidence == "medium"]
    low_confidence = [s for s in suggestions if s.confidence == "low"]

    print(f"\nHigh confidence fixes: {len(high_confidence)}")
    print(f"Medium confidence fixes: {len(medium_confidence)}")
    print(f"Low confidence fixes: {len(low_confidence)}")

    print("\nRecommendation: Apply high confidence fixes automatically,")
    print("review medium confidence fixes, and manually assess low confidence fixes.")


def main():
    """Run all examples"""
    print("\n" + "=" * 60)
    print("REMEDIATION ENGINE EXAMPLES")
    print("=" * 60 + "\n")

    example_basic_usage()
    print("\n")

    example_single_finding()
    print("\n")

    example_export_formats()
    print("\n")

    example_filtering_by_confidence()
    print("\n")

    print("=" * 60)
    print("All examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
