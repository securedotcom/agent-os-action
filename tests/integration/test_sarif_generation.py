"""Integration tests for SARIF report generation"""

from run_ai_audit import generate_sarif


class TestSARIFGeneration:
    """Test suite for SARIF report generation"""

    def test_generate_sarif_structure(self, temp_repo):
        """Test SARIF output structure"""
        findings = [
            {
                "severity": "critical",
                "category": "security",
                "message": "Hardcoded API key detected",
                "file_path": "config.js",
                "line_number": 15,
                "rule_id": "SECURITY-001",
            }
        ]

        sarif = generate_sarif(findings, str(temp_repo))

        # Validate SARIF structure
        assert sarif["$schema"] is not None
        assert sarif["version"] == "2.1.0"
        assert "runs" in sarif
        assert len(sarif["runs"]) == 1

        run = sarif["runs"][0]
        assert "tool" in run
        assert run["tool"]["driver"]["name"] == "Agent OS Code Reviewer"
        assert run["tool"]["driver"]["version"] == "1.0.15"

    def test_generate_sarif_findings(self, temp_repo):
        """Test SARIF findings mapping"""
        findings = [
            {
                "severity": "critical",
                "category": "security",
                "message": "SQL injection vulnerability",
                "file_path": "src/database.py",
                "line_number": 42,
                "rule_id": "SECURITY-002",
            },
            {
                "severity": "medium",
                "category": "performance",
                "message": "N+1 query detected",
                "file_path": "src/api.py",
                "line_number": 100,
                "rule_id": "PERFORMANCE-001",
            },
        ]

        sarif = generate_sarif(findings, str(temp_repo))
        results = sarif["runs"][0]["results"]

        assert len(results) == 2

        # Check critical finding
        assert results[0]["ruleId"] == "SECURITY-002"
        assert results[0]["level"] == "error"
        assert results[0]["message"]["text"] == "SQL injection vulnerability"

        # Check medium finding
        assert results[1]["ruleId"] == "PERFORMANCE-001"
        assert results[1]["level"] == "warning"

    def test_generate_sarif_severity_mapping(self, temp_repo):
        """Test severity to SARIF level mapping"""
        severities = [
            ("critical", "error"),
            ("high", "error"),
            ("medium", "warning"),
            ("low", "note"),
            ("info", "note"),
        ]

        for severity, expected_level in severities:
            findings = [
                {
                    "severity": severity,
                    "category": "quality",
                    "message": f"{severity} issue",
                    "file_path": "test.py",
                    "line_number": 1,
                    "rule_id": "TEST-001",
                }
            ]

            sarif = generate_sarif(findings, str(temp_repo))
            result = sarif["runs"][0]["results"][0]

            assert result["level"] == expected_level

    def test_generate_sarif_empty_findings(self, temp_repo):
        """Test SARIF generation with no findings"""
        sarif = generate_sarif([], str(temp_repo))

        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) == 0
