"""
Tests for normalizer schema compliance

Verifies that all normalizers properly validate input and output data.
Tests the critical fixes for data format inconsistencies.
"""

import pytest
from pathlib import Path

# Import normalizers
from scripts.normalizer.semgrep import SemgrepNormalizer
from scripts.normalizer.trivy import TrivyNormalizer
from scripts.normalizer.trufflehog import TruffleHogNormalizer
from scripts.normalizer.gitleaks import GitleaksNormalizer


class TestSemgrepNormalizerCompliance:
    """Test Semgrep normalizer schema compliance"""

    def test_rejects_empty_file_paths(self):
        """Test that Semgrep normalizer rejects empty file paths"""
        normalizer = SemgrepNormalizer()

        # SARIF with empty URI
        sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "semgrep"}},
                    "results": [
                        {
                            "ruleId": "test-rule",
                            "level": "error",
                            "message": {"text": "Test"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": ""},  # EMPTY
                                        "region": {"startLine": 1},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }

        findings = normalizer.normalize(sarif)
        # Should skip the finding with empty path
        assert len(findings) == 0

    def test_rejects_dot_file_paths(self):
        """Test that Semgrep normalizer rejects '.' file paths"""
        normalizer = SemgrepNormalizer()

        sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "semgrep"}},
                    "results": [
                        {
                            "ruleId": "test-rule",
                            "level": "error",
                            "message": {"text": "Test"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "."},  # DOT
                                        "region": {"startLine": 1},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }

        findings = normalizer.normalize(sarif)
        # Should skip the finding with '.' path
        assert len(findings) == 0

    def test_valid_finding_accepted(self):
        """Test that valid Semgrep findings are accepted"""
        normalizer = SemgrepNormalizer()

        sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "semgrep", "rules": []}},
                    "results": [
                        {
                            "ruleId": "python.lang.security.sql-injection",
                            "level": "error",
                            "message": {"text": "SQL injection"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/api/users.py"},
                                        "region": {"startLine": 42},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }

        findings = normalizer.normalize(sarif)
        assert len(findings) == 1
        assert findings[0].path == "src/api/users.py"
        assert findings[0].line == 42


class TestTrivyNormalizerCompliance:
    """Test Trivy normalizer schema compliance"""

    def test_rejects_string_vulnerabilities(self):
        """Test that Trivy normalizer rejects string vulnerabilities"""
        normalizer = TrivyNormalizer()

        # Trivy output with string instead of dict
        trivy = {
            "Results": [
                {
                    "Target": "package.json",
                    "Vulnerabilities": ["CVE-2021-1234"],  # STRING - INVALID
                }
            ]
        }

        findings = normalizer.normalize(trivy)
        # Should skip invalid vulnerabilities
        assert len(findings) == 0

    def test_rejects_non_dict_vulnerabilities(self):
        """Test that Trivy normalizer rejects non-dict vulnerability items"""
        normalizer = TrivyNormalizer()

        trivy = {
            "Results": [
                {
                    "Target": "package.json",
                    "Vulnerabilities": [
                        123,  # NUMBER - INVALID
                        "string",  # STRING - INVALID
                    ],
                }
            ]
        }

        findings = normalizer.normalize(trivy)
        # Should skip all invalid vulnerabilities
        assert len(findings) == 0

    def test_valid_trivy_vulnerabilities_accepted(self):
        """Test that valid Trivy vulnerabilities are accepted"""
        normalizer = TrivyNormalizer()

        trivy = {
            "Results": [
                {
                    "Target": "package.json",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2021-1234",
                            "PkgName": "lodash",
                            "InstalledVersion": "4.17.0",
                            "Severity": "HIGH",
                            "Title": "Prototype pollution",
                        }
                    ],
                }
            ]
        }

        findings = normalizer.normalize(trivy)
        assert len(findings) == 1
        assert findings[0].cve == "CVE-2021-1234"
        assert findings[0].severity == "high"


class TestTruffleHogNormalizerCompliance:
    """Test TruffleHog normalizer schema compliance"""

    def test_rejects_string_source_metadata(self):
        """Test that TruffleHog normalizer rejects string source_metadata"""
        normalizer = TruffleHogNormalizer()

        # TruffleHog output with string source_metadata
        trufflehog = [
            {
                "verified": True,
                "detector_type": "AWS",
                "detector_name": "AWS API Key",
                "source_metadata": "this is a string not a dict",  # INVALID
            }
        ]

        findings = normalizer.normalize(trufflehog)
        # Should skip findings with invalid source_metadata
        assert len(findings) == 0

    def test_rejects_invalid_data_field(self):
        """Test that TruffleHog normalizer rejects invalid data field"""
        normalizer = TruffleHogNormalizer()

        trufflehog = [
            {
                "verified": True,
                "detector_type": "AWS",
                "detector_name": "AWS API Key",
                "source_metadata": {
                    "data": "string not dict",  # INVALID
                },
            }
        ]

        findings = normalizer.normalize(trufflehog)
        # Should skip findings with invalid data field
        assert len(findings) == 0

    def test_valid_trufflehog_finding_accepted(self):
        """Test that valid TruffleHog findings are accepted"""
        normalizer = TruffleHogNormalizer()

        trufflehog = [
            {
                "verified": True,
                "detector_type": "AWS",
                "detector_name": "AWS API Key",
                "raw": "AKIAIOSFODNN7EXAMPLE",
                "source_metadata": {
                    "data": {
                        "Git": {
                            "file": "config.yaml",
                            "line": 10,
                            "commit": "abc123",
                        }
                    }
                },
            }
        ]

        findings = normalizer.normalize(trufflehog)
        assert len(findings) == 1
        assert findings[0].path == "config.yaml"
        assert findings[0].secret_verified == "true"


class TestGitleaksNormalizerCompliance:
    """Test Gitleaks normalizer schema compliance"""

    def test_rejects_empty_file_paths(self):
        """Test that Gitleaks normalizer rejects empty file paths"""
        normalizer = GitleaksNormalizer()

        gitleaks = [
            {
                "File": "",  # EMPTY - INVALID
                "RuleID": "generic-api-key",
                "Match": "secret123",
                "StartLine": 1,
            }
        ]

        findings = normalizer.normalize(gitleaks)
        # Should skip findings with empty file path
        assert len(findings) == 0

    def test_rejects_dot_file_paths(self):
        """Test that Gitleaks normalizer rejects '.' file paths"""
        normalizer = GitleaksNormalizer()

        gitleaks = [
            {
                "File": ".",  # DOT - INVALID
                "RuleID": "generic-api-key",
                "Match": "secret123",
                "StartLine": 1,
            }
        ]

        findings = normalizer.normalize(gitleaks)
        # Should skip findings with '.' file path
        assert len(findings) == 0

    def test_valid_gitleaks_finding_accepted(self):
        """Test that valid Gitleaks findings are accepted"""
        normalizer = GitleaksNormalizer()

        gitleaks = [
            {
                "File": ".env",
                "RuleID": "generic-api-key",
                "Description": "Generic API Key",
                "Match": "api_key=secret123",
                "StartLine": 5,
                "Secret": "secret123",
            }
        ]

        findings = normalizer.normalize(gitleaks)
        assert len(findings) == 1
        assert findings[0].path == ".env"
        assert findings[0].line == 5


class TestNormalizerValidationMethod:
    """Test normalizer validation methods"""

    def test_normalize_and_validate_with_validation(self):
        """Test normalize_and_validate method with validation enabled"""
        normalizer = SemgrepNormalizer(validate_output=True)

        sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "semgrep", "rules": []}},
                    "results": [
                        {
                            "ruleId": "test-rule",
                            "level": "error",
                            "message": {"text": "Test"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "test.py"},
                                        "region": {"startLine": 1},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }

        # Should return validated findings
        findings = normalizer.normalize_and_validate(sarif, validate_input=False)
        assert len(findings) == 1

    def test_finding_validate_method(self):
        """Test Finding.validate() method"""
        from scripts.normalizer.base import Finding

        # Valid finding
        finding = Finding(
            id="test123",
            origin="semgrep",
            repo="test-repo",
            commit_sha="abc123",
            branch="main",
            path="src/test.py",
            rule_id="test-rule",
            rule_name="Test Rule",
            category="SAST",
            severity="high",
            cwe="CWE-89",
        )
        assert finding.validate() is True

        # Invalid finding - empty path
        bad_finding = Finding(
            id="test123",
            origin="semgrep",
            repo="test-repo",
            commit_sha="abc123",
            branch="main",
            path="",  # EMPTY
            rule_id="test-rule",
            rule_name="Test Rule",
            category="SAST",
            severity="high",
        )
        with pytest.raises(ValueError, match="path cannot be empty"):
            bad_finding.validate()

    def test_finding_to_pydantic_conversion(self):
        """Test Finding.to_pydantic() conversion"""
        from scripts.normalizer.base import Finding

        finding = Finding(
            id="test123",
            origin="semgrep",
            repo="test-repo",
            commit_sha="abc123",
            branch="main",
            path="src/test.py",
            rule_id="test-rule",
            rule_name="Test Rule",
            category="SAST",
            severity="high",
            cwe="CWE-89",
        )

        pydantic_finding = finding.to_pydantic()
        if pydantic_finding:
            assert pydantic_finding.id == "test123"
            assert str(pydantic_finding.path) == "src/test.py"
            assert pydantic_finding.cwe == "CWE-89"


class TestRealWorldIssues:
    """Test fixes for real-world issues"""

    def test_issue_empty_sast_paths_correlation_failure(self):
        """
        ISSUE: SAST findings had empty file paths causing correlation failures.
        FIX: Validators reject empty paths, normalizers skip empty paths.
        """
        normalizer = SemgrepNormalizer()

        # Simulate real issue - SARIF with empty URI
        sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "semgrep"}},
                    "results": [
                        {
                            "ruleId": "sql-injection",
                            "level": "error",
                            "message": {"text": "SQL injection"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": ""},  # EMPTY
                                        "region": {"startLine": 42},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }

        findings = normalizer.normalize(sarif)
        # Fix: Should skip finding with empty path
        assert len(findings) == 0

    def test_issue_trivy_string_vulnerability(self):
        """
        ISSUE: Trivy results format incompatible - AttributeError: 'str' object has no attribute 'get'
        FIX: Validators ensure Vulnerabilities is list of dicts, not strings.
        """
        normalizer = TrivyNormalizer()

        # Simulate real issue - vulnerability as string
        trivy = {
            "Results": [
                {
                    "Target": "package.json",
                    "Vulnerabilities": "CVE-2021-1234",  # STRING - causes AttributeError
                }
            ]
        }

        # Fix: Should not raise AttributeError, should skip invalid data
        findings = normalizer.normalize(trivy)
        assert len(findings) == 0

    def test_issue_trufflehog_string_metadata(self):
        """
        ISSUE: TruffleHog SourceMetadata as string causing AttributeError.
        FIX: Validators ensure SourceMetadata is dict.
        """
        normalizer = TruffleHogNormalizer()

        # Simulate real issue - source_metadata as string
        trufflehog = [
            {
                "verified": True,
                "detector_name": "AWS",
                "source_metadata": "metadata string",  # STRING - causes AttributeError
            }
        ]

        # Fix: Should not raise AttributeError, should skip invalid data
        findings = normalizer.normalize(trufflehog)
        assert len(findings) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
