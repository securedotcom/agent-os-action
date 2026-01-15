#!/usr/bin/env python3
"""
Unit tests for regression_tester.py
Tests the Security Regression Testing framework
"""

import json
import pytest
from pathlib import Path
import tempfile
import shutil

# Import the module to test
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
from regression_tester import RegressionTester, RegressionTest


class TestRegressionTester:
    """Test the RegressionTester class"""

    @pytest.fixture
    def temp_test_dir(self):
        """Create a temporary test directory"""
        temp_dir = Path(tempfile.mkdtemp())
        yield temp_dir
        # Cleanup
        if temp_dir.exists():
            shutil.rmtree(temp_dir)

    @pytest.fixture
    def tester(self, temp_test_dir):
        """Create a RegressionTester instance"""
        return RegressionTester(test_dir=temp_test_dir)

    @pytest.fixture
    def sample_sql_injection_finding(self):
        """Sample SQL injection finding"""
        return {
            "type": "sql-injection",
            "path": "app/database.py",
            "function": "get_user_by_id",
            "cwe": "CWE-89",
            "cve": "CVE-2024-1234",
            "severity": "critical",
            "description": "SQL injection in user lookup",
        }

    @pytest.fixture
    def sample_xss_finding(self):
        """Sample XSS finding"""
        return {
            "type": "xss",
            "path": "app/templates.py",
            "function": "render_comment",
            "cwe": "CWE-79",
            "severity": "high",
            "description": "XSS in comment rendering",
        }

    def test_initialization(self, temp_test_dir):
        """Test RegressionTester initialization"""
        tester = RegressionTester(test_dir=temp_test_dir)
        assert tester.test_dir == temp_test_dir
        assert temp_test_dir.exists()
        assert tester.tests == []

    def test_generate_test_id(self, tester):
        """Test test ID generation"""
        test_id = tester._generate_test_id("sql-injection", "app/db.py", "CVE-2024-1234")
        assert isinstance(test_id, str)
        assert len(test_id) == 12  # SHA256 truncated to 12 chars

        # Same input should produce same ID
        test_id2 = tester._generate_test_id("sql-injection", "app/db.py", "CVE-2024-1234")
        assert test_id == test_id2

        # Different input should produce different ID
        test_id3 = tester._generate_test_id("xss", "app/db.py", "CVE-2024-1234")
        assert test_id != test_id3

    def test_detect_language(self, tester):
        """Test language detection"""
        assert tester._detect_language("app.py") == "python"
        assert tester._detect_language("app.js") == "javascript"
        assert tester._detect_language("app.ts") == "typescript"
        assert tester._detect_language("app.go") == "go"
        assert tester._detect_language("app.java") == "java"
        assert tester._detect_language("app.unknown") == "unknown"

    def test_extract_function_name(self, tester):
        """Test function name extraction"""
        # From function field
        finding = {"function": "test_func"}
        assert tester._extract_function_name(finding) == "test_func"

        # From method field
        finding = {"method": "test_method"}
        assert tester._extract_function_name(finding) == "test_method"

        # From snippet (Python)
        finding = {"snippet": "def test_function(arg):\n    pass"}
        assert tester._extract_function_name(finding) == "test_function"

        # Default fallback
        finding = {}
        assert tester._extract_function_name(finding) == "vulnerable_function"

    def test_get_exploit_payload(self, tester):
        """Test exploit payload retrieval"""
        assert "OR" in tester._get_exploit_payload("sql-injection")
        assert "<script>" in tester._get_exploit_payload("xss")
        assert "cat" in tester._get_exploit_payload("command-injection")
        assert ".." in tester._get_exploit_payload("path-traversal")
        assert "xxe" in tester._get_exploit_payload("xxe").lower()

    def test_get_expected_behavior(self, tester):
        """Test expected behavior retrieval"""
        assert "parameterized" in tester._get_expected_behavior("sql-injection")
        assert "escape" in tester._get_expected_behavior("xss")
        assert "sanitize" in tester._get_expected_behavior("command-injection")

    def test_generate_regression_test_sql_injection(self, tester, sample_sql_injection_finding):
        """Test regression test generation for SQL injection"""
        test = tester.generate_regression_test(sample_sql_injection_finding)

        assert isinstance(test, RegressionTest)
        assert test.vulnerability_type == "sql-injection"
        assert test.cwe_id == "CWE-89"
        assert test.cve_id == "CVE-2024-1234"
        assert test.severity == "critical"
        assert test.file_path == "app/database.py"
        assert test.function_name == "get_user_by_id"
        assert test.language == "python"
        assert "import pytest" in test.test_code
        assert "sql_injection_regression" in test.test_code
        assert len(tester.tests) == 1

    def test_generate_regression_test_xss(self, tester, sample_xss_finding):
        """Test regression test generation for XSS"""
        test = tester.generate_regression_test(sample_xss_finding)

        assert test.vulnerability_type == "xss"
        assert test.cwe_id == "CWE-79"
        assert test.severity == "high"
        assert "<script>" in test.test_code
        assert "xss_regression" in test.test_code

    def test_save_and_load_tests(self, tester, sample_sql_injection_finding):
        """Test saving and loading tests"""
        # Generate and save a test
        test = tester.generate_regression_test(sample_sql_injection_finding)

        # Verify files were created
        vuln_dir = tester.test_dir / "sql_injection"
        test_file = vuln_dir / f"test_{test.test_id}.py"
        metadata_file = vuln_dir / f"test_{test.test_id}.json"

        assert test_file.exists()
        assert metadata_file.exists()

        # Verify test code was saved
        with open(test_file) as f:
            saved_code = f.read()
        assert saved_code == test.test_code

        # Verify metadata was saved
        with open(metadata_file) as f:
            metadata = json.load(f)
        assert metadata["test_id"] == test.test_id
        assert metadata["vulnerability_type"] == "sql-injection"

        # Create a new tester instance and verify tests are loaded
        tester2 = RegressionTester(test_dir=tester.test_dir)
        assert len(tester2.tests) == 1
        loaded_test = tester2.tests[0]
        assert loaded_test.test_id == test.test_id
        assert loaded_test.vulnerability_type == test.vulnerability_type

    def test_generate_python_test_templates(self, tester):
        """Test Python test generation for different vulnerability types"""
        vuln_types = ["sql-injection", "xss", "command-injection", "path-traversal"]

        for vuln_type in vuln_types:
            test_code = tester._generate_python_test(
                vuln_type, "app/test.py", "test_func", "malicious"
            )
            assert "import pytest" in test_code
            assert "def test_" in test_code
            assert "regression" in test_code
            assert "normal_input" in test_code

    def test_generate_javascript_test(self, tester):
        """Test JavaScript test generation"""
        test_code = tester._generate_javascript_test(
            "xss", "app/test.js", "testFunc", "<script>alert(1)</script>"
        )
        assert "require" in test_code
        assert "describe" in test_code
        assert "test(" in test_code
        assert "expect(" in test_code

    def test_get_stats_empty(self, tester):
        """Test statistics with no tests"""
        stats = tester.get_stats()
        assert stats["total_tests"] == 0
        assert stats["by_language"] == {}
        assert stats["by_vulnerability"] == {}
        assert stats["by_severity"] == {}

    def test_get_stats_with_tests(self, tester, sample_sql_injection_finding, sample_xss_finding):
        """Test statistics with multiple tests"""
        tester.generate_regression_test(sample_sql_injection_finding)
        tester.generate_regression_test(sample_xss_finding)

        stats = tester.get_stats()
        assert stats["total_tests"] == 2
        assert stats["by_language"]["python"] == 2
        assert stats["by_vulnerability"]["sql-injection"] == 1
        assert stats["by_vulnerability"]["xss"] == 1
        assert stats["by_severity"]["critical"] == 1
        assert stats["by_severity"]["high"] == 1

    def test_test_code_quality(self, tester, sample_sql_injection_finding):
        """Test that generated code has proper structure"""
        test = tester.generate_regression_test(sample_sql_injection_finding)

        # Check for proper imports
        assert "import pytest" in test.test_code
        assert "from app.database import" in test.test_code

        # Check for test functions
        assert "def test_sql_injection_regression():" in test.test_code
        assert "def test_sql_injection_normal_input():" in test.test_code

        # Check for assertions
        assert "assert" in test.test_code

        # Check for docstrings
        assert '"""' in test.test_code

    def test_multiple_findings_generation(self, tester):
        """Test generating tests from multiple findings"""
        findings = [
            {
                "type": "sql-injection",
                "path": "app/db.py",
                "function": "get_user",
                "cwe": "CWE-89",
                "severity": "critical",
            },
            {
                "type": "xss",
                "path": "app/views.py",
                "function": "render",
                "cwe": "CWE-79",
                "severity": "high",
            },
            {
                "type": "command-injection",
                "path": "app/exec.py",
                "function": "run_cmd",
                "cwe": "CWE-78",
                "severity": "critical",
            },
        ]

        for finding in findings:
            tester.generate_regression_test(finding)

        assert len(tester.tests) == 3

        # Verify directory structure
        assert (tester.test_dir / "sql_injection").exists()
        assert (tester.test_dir / "xss").exists()
        assert (tester.test_dir / "command_injection").exists()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
