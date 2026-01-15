#!/usr/bin/env python3
"""Unit tests for SAST-DAST Correlator"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Add scripts directory to path
scripts_dir = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(scripts_dir))

from sast_dast_correlator import (
    CorrelationResult,
    CorrelationStatus,
    SASTDASTCorrelator,
)


class TestCorrelationStatus:
    """Test CorrelationStatus enum"""

    def test_enum_values(self):
        """Test enum has correct values"""
        assert CorrelationStatus.CONFIRMED.value == "confirmed"
        assert CorrelationStatus.PARTIAL.value == "partial"
        assert CorrelationStatus.NOT_VERIFIED.value == "not_verified"
        assert CorrelationStatus.NO_DAST_COVERAGE.value == "no_dast_coverage"


class TestCorrelationResult:
    """Test CorrelationResult dataclass"""

    def test_to_dict(self):
        """Test conversion to dictionary"""
        result = CorrelationResult(
            sast_finding_id="sast-001",
            dast_finding_id="dast-001",
            status=CorrelationStatus.CONFIRMED,
            confidence=0.95,
            exploitability="trivial",
            reasoning="Test reasoning",
            poc_exploit="curl test",
            match_score=0.98
        )

        result_dict = result.to_dict()
        assert result_dict["sast_finding_id"] == "sast-001"
        assert result_dict["dast_finding_id"] == "dast-001"
        assert result_dict["status"] == "confirmed"
        assert result_dict["confidence"] == 0.95
        assert result_dict["exploitability"] == "trivial"

    def test_to_dict_with_none_dast_id(self):
        """Test conversion when no DAST finding matched"""
        result = CorrelationResult(
            sast_finding_id="sast-001",
            dast_finding_id=None,
            status=CorrelationStatus.NO_DAST_COVERAGE,
            confidence=0.95,
            exploitability="unknown",
            reasoning="No coverage"
        )

        result_dict = result.to_dict()
        assert result_dict["dast_finding_id"] is None
        assert result_dict["status"] == "no_dast_coverage"


class TestSASTDASTCorrelator:
    """Test SASTDASTCorrelator class"""

    @pytest.fixture
    def correlator(self):
        """Create correlator instance without LLM"""
        with patch("sast_dast_correlator.LLMManager"):
            correlator = SASTDASTCorrelator()
            correlator.llm = None  # Disable LLM for tests
            return correlator

    @pytest.fixture
    def sample_sast_finding(self):
        """Sample SAST finding"""
        return {
            "id": "sast-001",
            "path": "src/api/users.py",
            "line": 42,
            "rule_id": "python.django.security.injection.sql.sql-injection",
            "rule_name": "SQL Injection",
            "severity": "high",
            "cwe": "CWE-89",
            "evidence": {
                "message": "Potential SQL injection",
                "snippet": "cursor.execute('SELECT * FROM users WHERE id = ' + user_id)"
            }
        }

    @pytest.fixture
    def sample_dast_finding(self):
        """Sample DAST finding"""
        return {
            "id": "dast-001",
            "path": "/api/users",
            "rule_id": "sql-injection",
            "rule_name": "SQL Injection",
            "severity": "high",
            "cwe": "CWE-89",
            "evidence": {
                "url": "http://localhost:8000/api/users?id=1' OR '1'='1",
                "method": "GET",
                "message": "SQL injection confirmed",
                "poc": "curl 'http://localhost:8000/api/users?id=1%27'"
            }
        }

    def test_initialization_without_llm(self):
        """Test correlator initializes without LLM"""
        with patch("sast_dast_correlator.LLMManager") as mock_llm:
            mock_llm.side_effect = Exception("No LLM")
            correlator = SASTDASTCorrelator()
            assert correlator.llm is None

    def test_normalize_vuln_type_cwe(self, correlator):
        """Test vulnerability type normalization from CWE"""
        assert correlator._normalize_vuln_type("CWE-89") == "sql-injection"
        assert correlator._normalize_vuln_type("cwe-79") == "xss"
        assert correlator._normalize_vuln_type("CWE-78") == "command-injection"

    def test_normalize_vuln_type_alias(self, correlator):
        """Test vulnerability type normalization from alias"""
        assert correlator._normalize_vuln_type("sqli") == "sql-injection"
        assert correlator._normalize_vuln_type("cross-site-scripting") == "xss"
        assert correlator._normalize_vuln_type("os-command-injection") == "command-injection"

    def test_normalize_vuln_type_rule_id(self, correlator):
        """Test vulnerability type normalization from rule ID"""
        rule = "python.django.security.injection.sql.sql-injection-using-db-cursor"
        assert correlator._normalize_vuln_type(rule) == "sql-injection"

    def test_extract_endpoint_from_url(self, correlator):
        """Test endpoint extraction from URL"""
        assert correlator._extract_endpoint_from_url("http://localhost:8000/api/users") == "/api/users"
        assert correlator._extract_endpoint_from_url("/api/users?id=1") == "/api/users"
        assert correlator._extract_endpoint_from_url("https://example.com/api/v1/users#section") == "/api/v1/users"

    def test_extract_endpoint_from_path(self, correlator):
        """Test endpoint extraction from file path"""
        assert correlator._extract_endpoint_from_path("src/api/users.py") == "/api/users"
        assert correlator._extract_endpoint_from_path("backend/routes/products.js") == "/routes/products"
        assert correlator._extract_endpoint_from_path("controllers/auth.py") == "/controllers/auth"

    def test_fuzzy_match_paths_exact(self, correlator):
        """Test fuzzy matching with exact match"""
        score = correlator._fuzzy_match_paths("src/api/users.py", "http://localhost/api/users")
        assert score > 0.8  # High similarity

    def test_fuzzy_match_paths_similar(self, correlator):
        """Test fuzzy matching with similar paths"""
        score = correlator._fuzzy_match_paths("src/api/products.py", "http://localhost/api/search")
        assert 0.3 < score < 0.7  # Moderate similarity

    def test_fuzzy_match_paths_different(self, correlator):
        """Test fuzzy matching with different paths"""
        score = correlator._fuzzy_match_paths("src/models/user.py", "http://localhost/api/orders")
        assert score < 0.5  # Low similarity

    def test_are_related_vuln_types_same(self, correlator):
        """Test related vulnerability types (same type)"""
        assert correlator._are_related_vuln_types("sql-injection", "sqli")
        assert correlator._are_related_vuln_types("xss", "cross-site-scripting")

    def test_are_related_vuln_types_different(self, correlator):
        """Test unrelated vulnerability types"""
        assert not correlator._are_related_vuln_types("sql-injection", "xss")
        assert not correlator._are_related_vuln_types("command-injection", "path-traversal")

    def test_calculate_match_score_perfect(self, correlator, sample_sast_finding, sample_dast_finding):
        """Test match score calculation with perfect match"""
        score = correlator._calculate_match_score(sample_sast_finding, sample_dast_finding)
        assert score > 0.9  # High score for perfect match

    def test_calculate_match_score_no_match(self, correlator, sample_sast_finding):
        """Test match score calculation with no match"""
        different_dast = {
            "id": "dast-002",
            "path": "/api/products",
            "rule_id": "xss",
            "rule_name": "XSS",
            "severity": "medium",
            "cwe": "CWE-79",
            "evidence": {"url": "http://localhost/api/products"}
        }
        score = correlator._calculate_match_score(sample_sast_finding, different_dast)
        assert score < 0.5  # Low score for different findings

    def test_find_dast_candidates(self, correlator, sample_sast_finding, sample_dast_finding):
        """Test finding DAST candidates"""
        dast_findings = [sample_dast_finding]
        candidates = correlator._find_dast_candidates(sample_sast_finding, dast_findings)

        assert len(candidates) == 1
        assert candidates[0]["finding"]["id"] == "dast-001"
        assert candidates[0]["match_score"] > 0.5

    def test_find_dast_candidates_no_match(self, correlator, sample_sast_finding):
        """Test finding DAST candidates with no matches"""
        dast_findings = [{
            "id": "dast-002",
            "path": "/completely/different",
            "rule_id": "different-vuln",
            "rule_name": "Different",
            "severity": "low",
            "cwe": "CWE-999",
            "evidence": {"url": "http://localhost/completely/different"}
        }]

        candidates = correlator._find_dast_candidates(sample_sast_finding, dast_findings)
        assert len(candidates) == 0  # Below threshold

    def test_heuristic_correlation_high_score(self, correlator, sample_sast_finding, sample_dast_finding):
        """Test heuristic correlation with high match score"""
        result = correlator._heuristic_correlation(sample_sast_finding, sample_dast_finding, match_score=0.95)

        assert result.status == CorrelationStatus.CONFIRMED
        assert result.confidence >= 0.9
        assert result.exploitability == "moderate"
        assert result.sast_finding_id == "sast-001"
        assert result.dast_finding_id == "dast-001"

    def test_heuristic_correlation_medium_score(self, correlator, sample_sast_finding, sample_dast_finding):
        """Test heuristic correlation with medium match score"""
        result = correlator._heuristic_correlation(sample_sast_finding, sample_dast_finding, match_score=0.6)

        assert result.status == CorrelationStatus.PARTIAL
        assert 0.4 < result.confidence < 0.6
        assert result.exploitability == "complex"

    def test_heuristic_correlation_low_score(self, correlator, sample_sast_finding, sample_dast_finding):
        """Test heuristic correlation with low match score"""
        result = correlator._heuristic_correlation(sample_sast_finding, sample_dast_finding, match_score=0.3)

        assert result.status == CorrelationStatus.NOT_VERIFIED
        assert result.confidence < 0.5
        assert result.exploitability == "theoretical"

    def test_correlate_single_no_dast_coverage(self, correlator, sample_sast_finding):
        """Test correlating single finding with no DAST coverage"""
        result = correlator._correlate_single(sample_sast_finding, dast_findings=[], use_ai=False)

        assert result.status == CorrelationStatus.NO_DAST_COVERAGE
        assert result.confidence == 0.95
        assert result.exploitability == "unknown"
        assert result.dast_finding_id is None

    def test_correlate_single_with_match(self, correlator, sample_sast_finding, sample_dast_finding):
        """Test correlating single finding with DAST match"""
        result = correlator._correlate_single(
            sample_sast_finding,
            dast_findings=[sample_dast_finding],
            use_ai=False
        )

        assert result.status in [CorrelationStatus.CONFIRMED, CorrelationStatus.PARTIAL]
        assert result.confidence > 0.5
        assert result.dast_finding_id == "dast-001"

    def test_correlate_multiple_findings(self, correlator, sample_sast_finding, sample_dast_finding):
        """Test correlating multiple SAST findings"""
        sast_findings = [
            sample_sast_finding,
            {
                "id": "sast-002",
                "path": "src/api/products.py",
                "line": 10,
                "rule_id": "xss",
                "rule_name": "XSS",
                "severity": "medium",
                "cwe": "CWE-79",
                "evidence": {}
            }
        ]

        dast_findings = [sample_dast_finding]

        results = correlator.correlate(sast_findings, dast_findings, use_ai=False)

        assert len(results) == 2
        assert results[0].sast_finding_id == "sast-001"
        assert results[1].sast_finding_id == "sast-002"
        assert results[1].status == CorrelationStatus.NO_DAST_COVERAGE  # No matching DAST finding

    def test_summarize_finding(self, correlator, sample_sast_finding):
        """Test finding summarization"""
        summary = correlator._summarize_finding(sample_sast_finding)

        assert summary["id"] == "sast-001"
        assert summary["type"] == "SQL Injection"
        assert summary["path"] == "src/api/users.py"
        assert summary["severity"] == "high"
        assert summary["cwe"] == "CWE-89"

    def test_export_json(self, correlator, tmp_path):
        """Test JSON export"""
        results = [
            CorrelationResult(
                sast_finding_id="sast-001",
                dast_finding_id="dast-001",
                status=CorrelationStatus.CONFIRMED,
                confidence=0.95,
                exploitability="trivial",
                reasoning="Test",
                match_score=0.98
            )
        ]

        output_file = tmp_path / "test-output.json"
        correlator._export_json(results, str(output_file))

        assert output_file.exists()

        with open(output_file) as f:
            data = json.load(f)

        assert data["metadata"]["total_findings"] == 1
        assert data["metadata"]["confirmed"] == 1
        assert len(data["correlations"]) == 1
        assert data["correlations"][0]["sast_finding_id"] == "sast-001"

    def test_export_markdown(self, correlator, tmp_path):
        """Test Markdown export"""
        results = [
            CorrelationResult(
                sast_finding_id="sast-001",
                dast_finding_id="dast-001",
                status=CorrelationStatus.CONFIRMED,
                confidence=0.95,
                exploitability="trivial",
                reasoning="Test reasoning",
                match_score=0.98
            )
        ]

        output_file = tmp_path / "test-report.md"
        correlator._export_markdown(results, str(output_file))

        assert output_file.exists()

        content = output_file.read_text()
        assert "# SAST-DAST Correlation Report" in content
        assert "## Summary" in content
        assert "sast-001" in content

    def test_build_correlation_prompt(self, correlator, sample_sast_finding, sample_dast_finding):
        """Test AI correlation prompt building"""
        prompt = correlator._build_correlation_prompt(
            sample_sast_finding,
            sample_dast_finding,
            match_score=0.95
        )

        assert "SAST Finding" in prompt
        assert "DAST Finding" in prompt
        assert "sast-001" in prompt
        assert "dast-001" in prompt
        assert "SQL Injection" in prompt
        assert "0.95" in prompt
        assert "JSON only" in prompt


class TestIntegration:
    """Integration tests for full correlation workflow"""

    @pytest.fixture
    def full_correlator(self):
        """Create correlator without LLM for integration tests"""
        with patch("sast_dast_correlator.LLMManager"):
            correlator = SASTDASTCorrelator()
            correlator.llm = None
            return correlator

    def test_full_workflow(self, full_correlator, tmp_path):
        """Test complete correlation workflow"""
        # Sample findings
        sast_findings = [
            {
                "id": "sast-001",
                "path": "src/api/users.py",
                "line": 42,
                "rule_id": "sql-injection",
                "rule_name": "SQL Injection",
                "severity": "high",
                "cwe": "CWE-89",
                "evidence": {"message": "SQL injection", "snippet": "SELECT * FROM users"}
            },
            {
                "id": "sast-002",
                "path": "src/api/products.py",
                "line": 10,
                "rule_id": "xss",
                "rule_name": "XSS",
                "severity": "medium",
                "cwe": "CWE-79",
                "evidence": {}
            }
        ]

        dast_findings = [
            {
                "id": "dast-001",
                "path": "/api/users",
                "rule_id": "sql-injection",
                "rule_name": "SQL Injection",
                "severity": "high",
                "cwe": "CWE-89",
                "evidence": {
                    "url": "http://localhost/api/users?id=1'",
                    "method": "GET",
                    "message": "SQL injection confirmed",
                    "poc": "curl test"
                }
            }
        ]

        # Run correlation
        results = full_correlator.correlate(sast_findings, dast_findings, use_ai=False)

        # Verify results
        assert len(results) == 2

        # First finding should be confirmed
        assert results[0].status in [CorrelationStatus.CONFIRMED, CorrelationStatus.PARTIAL]
        assert results[0].sast_finding_id == "sast-001"

        # Second finding should have no coverage
        assert results[1].status == CorrelationStatus.NO_DAST_COVERAGE
        assert results[1].sast_finding_id == "sast-002"

        # Export results
        output_file = tmp_path / "results.json"
        full_correlator.export_results(results, str(output_file))

        assert output_file.exists()
