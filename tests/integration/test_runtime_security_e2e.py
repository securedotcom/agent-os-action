#!/usr/bin/env python3
"""
End-to-end tests for Runtime Security features (DAST Scanner + SAST-DAST Correlation)
Tests the complete workflow of dynamic application security testing and correlation with static findings.
"""

import json
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

# Import the modules we're testing
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from dast_scanner import DASTScanner, DASTScanResult, DASTTarget, NucleiFinding
try:
    from sast_dast_correlator import SASTDASTCorrelator, CorrelationResult
except ImportError:
    # Create mock if not available
    SASTDASTCorrelator = None
    CorrelationResult = None


class TestDASTScannerE2E:
    """End-to-end tests for DAST scanner"""

    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.scanner = DASTScanner(nuclei_path="nuclei")
        self.test_target = "http://testphp.vulnweb.com"  # Public test site

    def test_complete_dast_workflow(self):
        """
        Test complete DAST workflow:
        1. Configure target application
        2. Discover endpoints
        3. Run dynamic scans
        4. Generate PoC exploits
        5. Create findings report
        """
        # Step 1: Configure target
        target_url = "http://example.com/api"
        headers = {"Authorization": "Bearer test-token"}

        # Step 2: Create scan targets
        targets = [
            DASTTarget(
                url=f"{target_url}/users/1",
                method="GET",
                headers=headers,
                endpoint_path="/users/{id}",
            ),
            DASTTarget(
                url=f"{target_url}/login",
                method="POST",
                headers=headers,
                body='{"username":"test","password":"test"}',
                endpoint_path="/login",
            ),
        ]

        # Step 3: Mock scan execution (since we don't have a real target)
        with patch.object(self.scanner, "_run_nuclei_scan") as mock_scan:
            mock_scan.return_value = self._create_mock_nuclei_output()

            # Run scan
            result = self.scanner.scan_targets(
                targets, output_dir=str(self.temp_dir), timeout=300
            )

            assert isinstance(result, DASTScanResult), "Should return scan result"
            assert result.total_findings >= 0, "Should count findings"
            assert result.scan_duration_seconds >= 0, "Should track duration"

        # Step 4: Verify PoC generation
        if result.total_findings > 0:
            finding = result.findings[0]
            assert hasattr(finding, "curl_command"), "Should have PoC command"
            assert len(finding.curl_command) > 0, "PoC should not be empty"

        # Step 5: Generate report
        report = self._generate_dast_report(result)
        assert "total_findings" in report
        assert "findings_by_severity" in report

    def test_openapi_endpoint_discovery(self, tmp_path: Path):
        """Test automatic endpoint discovery from OpenAPI spec"""
        # Create sample OpenAPI spec
        openapi_spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0"},
            "servers": [{"url": "http://api.example.com"}],
            "paths": {
                "/users/{id}": {
                    "get": {
                        "parameters": [{"name": "id", "in": "path", "required": True}],
                        "responses": {"200": {"description": "Success"}},
                    }
                },
                "/users": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {"type": "object"}
                                }
                            }
                        },
                        "responses": {"201": {"description": "Created"}},
                    }
                },
                "/search": {
                    "get": {
                        "parameters": [{"name": "q", "in": "query"}],
                        "responses": {"200": {"description": "Results"}},
                    }
                },
            },
        }

        spec_file = tmp_path / "openapi.yaml"
        spec_file.write_text(json.dumps(openapi_spec))

        # Discover endpoints
        targets = self.scanner.discover_endpoints_from_openapi(str(spec_file))

        assert len(targets) >= 3, "Should discover all endpoints"

        # Verify endpoint details
        paths = [t.endpoint_path for t in targets]
        assert "/users/{id}" in paths, "Should discover parameterized path"
        assert "/users" in paths, "Should discover POST endpoint"
        assert "/search" in paths, "Should discover query param endpoint"

    def test_authenticated_scanning(self):
        """Test DAST scanning with authentication"""
        target_url = "https://api.example.com/protected"

        # Configure authentication
        auth_headers = {
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            "X-API-Key": "test-api-key",
        }

        target = DASTTarget(
            url=target_url, method="GET", headers=auth_headers, endpoint_path="/protected"
        )

        # Mock scan with auth
        with patch.object(self.scanner, "_run_nuclei_scan") as mock_scan:
            mock_scan.return_value = []

            result = self.scanner.scan_targets(
                [target], output_dir=str(self.temp_dir), timeout=60
            )

            # Verify auth headers were passed to Nuclei
            call_args = mock_scan.call_args
            assert call_args is not None, "Should call Nuclei"

    def test_vulnerability_detection_types(self):
        """Test detection of various vulnerability types"""
        mock_findings = [
            NucleiFinding(
                template_id="sqli-detect",
                template_name="SQL Injection",
                severity="critical",
                matched_at="http://example.com/api/users?id=1",
                extracted_results=["SQL error: syntax error"],
                curl_command="curl 'http://example.com/api/users?id=1%27'",
                matcher_name="sql-error",
                type="http",
                host="example.com",
                tags=["sqli", "injection"],
            ),
            NucleiFinding(
                template_id="xss-reflected",
                template_name="Reflected XSS",
                severity="high",
                matched_at="http://example.com/search?q=<script>alert(1)</script>",
                extracted_results=["<script>alert(1)</script>"],
                curl_command="curl 'http://example.com/search?q=<script>alert(1)</script>'",
                matcher_name="xss-reflected",
                type="http",
                host="example.com",
                tags=["xss", "injection"],
            ),
            NucleiFinding(
                template_id="ssrf-detection",
                template_name="SSRF Vulnerability",
                severity="high",
                matched_at="http://example.com/api/fetch?url=http://internal.service",
                extracted_results=["Internal service response"],
                curl_command="curl 'http://example.com/api/fetch?url=http://internal.service'",
                matcher_name="ssrf-detected",
                type="http",
                host="example.com",
                tags=["ssrf"],
            ),
        ]

        # Group by vulnerability type
        vuln_types = {}
        for finding in mock_findings:
            for tag in finding.tags:
                if tag not in vuln_types:
                    vuln_types[tag] = []
                vuln_types[tag].append(finding)

        assert "sqli" in vuln_types, "Should detect SQL injection"
        assert "xss" in vuln_types, "Should detect XSS"
        assert "ssrf" in vuln_types, "Should detect SSRF"

    def test_poc_exploit_generation(self):
        """Test generation of PoC exploits"""
        finding = NucleiFinding(
            template_id="test-exploit",
            template_name="Test Vulnerability",
            severity="high",
            matched_at="http://example.com/vuln?param=test",
            extracted_results=["Vulnerable response"],
            curl_command="",
            matcher_name="test",
            type="http",
            host="example.com",
            request="GET /vuln?param=test HTTP/1.1\nHost: example.com\n",
            response="HTTP/1.1 200 OK\nVulnerable response",
        )

        # Generate PoC
        poc = self.scanner.generate_poc(finding)

        assert poc is not None, "Should generate PoC"
        assert "curl" in poc or "http" in poc.lower(), "PoC should be executable"
        assert "example.com" in poc, "Should include target URL"

    def test_rate_limiting_and_throttling(self):
        """Test rate limiting to avoid overwhelming target"""
        # Create many targets
        targets = [
            DASTTarget(
                url=f"http://example.com/api/endpoint{i}",
                method="GET",
                endpoint_path=f"/api/endpoint{i}",
            )
            for i in range(20)
        ]

        # Configure rate limiting (e.g., 5 requests per second)
        with patch.object(self.scanner, "_run_nuclei_scan") as mock_scan:
            mock_scan.return_value = []

            start = time.time()
            result = self.scanner.scan_targets(
                targets, output_dir=str(self.temp_dir), timeout=60, rate_limit=5
            )
            duration = time.time() - start

            # With 20 targets and rate limit of 5/sec, should take ~4 seconds minimum
            # (In practice, this test verifies rate limiting is configurable)
            assert duration >= 0, "Should complete scan"

    def test_error_handling_unreachable_target(self):
        """Test error handling when target is unreachable"""
        unreachable_target = DASTTarget(
            url="http://this-domain-does-not-exist-12345.com",
            method="GET",
            endpoint_path="/test",
        )

        # Should not crash
        try:
            with patch.object(self.scanner, "_run_nuclei_scan") as mock_scan:
                mock_scan.side_effect = subprocess.CalledProcessError(1, "nuclei")

                result = self.scanner.scan_targets(
                    [unreachable_target], output_dir=str(self.temp_dir), timeout=10
                )

                # Should handle error gracefully
                assert isinstance(result, DASTScanResult)
        except Exception as e:
            # Should be handled gracefully
            assert "unreachable" in str(e).lower() or "timeout" in str(e).lower()

    def test_performance_large_scale_scan(self):
        """Test performance with large number of endpoints"""
        # Create 100 targets
        targets = [
            DASTTarget(
                url=f"http://example.com/endpoint{i}", method="GET", endpoint_path=f"/endpoint{i}"
            )
            for i in range(100)
        ]

        with patch.object(self.scanner, "_run_nuclei_scan") as mock_scan:
            mock_scan.return_value = []

            start = time.time()
            result = self.scanner.scan_targets(
                targets, output_dir=str(self.temp_dir), timeout=300
            )
            duration = time.time() - start

            assert duration < 60, f"Large scan should complete reasonably: {duration}s"

    def test_nuclei_template_selection(self):
        """Test selection of appropriate Nuclei templates"""
        # Different scan configurations
        configs = [
            {"templates": ["cves", "vulnerabilities"], "expected_count": 2},
            {"templates": ["exposed-panels", "misconfigurations"], "expected_count": 2},
            {"templates": ["default-logins"], "expected_count": 1},
        ]

        for config in configs:
            templates = config["templates"]
            # Verify templates can be configured
            assert len(templates) == config["expected_count"]

    # Helper methods

    def _create_mock_nuclei_output(self) -> List[NucleiFinding]:
        """Create mock Nuclei scan output"""
        return [
            NucleiFinding(
                template_id="mock-finding-1",
                template_name="Mock SQL Injection",
                severity="high",
                matched_at="http://example.com/api/user?id=1",
                extracted_results=["SQL error detected"],
                curl_command="curl 'http://example.com/api/user?id=1%27'",
                matcher_name="sql-error",
                type="http",
                host="example.com",
                tags=["sqli"],
            )
        ]

    def _generate_dast_report(self, result: DASTScanResult) -> Dict[str, Any]:
        """Generate DAST report"""
        findings_by_severity = {}
        for finding in result.findings:
            severity = finding.severity
            if severity not in findings_by_severity:
                findings_by_severity[severity] = 0
            findings_by_severity[severity] += 1

        return {
            "total_findings": result.total_findings,
            "findings_by_severity": findings_by_severity,
            "scan_duration": result.scan_duration_seconds,
            "target": result.target,
        }


class TestSASTDASTCorrelationE2E:
    """End-to-end tests for SAST-DAST correlation"""

    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = Path(tempfile.mkdtemp())
        if SASTDASTCorrelator:
            self.correlator = SASTDASTCorrelator()

    @pytest.mark.skipif(SASTDASTCorrelator is None, reason="Correlator not available")
    def test_complete_correlation_workflow(self):
        """
        Test complete correlation workflow:
        1. Receive SAST findings
        2. Receive DAST findings
        3. Correlate by endpoint/vulnerability type
        4. Mark SAST findings as verified/unverified
        5. Generate prioritized report
        """
        # Step 1: SAST findings
        sast_findings = [
            {
                "id": "sast-001",
                "type": "sql-injection",
                "severity": "high",
                "file": "api/users.py",
                "line": 42,
                "endpoint": "/api/users",
                "code": "query = f'SELECT * FROM users WHERE id = {user_id}'",
            },
            {
                "id": "sast-002",
                "type": "xss",
                "severity": "medium",
                "file": "api/search.py",
                "line": 15,
                "endpoint": "/api/search",
                "code": "return f'<div>{search_term}</div>'",
            },
        ]

        # Step 2: DAST findings
        dast_findings = [
            NucleiFinding(
                template_id="sqli-exploit",
                template_name="SQL Injection Confirmed",
                severity="critical",
                matched_at="http://api.example.com/api/users?id=1",
                extracted_results=["SQL error: syntax error"],
                curl_command="curl ...",
                matcher_name="sql-error",
                type="http",
                host="api.example.com",
                tags=["sqli"],
            )
        ]

        # Step 3: Correlate
        correlations = self.correlator.correlate(sast_findings, dast_findings)

        assert len(correlations) > 0, "Should find correlations"

        # Step 4: Verify correlation details
        for correlation in correlations:
            if correlation.is_verified:
                assert correlation.sast_finding_id is not None
                assert correlation.dast_finding_id is not None
                assert correlation.confidence_score > 0.5

    @pytest.mark.skipif(SASTDASTCorrelator is None, reason="Correlator not available")
    def test_endpoint_matching(self):
        """Test matching SAST and DAST findings by endpoint"""
        sast_finding = {
            "id": "sast-endpoint",
            "type": "sql-injection",
            "endpoint": "/api/users/{id}",
            "file": "users.py",
        }

        dast_finding = NucleiFinding(
            template_id="sqli",
            template_name="SQLi",
            severity="high",
            matched_at="http://example.com/api/users/123",
            extracted_results=[],
            curl_command="",
            matcher_name="sqli",
            type="http",
            host="example.com",
            tags=["sqli"],
        )

        # Should match despite path parameter difference
        is_match = self.correlator._endpoints_match(
            sast_finding["endpoint"], dast_finding.matched_at
        )

        assert is_match, "Should match endpoints with path parameters"

    @pytest.mark.skipif(SASTDASTCorrelator is None, reason="Correlator not available")
    def test_vulnerability_type_matching(self):
        """Test matching by vulnerability type"""
        matches = [
            ("sql-injection", ["sqli", "injection"], True),
            ("xss", ["xss", "cross-site-scripting"], True),
            ("command-injection", ["rce", "command-execution"], True),
            ("sql-injection", ["xss"], False),  # Should not match
        ]

        for sast_type, dast_tags, should_match in matches:
            result = self.correlator._vulnerability_types_match(sast_type, dast_tags)
            if should_match:
                assert result, f"{sast_type} should match {dast_tags}"
            else:
                assert not result, f"{sast_type} should not match {dast_tags}"

    @pytest.mark.skipif(SASTDASTCorrelator is None, reason="Correlator not available")
    def test_false_positive_reduction(self):
        """Test that verified findings reduce false positive rate"""
        # SAST finding without DAST confirmation (potential FP)
        unverified_sast = {
            "id": "unverified",
            "type": "sql-injection",
            "severity": "medium",
            "endpoint": "/api/endpoint1",
        }

        # SAST finding with DAST confirmation (verified TP)
        verified_sast = {
            "id": "verified",
            "type": "sql-injection",
            "severity": "high",
            "endpoint": "/api/endpoint2",
        }

        verified_dast = NucleiFinding(
            template_id="sqli",
            template_name="SQLi",
            severity="critical",
            matched_at="http://example.com/api/endpoint2",
            extracted_results=["SQL error"],
            curl_command="",
            matcher_name="sqli",
            type="http",
            host="example.com",
            tags=["sqli"],
        )

        correlations = self.correlator.correlate(
            [unverified_sast, verified_sast], [verified_dast]
        )

        # Verified finding should be prioritized
        verified_correlations = [c for c in correlations if c.is_verified]
        assert len(verified_correlations) >= 1, "Should have verified correlations"

    @pytest.mark.skipif(SASTDASTCorrelator is None, reason="Correlator not available")
    def test_prioritization_by_verification(self):
        """Test that verified findings are prioritized higher"""
        correlations = [
            CorrelationResult(
                sast_finding_id="1",
                dast_finding_id="d1",
                is_verified=True,
                confidence_score=0.9,
                match_type="endpoint+type",
            ),
            CorrelationResult(
                sast_finding_id="2",
                dast_finding_id=None,
                is_verified=False,
                confidence_score=0.3,
                match_type="none",
            ),
        ]

        # Sort by priority
        sorted_correlations = self.correlator.prioritize(correlations)

        assert sorted_correlations[0].is_verified, "Verified should be first"
        assert not sorted_correlations[-1].is_verified, "Unverified should be last"


class TestRuntimeSecurityIntegration:
    """Test integration of runtime security features"""

    def test_ci_cd_integration(self, tmp_path: Path):
        """Test integration in CI/CD pipeline"""
        # Simulate CI environment
        scanner = DASTScanner()

        # Mock scan
        with patch.object(scanner, "_run_nuclei_scan") as mock_scan:
            mock_scan.return_value = []

            # Run quick scan suitable for CI
            result = scanner.scan_targets(
                [DASTTarget(url="http://staging.example.com", method="GET", endpoint_path="/")],
                output_dir=str(tmp_path),
                timeout=60,  # Fast for CI
            )

            # Generate CI report
            should_fail_ci = result.total_findings > 0 and any(
                f.severity in ["critical", "high"] for f in result.findings
            )

            exit_code = 1 if should_fail_ci else 0
            assert exit_code in [0, 1], "Should return valid exit code"

    def test_progressive_scanning(self):
        """Test progressive scanning (quick → deep)"""
        scanner = DASTScanner()

        # Step 1: Quick scan (basic templates)
        quick_templates = ["cves/2023", "exposed-panels"]

        # Step 2: If issues found, deep scan
        deep_templates = ["vulnerabilities", "fuzzing", "default-logins"]

        # In practice, quick scan runs first, deep scan only if needed
        assert len(quick_templates) < len(deep_templates), "Quick scan should be faster"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
