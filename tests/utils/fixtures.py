"""
Test fixture management utilities
Provides easy access to real scanner outputs and vulnerable code samples
"""
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

# Paths to fixture directories
FIXTURES_ROOT = Path(__file__).parent.parent / "fixtures"
SCANNER_OUTPUTS = FIXTURES_ROOT / "scanner_outputs"
VULNERABLE_APP = FIXTURES_ROOT / "vulnerable_app"


class FixtureManager:
    """Manages test fixtures for integration tests"""

    @staticmethod
    def load_scanner_output(scanner_name: str, filename: Optional[str] = None) -> Dict[str, Any]:
        """
        Load scanner output from fixtures

        Args:
            scanner_name: Name of scanner (semgrep, trivy, checkov, trufflehog, gitleaks)
            filename: Optional specific filename, otherwise uses default naming

        Returns:
            Dictionary with scanner output
        """
        if filename is None:
            # Use default naming conventions
            filename_map = {
                "semgrep": "semgrep_vulnerable_api.json",
                "trivy": "trivy_vulnerabilities.json",
                "checkov": "checkov_terraform.json",
                "trufflehog": "trufflehog_vulnerable_app.json",
            }
            filename = filename_map.get(scanner_name)
            if filename is None:
                raise ValueError(f"Unknown scanner: {scanner_name}")

        filepath = SCANNER_OUTPUTS / filename
        if not filepath.exists():
            raise FileNotFoundError(f"Fixture not found: {filepath}")

        with open(filepath, 'r') as f:
            return json.load(f)

    @staticmethod
    def get_vulnerable_file_path(filename: str) -> Path:
        """
        Get path to vulnerable code sample

        Args:
            filename: Name of vulnerable file

        Returns:
            Path to vulnerable file
        """
        filepath = VULNERABLE_APP / filename
        if not filepath.exists():
            raise FileNotFoundError(f"Vulnerable file not found: {filepath}")
        return filepath

    @staticmethod
    def get_vulnerable_file_content(filename: str) -> str:
        """
        Get content of vulnerable code sample

        Args:
            filename: Name of vulnerable file

        Returns:
            File content as string
        """
        filepath = FixtureManager.get_vulnerable_file_path(filename)
        return filepath.read_text()

    @staticmethod
    def list_scanner_outputs() -> List[str]:
        """List all available scanner output fixtures"""
        if not SCANNER_OUTPUTS.exists():
            return []
        return [f.name for f in SCANNER_OUTPUTS.glob("*.json")]

    @staticmethod
    def list_vulnerable_files() -> List[str]:
        """List all vulnerable code samples"""
        if not VULNERABLE_APP.exists():
            return []
        return [f.name for f in VULNERABLE_APP.iterdir() if f.is_file()]


class ScannerOutputParser:
    """Parse and extract information from scanner outputs"""

    @staticmethod
    def extract_semgrep_findings(output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract findings from Semgrep output"""
        return output.get("findings", [])

    @staticmethod
    def extract_trivy_vulnerabilities(output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract vulnerabilities from Trivy output"""
        vulnerabilities = []
        results = output.get("Results", [])
        for result in results:
            for vuln in result.get("Vulnerabilities", []):
                vulnerabilities.append(vuln)
        return vulnerabilities

    @staticmethod
    def extract_checkov_failures(output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract failed checks from Checkov output"""
        failures = []
        # Checkov output can be list or dict
        if isinstance(output, list):
            for check_type_result in output:
                results = check_type_result.get("results", {})
                failures.extend(results.get("failed_checks", []))
        elif isinstance(output, dict):
            results = output.get("results", {})
            failures.extend(results.get("failed_checks", []))
        return failures

    @staticmethod
    def count_findings_by_severity(findings: List[Dict[str, Any]], severity_field: str = "severity") -> Dict[str, int]:
        """
        Count findings by severity level

        Args:
            findings: List of findings
            severity_field: Field name for severity in findings

        Returns:
            Dictionary with counts per severity level
        """
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            severity = finding.get(severity_field, "unknown").lower()
            if severity in counts:
                counts[severity] += 1
        return counts

    @staticmethod
    def filter_by_cwe(findings: List[Dict[str, Any]], cwe_id: str) -> List[Dict[str, Any]]:
        """Filter findings by CWE ID"""
        return [f for f in findings if f.get("cwe") == cwe_id or f.get("cwe_id") == cwe_id]

    @staticmethod
    def filter_by_severity(findings: List[Dict[str, Any]], min_severity: str) -> List[Dict[str, Any]]:
        """
        Filter findings by minimum severity

        Args:
            findings: List of findings
            min_severity: Minimum severity (critical, high, medium, low)
        """
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        min_level = severity_order.get(min_severity.lower(), 4)

        filtered = []
        for finding in findings:
            severity = finding.get("severity", "unknown").lower()
            if severity in severity_order and severity_order[severity] <= min_level:
                filtered.append(finding)
        return filtered


# Convenience instances
fixture_manager = FixtureManager()
scanner_parser = ScannerOutputParser()
