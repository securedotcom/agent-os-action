"""Checkov IaC normalizer"""


from .base import Finding, Normalizer


class CheckovNormalizer(Normalizer):
    """Normalize Checkov output to Finding format"""

    def normalize(self, raw_output: dict) -> list[Finding]:
        """
        Convert Checkov JSON to Finding objects

        Args:
            raw_output: Checkov JSON output

        Returns:
            List of Finding objects
        """
        findings = []
        git_context = self._get_git_context()

        # Checkov format: { results: { failed_checks: [...] } }
        results = raw_output.get("results", {})
        failed_checks = results.get("failed_checks", [])

        for check in failed_checks:
            # Extract location
            file_path = check.get("file_path", "unknown")
            file_line_range = check.get("file_line_range", [0, 0])
            start_line = file_line_range[0] if file_line_range else 0

            finding = Finding(
                id=self._generate_id(
                    {
                        "repo": git_context["repo"],
                        "path": file_path,
                        "rule_id": check.get("check_id", "unknown"),
                        "line": start_line,
                    }
                ),
                origin="checkov",
                repo=git_context["repo"],
                commit_sha=git_context["commit_sha"],
                branch=git_context["branch"],
                asset_type="iac",
                path=file_path,
                line=start_line,
                resource_id=check.get("resource", ""),
                rule_id=check.get("check_id", "unknown"),
                rule_name=check.get("check_name", "IaC Check"),
                category="IAC",
                severity=self._map_severity(check),
                evidence={
                    "message": check.get("check_result", {}).get("result", "IaC misconfiguration detected"),
                    "snippet": "\n".join(check.get("code_block", [])),
                    "artifact_url": check.get("guideline", ""),
                },
                references=[check.get("guideline", "")] if check.get("guideline") else [],
                confidence=0.9,  # Checkov rules are well-tested
            )

            # IaC findings with public exposure are high risk
            if "public" in finding.evidence["message"].lower() or "0.0.0.0" in finding.evidence["snippet"]:
                finding.service_tier = "public"
                finding.severity = "high" if finding.severity == "medium" else finding.severity

            finding.risk_score = finding.calculate_risk_score()
            findings.append(finding)

        return findings

    def _map_severity(self, check: dict) -> str:
        """Map Checkov severity to standard severity"""
        # Checkov uses severity in check_result
        check_result = check.get("check_result", {})
        severity = check_result.get("severity", "MEDIUM")

        mapping = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "INFO": "info"}
        return mapping.get(severity.upper(), "medium")
