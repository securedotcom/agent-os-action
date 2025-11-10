#!/usr/bin/env python3
"""
LLM Secret Detector - Phase 2.9
Uses Foundation-Sec-8B for semantic secret detection (inspired by FuzzForge's 84% recall)
Cross-validates with Gitleaks/TruffleHog - only verified secrets can block PRs
"""

import json
import re
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from normalizer.base import Finding
from providers.sagemaker_foundation_sec import SageMakerFoundationSecProvider


class LLMSecretDetector:
    """
    Semantic secret detection using Foundation-Sec-8B

    Finds obfuscated and hidden secrets that pattern-based tools miss:
    - Base64 encoded credentials
    - Split strings
    - Obfuscated keys
    - Comments with credentials
    - Environment variable patterns

    Cross-validates with Gitleaks/TruffleHog for verification
    """

    def __init__(self):
        self.foundation_sec = SageMakerFoundationSecProvider()
        print("✅ Foundation-Sec-8B initialized for LLM secret detection")

        # Patterns for quick pre-filtering
        self.suspicious_patterns = [
            r"password",
            r"secret",
            r"api[_-]?key",
            r"token",
            r"credential",
            r"auth",
            r"private[_-]?key",
            r"access[_-]?key",
            r"[A-Za-z0-9+/]{40,}={0,2}",  # Base64-like
        ]

    def detect_secrets(self, file_path: str, content: str, git_context: dict) -> list[Finding]:
        """
        Detect secrets in file content using Foundation-Sec

        Args:
            file_path: Path to file
            content: File content
            git_context: Git context (repo, commit, branch)

        Returns:
            List of Finding objects for detected secrets
        """
        findings = []

        # Pre-filter: only analyze files with suspicious patterns
        if not self._has_suspicious_patterns(content):
            return findings

        print(f"   🔍 LLM analyzing {file_path}...")

        # Split content into chunks (for large files)
        chunks = self._chunk_content(content)

        for chunk_idx, chunk in enumerate(chunks):
            # Ask Foundation-Sec to find secrets
            secrets = self._detect_secrets_in_chunk(chunk, file_path, chunk_idx)
            findings.extend(secrets)

        # Add git context to all findings
        for finding in findings:
            finding.repo = git_context.get("repo", "unknown")
            finding.commit_sha = git_context.get("commit_sha", "unknown")
            finding.branch = git_context.get("branch", "unknown")
            finding.path = file_path
            finding.category = "SECRETS"
            finding.origin = "llm_secret_detector"
            finding.secret_verified = "false"  # Not verified until cross-checked

        return findings

    def cross_validate(
        self, llm_findings: list[Finding], gitleaks_findings: list[Finding], trufflehog_findings: list[Finding]
    ) -> list[Finding]:
        """
        Cross-validate LLM findings with Gitleaks/TruffleHog

        Only mark as verified if:
        1. LLM found it AND (Gitleaks OR TruffleHog) found it
        2. OR TruffleHog verified it via API

        This reduces false positives while maintaining high recall
        """
        print("\n🔐 Cross-validating secrets...")
        print(f"   LLM findings: {len(llm_findings)}")
        print(f"   Gitleaks findings: {len(gitleaks_findings)}")
        print(f"   TruffleHog findings: {len(trufflehog_findings)}")

        verified_findings = []

        # Build sets of (path, line) for quick lookup
        gitleaks_locations = {(f.path, f.line) for f in gitleaks_findings}
        trufflehog_locations = {(f.path, f.line) for f in trufflehog_findings}
        trufflehog_verified = {(f.path, f.line) for f in trufflehog_findings if f.secret_verified == "true"}

        # Check each LLM finding
        for llm_finding in llm_findings:
            location = (llm_finding.path, llm_finding.line)

            # Verified if TruffleHog API-verified it
            if location in trufflehog_verified:
                llm_finding.secret_verified = "true"
                llm_finding.evidence["verification_method"] = "trufflehog_api"
                verified_findings.append(llm_finding)
                continue

            # Verified if both LLM and (Gitleaks OR TruffleHog) found it
            if location in gitleaks_locations or location in trufflehog_locations:
                llm_finding.secret_verified = "true"
                llm_finding.evidence["verification_method"] = "cross_validation"
                verified_findings.append(llm_finding)
                continue

            # Not verified - keep as warning but don't block
            llm_finding.secret_verified = "false"
            llm_finding.severity = "medium"  # Downgrade unverified
            llm_finding.evidence["verification_method"] = "llm_only"
            verified_findings.append(llm_finding)

        verified_count = sum(1 for f in verified_findings if f.secret_verified == "true")
        print("\n✅ Cross-validation complete:")
        print(f"   Verified secrets: {verified_count}")
        print(f"   Unverified (warnings): {len(verified_findings) - verified_count}")

        return verified_findings

    def _has_suspicious_patterns(self, content: str) -> bool:
        """Quick pre-filter for suspicious patterns"""
        content_lower = content.lower()
        return any(re.search(pattern, content_lower, re.IGNORECASE) for pattern in self.suspicious_patterns)

    def _chunk_content(self, content: str, max_lines: int = 100) -> list[tuple[str, int]]:
        """
        Split content into chunks for analysis

        Returns list of (chunk_content, start_line)
        """
        lines = content.split("\n")
        chunks = []

        for i in range(0, len(lines), max_lines):
            chunk_lines = lines[i : i + max_lines]
            chunk_content = "\n".join(chunk_lines)
            chunks.append((chunk_content, i + 1))  # 1-indexed line numbers

        return chunks

    def _detect_secrets_in_chunk(self, chunk: tuple[str, int], file_path: str, chunk_idx: int) -> list[Finding]:
        """Use Foundation-Sec to detect secrets in a chunk"""
        chunk_content, start_line = chunk

        try:
            # Build prompt for Foundation-Sec
            prompt = self._build_secret_detection_prompt(chunk_content, file_path)

            # Get detection from Foundation-Sec
            response = self.foundation_sec.analyze_code(code=chunk_content, context=prompt, focus="secret_detection")

            # Parse response
            secrets = self._parse_secret_detection(response, chunk_content, start_line)

            return secrets

        except Exception as e:
            print(f"      ⚠️  LLM detection failed: {e}")
            return []

    def _build_secret_detection_prompt(self, code: str, file_path: str) -> str:
        """Build prompt for Foundation-Sec secret detection"""
        return f"""Analyze this code for hardcoded secrets, credentials, and API keys.

**File:** {file_path}

**Code:**
```
{code}
```

**Task:** Find ALL secrets, including:
1. Obvious: API keys, passwords, tokens
2. Obfuscated: Base64 encoded, split strings, XOR'd
3. Hidden: Comments, variable names, test data
4. Patterns: AWS keys, GitHub tokens, database URLs

For each secret found, provide:
- Line number (approximate)
- Secret type (api_key, password, token, etc.)
- Evidence (the actual secret or pattern)
- Confidence (0.0-1.0)

**Important:**
- Include secrets in comments and strings
- Look for obfuscation patterns
- Check for credential-like patterns even if not obvious

Respond with ONLY a JSON array:
[
  {{
    "line": 42,
    "secret_type": "api_key",
    "evidence": "the secret value or pattern",
    "confidence": 0.9,
    "reasoning": "why this is likely a secret"
  }}
]

If no secrets found, respond with: []
"""

    def _parse_secret_detection(self, response: str, code: str, start_line: int) -> list[Finding]:
        """Parse Foundation-Sec secret detection response"""
        findings = []

        try:
            # Extract JSON from response
            if "[" in response and "]" in response:
                start = response.index("[")
                end = response.rindex("]") + 1
                json_str = response[start:end]
                secrets_data = json.loads(json_str)

                # Create Finding objects
                for secret in secrets_data:
                    line_num = secret.get("line", 0) + start_line - 1

                    finding = Finding(
                        id="",  # Will be generated
                        origin="llm_secret_detector",
                        repo="",  # Will be set by caller
                        commit_sha="",
                        branch="",
                        path="",
                        asset_type="code",
                        rule_id="llm-secret-detection",
                        rule_name=f"LLM Detected {secret.get('secret_type', 'secret')}",
                        category="SECRETS",
                        severity="critical",  # Will be downgraded if unverified
                        line=line_num,
                        evidence={
                            "message": secret.get("reasoning", "LLM detected potential secret"),
                            "secret_type": secret.get("secret_type", "unknown"),
                            "snippet": self._extract_snippet(code, line_num - start_line + 1),
                            "confidence_reason": secret.get("reasoning", ""),
                        },
                        confidence=float(secret.get("confidence", 0.7)),
                        secret_verified="false",  # Not verified yet
                    )

                    # Generate ID
                    finding.id = finding.dedup_key()

                    findings.append(finding)

        except Exception as e:
            print(f"      ⚠️  Failed to parse secrets: {e}")

        return findings

    def _extract_snippet(self, code: str, line_num: int, context_lines: int = 2) -> str:
        """Extract code snippet around line"""
        lines = code.split("\n")
        start = max(0, line_num - context_lines - 1)
        end = min(len(lines), line_num + context_lines)
        return "\n".join(lines[start:end])


def main():
    """CLI interface for LLM secret detection"""
    import argparse

    parser = argparse.ArgumentParser(description="Detect secrets using Foundation-Sec LLM")
    parser.add_argument("--file", "-f", required=True, help="File to scan")
    parser.add_argument("--output", "-o", required=True, help="Output findings JSON file")
    parser.add_argument("--gitleaks", help="Gitleaks findings JSON for cross-validation")
    parser.add_argument("--trufflehog", help="TruffleHog findings JSON for cross-validation")

    args = parser.parse_args()

    # Read file
    with open(args.file) as f:
        content = f.read()

    # Get git context
    import subprocess

    try:
        repo = subprocess.check_output(["git", "config", "--get", "remote.origin.url"], text=True).strip()
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
        branch = subprocess.check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"], text=True).strip()
        git_context = {"repo": repo, "commit_sha": commit, "branch": branch}
    except:
        git_context = {"repo": "unknown", "commit_sha": "unknown", "branch": "unknown"}

    # Detect secrets
    detector = LLMSecretDetector()
    llm_findings = detector.detect_secrets(args.file, content, git_context)

    # Cross-validate if other tool results provided
    if args.gitleaks or args.trufflehog:
        gitleaks_findings = []
        trufflehog_findings = []

        if args.gitleaks:
            with open(args.gitleaks) as f:
                gitleaks_findings = [Finding.from_dict(f) for f in json.load(f)]

        if args.trufflehog:
            with open(args.trufflehog) as f:
                trufflehog_findings = [Finding.from_dict(f) for f in json.load(f)]

        final_findings = detector.cross_validate(llm_findings, gitleaks_findings, trufflehog_findings)
    else:
        final_findings = llm_findings

    # Save results
    with open(args.output, "w") as f:
        json.dump([f.to_dict() for f in final_findings], f, indent=2)

    print(f"\n✅ LLM secret detection complete: {len(final_findings)} findings saved to {args.output}")


if __name__ == "__main__":
    main()
