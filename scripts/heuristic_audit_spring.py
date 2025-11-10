#!/usr/bin/env python3
"""
Heuristic-only audit of spring-attack-surface (no API keys required)
Uses pattern matching and static analysis
"""

import ast
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


class HeuristicAuditor:
    """Fast heuristic-based security audit"""

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.findings = []

    def pre_scan_heuristics(self, file_path: str, content: str) -> list[dict[str, Any]]:
        """Scan for security patterns"""
        findings = []

        # Security patterns
        if re.search(r'(password|secret|api[_-]?key|token|credential)\s*=\s*["\'][^"\']{8,}["\']', content, re.I):
            findings.append(
                {
                    "type": "hardcoded-secrets",
                    "severity": "CRITICAL",
                    "line": self._find_line(content, r"(password|secret|api[_-]?key|token)"),
                    "description": "Potential hardcoded secret or API key detected",
                }
            )

        if re.search(r"eval\(|exec\(|__import__\(|compile\(", content):
            findings.append(
                {
                    "type": "dangerous-exec",
                    "severity": "HIGH",
                    "line": self._find_line(content, r"eval\(|exec\("),
                    "description": "Dangerous code execution function detected",
                }
            )

        if re.search(r'(SELECT|INSERT|UPDATE|DELETE).*[\+\%f].*["\']', content, re.I):
            findings.append(
                {
                    "type": "sql-injection-risk",
                    "severity": "CRITICAL",
                    "line": self._find_line(content, r"(SELECT|INSERT|UPDATE|DELETE)", re.I),
                    "description": "SQL query with string concatenation or f-string (injection risk)",
                }
            )

        if re.search(r"\.innerHTML\s*=|dangerouslySetInnerHTML|document\.write\(", content):
            findings.append(
                {
                    "type": "xss-risk",
                    "severity": "HIGH",
                    "line": self._find_line(content, r"\.innerHTML"),
                    "description": "XSS vulnerability via innerHTML or unsafe DOM manipulation",
                }
            )

        # Authentication/Authorization
        if re.search(r"(admin|root|superuser).*=.*(true|True|1)", content):
            findings.append(
                {
                    "type": "hardcoded-admin",
                    "severity": "HIGH",
                    "line": self._find_line(content, r"admin"),
                    "description": "Hardcoded admin/root privilege detected",
                }
            )

        if re.search(r"#\s*(TODO|FIXME|XXX|HACK).*secur", content, re.I):
            findings.append(
                {
                    "type": "security-todo",
                    "severity": "MEDIUM",
                    "line": self._find_line(content, r"TODO|FIXME", re.I),
                    "description": "Incomplete security implementation (TODO/FIXME comment)",
                }
            )

        # Weak crypto
        if re.search(r"(md5|sha1|des)\(", content, re.I):
            findings.append(
                {
                    "type": "weak-crypto",
                    "severity": "HIGH",
                    "line": self._find_line(content, r"md5|sha1", re.I),
                    "description": "Weak cryptographic algorithm (MD5/SHA1/DES)",
                }
            )

        # Input validation
        if re.search(r'request\.(args|form|json)\.get\(["\']', content) and "validate" not in content.lower() and "sanitize" not in content.lower():
                findings.append(
                    {
                        "type": "missing-input-validation",
                        "severity": "MEDIUM",
                        "line": self._find_line(content, r"request\."),
                        "description": "User input accessed without visible validation",
                    }
                )

        # SSRF risks
        if re.search(r"requests\.(get|post|put)\([^)]*\+", content):
            findings.append(
                {
                    "type": "ssrf-risk",
                    "severity": "HIGH",
                    "line": self._find_line(content, r"requests\."),
                    "description": "HTTP request with concatenated URL (SSRF risk)",
                }
            )

        # Logging sensitive data
        if re.search(r"(log|print).*\b(password|token|secret|key)\b", content, re.I):
            findings.append(
                {
                    "type": "sensitive-data-logging",
                    "severity": "MEDIUM",
                    "line": self._find_line(content, r"log.*password", re.I),
                    "description": "Potential logging of sensitive data",
                }
            )

        # Python-specific complexity
        if file_path.endswith(".py"):
            try:
                tree = ast.parse(content)
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        complexity = self._calculate_complexity(node)
                        if complexity > 15:
                            findings.append(
                                {
                                    "type": "high-complexity",
                                    "severity": "LOW",
                                    "line": node.lineno,
                                    "description": f'Function "{node.name}" has cyclomatic complexity of {complexity} (>15 threshold)',
                                }
                            )
            except Exception:
                pass

        return findings

    def _find_line(self, content: str, pattern: str, flags=0) -> int:
        """Find line number of pattern match"""
        try:
            match = re.search(pattern, content, flags)
            if match:
                return content[: match.start()].count("\n") + 1
        except:
            pass
        return 0

    def _calculate_complexity(self, node: ast.FunctionDef) -> int:
        """Calculate cyclomatic complexity"""
        complexity = 1
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.ExceptHandler)):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
        return complexity

    def audit_file(self, file_path: Path) -> list[dict[str, Any]]:
        """Audit a single file"""
        try:
            with open(file_path, encoding="utf-8") as f:
                content = f.read()

            findings = self.pre_scan_heuristics(str(file_path), content)

            # Add file context
            for finding in findings:
                finding["file"] = str(file_path.relative_to(self.repo_path))

            return findings
        except Exception as e:
            print(f"⚠️  Error reading {file_path}: {e}")
            return []

    def audit_repository(self, file_patterns: list[str] = None) -> dict[str, Any]:
        """Audit entire repository"""
        print(f"🔍 Scanning {self.repo_path.name}...")

        if not file_patterns:
            file_patterns = ["**/*.py", "**/*.js", "**/*.ts", "**/*.sql"]

        files_scanned = 0
        all_findings = []

        for pattern in file_patterns:
            for file_path in self.repo_path.glob(pattern):
                if any(
                    skip in str(file_path)
                    for skip in ["__pycache__", ".venv", "node_modules", ".git", "migrations/versions"]
                ):
                    continue

                findings = self.audit_file(file_path)
                all_findings.extend(findings)
                files_scanned += 1

                if findings and files_scanned % 10 == 0:
                    print(f"  Scanned {files_scanned} files, found {len(all_findings)} issues...")

        print(f"✅ Scanned {files_scanned} files\n")

        # Aggregate results
        severity_counts = defaultdict(int)
        type_counts = defaultdict(int)
        file_issues = defaultdict(list)

        for finding in all_findings:
            severity_counts[finding["severity"]] += 1
            type_counts[finding["type"]] += 1
            file_issues[finding["file"]].append(finding)

        return {
            "total_files": files_scanned,
            "total_findings": len(all_findings),
            "severity_counts": dict(severity_counts),
            "type_counts": dict(type_counts),
            "findings": all_findings,
            "files_with_issues": dict(file_issues),
        }


def generate_report(results: dict[str, Any], repo_name: str) -> str:
    """Generate markdown report"""

    critical = [f for f in results["findings"] if f["severity"] == "CRITICAL"]
    high = [f for f in results["findings"] if f["severity"] == "HIGH"]
    medium = [f for f in results["findings"] if f["severity"] == "MEDIUM"]
    low = [f for f in results["findings"] if f["severity"] == "LOW"]

    report = f"""# 🛡️ Heuristic Security Audit Report

**Repository**: {repo_name}
**Audit Date**: {datetime.utcnow().isoformat()}Z
**Audit Type**: Pattern-based Heuristic Analysis

---

## 📊 Executive Summary

| Metric | Count |
|--------|-------|
| **Files Scanned** | {results["total_files"]} |
| **Total Findings** | {results["total_findings"]} |
| **Critical Issues** | {len(critical)} 🔴 |
| **High Severity** | {len(high)} 🟠 |
| **Medium Severity** | {len(medium)} 🟡 |
| **Low Severity** | {len(low)} ⚪ |

---

## 🎯 Issue Breakdown

### By Type:
"""

    for issue_type, count in sorted(results["type_counts"].items(), key=lambda x: -x[1]):
        report += f"- **{issue_type.replace('-', ' ').title()}**: {count}\n"

    report += "\n---\n\n## 🔴 Critical Issues\n\n"

    if critical:
        for finding in critical[:10]:  # Top 10
            report += f"""### {finding["type"].replace("-", " ").title()}

**File**: `{finding["file"]}:{finding["line"]}`
**Severity**: CRITICAL 🔴

{finding["description"]}

---

"""
    else:
        report += "*No critical issues detected*\n\n"

    report += f"\n## 🟠 High Severity Issues ({len(high)})\n\n"

    for finding in high[:5]:
        report += f"- `{finding['file']}:{finding['line']}` - {finding['description']}\n"

    if len(high) > 5:
        report += f"\n*...and {len(high) - 5} more high severity issues*\n"

    report += "\n---\n\n## 📋 Files with Most Issues\n\n"

    file_counts = [(f, len(issues)) for f, issues in results["files_with_issues"].items()]
    file_counts.sort(key=lambda x: -x[1])

    for file, count in file_counts[:10]:
        report += f"- `{file}`: {count} issue(s)\n"

    report += """

---

## ⚠️ Limitations of Heuristic Analysis

This is a **pattern-based** security audit using regex and static analysis. It identifies potential vulnerabilities but may have:

- **False Positives**: Some flagged issues may not be exploitable in context
- **False Negatives**: Complex vulnerabilities requiring semantic understanding will be missed
- **No Context Awareness**: Cannot distinguish between dev/test vs production code

### 🚀 For Comprehensive Analysis:

Run the **AI-powered multi-agent audit** for:
- ✅ Context-aware analysis (dev vs prod)
- ✅ Semantic understanding of code flow
- ✅ Automated test case generation
- ✅ Category-specific reviews (security/performance/quality)
- ✅ Self-verifying findings (fewer false positives)
- ✅ Git context integration

**To run AI audit**:
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
python scripts/audit_spring_attack_surface.py
```

---

**🔍 This report was generated using lightweight heuristic scanning.**
**For production security decisions, combine with AI audit and manual review.**

"""

    return report


def main():
    """Main entry point"""
    print("🛡️  Spring Attack Surface - Heuristic Security Audit")
    print("=" * 70)
    print()

    repo_path = "/Users/waseem.ahmed/Repos/spring-attack-surface"
    repo_name = "spring-attack-surface"

    if not Path(repo_path).exists():
        print(f"❌ Repository not found: {repo_path}")
        return

    # Run audit
    auditor = HeuristicAuditor(repo_path)
    results = auditor.audit_repository(["**/*.py"])  # Python only for now

    # Generate report
    print("📝 Generating report...")
    report = generate_report(results, repo_name)

    # Save report
    output_dir = Path(repo_path) / "audit-results"
    output_dir.mkdir(exist_ok=True)

    heuristic_report_path = output_dir / "heuristic-audit-report.md"
    with open(heuristic_report_path, "w") as f:
        f.write(report)

    print(f"✅ Report saved: {heuristic_report_path}")
    print()

    # Summary
    critical = sum(1 for f in results["findings"] if f["severity"] == "CRITICAL")
    high = sum(1 for f in results["findings"] if f["severity"] == "HIGH")
    medium = sum(1 for f in results["findings"] if f["severity"] == "MEDIUM")

    print("📊 Summary:")
    print(f"  🔴 Critical: {critical}")
    print(f"  🟠 High: {high}")
    print(f"  🟡 Medium: {medium}")
    print(f"  📁 Total Files: {results['total_files']}")
    print()

    print("🎉 Heuristic audit complete!")
    print(f"📄 View report: {heuristic_report_path}")
    print()
    print("💡 For comprehensive AI-powered audit:")
    print("   export ANTHROPIC_API_KEY='your-key'")
    print("   python scripts/audit_spring_attack_surface.py")


if __name__ == "__main__":
    main()
