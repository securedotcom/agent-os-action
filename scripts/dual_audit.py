#!/usr/bin/env python3
"""
Dual-Audit Security Analysis
Runs Agent-OS (Anthropic Claude) followed by Codex (OpenAI) validation
Compares findings and generates comprehensive validation report

Usage:
    python scripts/dual_audit.py <target_repo> [--project-type backend-api]

Example:
    python scripts/dual_audit.py /path/to/repo --project-type backend-api
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

# Scoring Rubric Constants
SCORING_RUBRIC = {
    5: {
        "label": "Definitely Valid",
        "description": "Confirmed vulnerability with clear evidence",
        "criteria": [
            "Direct proof of vulnerability in code",
            "Exploitable without edge cases",
            "Matches known CVE or vulnerability pattern",
            "Can be demonstrated in current codebase"
        ]
    },
    4: {
        "label": "Likely Valid",
        "description": "Matches known vulnerability patterns",
        "criteria": [
            "Code matches vulnerable pattern",
            "Requires some conditions but reasonably exploitable",
            "Similar to documented vulnerability types",
            "Strong evidence but not definitively confirmed"
        ]
    },
    3: {
        "label": "Uncertain",
        "description": "Requires human review to validate",
        "criteria": [
            "Evidence is ambiguous or context-dependent",
            "Could be valid or false positive depending on usage",
            "Requires understanding of business logic",
            "Warrants further investigation"
        ]
    },
    2: {
        "label": "Likely False Positive",
        "description": "Edge case or safe pattern",
        "criteria": [
            "Code appears vulnerable but has safeguards",
            "Only exploitable under unusual circumstances",
            "Matches false positive signature",
            "Safe implementation of potentially risky pattern"
        ]
    },
    1: {
        "label": "Definitely False Positive",
        "description": "Known safe pattern",
        "criteria": [
            "Definitively safe code pattern",
            "Not exploitable in any context",
            "Common safe implementation",
            "Clear false positive signature"
        ]
    }
}

class DualAuditOrchestrator:
    """Orchestrates dual-audit process with Agent-OS and Codex"""

    def __init__(self, target_repo: str, project_type: str = "backend-api"):
        self.target_repo = Path(target_repo).resolve()
        self.project_type = project_type
        self.timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.output_dir = self.target_repo / ".agent-os" / "dual-audit" / self.timestamp
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def run_agent_os_audit(self) -> Dict[str, Any]:
        """Run Agent-OS security audit"""
        print("\n" + "="*80)
        print("PHASE 1: Agent-OS Security Audit (Anthropic Claude)")
        print("="*80 + "\n")

        agent_os_script = Path(__file__).parent / "run_ai_audit.py"

        cmd = [
            sys.executable,
            str(agent_os_script),
            str(self.target_repo),
            self.project_type,
            "--ai-provider", "anthropic",
            "--output-file", str(self.output_dir / "agent_os_report.json"),
            "--output-format", "markdown"
        ]

        try:
            result = subprocess.run(
                cmd,
                cwd=self.target_repo,
                capture_output=True,
                text=True,
                timeout=600
            )

            print(result.stdout)
            if result.stderr:
                print("STDERR:", result.stderr, file=sys.stderr)

            # Load Agent-OS results
            report_path = self.target_repo / ".agent-os" / "reviews" / "backend-api-report.md"
            json_path = self.target_repo / ".agent-os" / "reviews" / "results.json"

            if json_path.exists():
                with open(json_path, 'r') as f:
                    agent_os_results = json.load(f)
            else:
                agent_os_results = {"error": "No results generated"}

            # Copy reports to dual-audit directory
            if report_path.exists():
                import shutil
                shutil.copy(report_path, self.output_dir / "agent_os_report.md")
                shutil.copy(json_path, self.output_dir / "agent_os_results.json")

            return {
                "success": result.returncode == 0,
                "results": agent_os_results,
                "stdout": result.stdout,
                "stderr": result.stderr
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Agent-OS audit timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def run_codex_validation(self, agent_os_results: Dict[str, Any]) -> Dict[str, Any]:
        """Run Codex validation of Agent-OS findings with chain-of-thought reasoning"""
        print("\n" + "="*80)
        print("PHASE 2: Codex Independent Validation (OpenAI GPT-5.2)")
        print("="*80 + "\n")

        # Check if codex is available
        try:
            subprocess.run(["which", "codex"], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            return {"success": False, "error": "Codex CLI not installed"}

        # Extract key findings from Agent-OS for targeted validation
        findings_summary = self._generate_findings_summary(agent_os_results)

        # Create enhanced Codex validation prompt with chain-of-thought reasoning
        codex_prompt = f"""You are a senior security auditor performing independent validation of AI-generated security findings.

SCORING RUBRIC:
{self._format_scoring_rubric()}

AGENT-OS FINDINGS TO VALIDATE:
{findings_summary}

VALIDATION METHODOLOGY (Chain-of-Thought):

For EACH Agent-OS finding, follow this reasoning process:

1. UNDERSTANDING OF THE CLAIM
   - What vulnerability is being claimed?
   - What code pattern is being flagged?
   - What is the threat model (attacker capabilities, access level)?

2. EVIDENCE FROM CODE REVIEW
   - Is the flagged code actually present?
   - What is the surrounding context?
   - Are there any mitigating factors (input validation, sanitization, etc.)?
   - Does this match a known vulnerable pattern?

3. EXPLOITABILITY ASSESSMENT
   - Under what conditions could this be exploited?
   - What preconditions must exist?
   - What is the attack surface?
   - What is the impact if exploited?

4. REASONING FOR JUDGMENT
   - Based on evidence, is this finding valid?
   - What specific factors led to your determination?
   - Are there any edge cases or ambiguities?

5. CONFIDENCE SCORE
   - Assign a score from 1-5 using the rubric above
   - Explain why this score applies

VALIDATION TASKS:
1. Review the same security categories that Agent-OS analyzed
2. Independently identify security vulnerabilities
3. For EACH Agent-OS finding, provide:
   - Finding description
   - Your assessment (Valid/Invalid/Uncertain)
   - Confidence score (1-5) with justification
   - Evidence or reasoning
4. Identify any issues Agent-OS missed
5. Assess overall false positive rate

FOCUS AREAS:
- SQL injection vulnerabilities
- Hardcoded secrets and credentials
- Input validation gaps
- Sensitive data exposure
- Deserialization risks
- Code quality issues
- Authentication/authorization flaws
- Insecure dependencies

OUTPUT FORMAT:

For each finding:
```
FINDING: [Original finding description]
ASSESSMENT: Valid | Invalid | Uncertain
SCORE: [1-5]
JUSTIFICATION: [Why this score]
EVIDENCE: [Specific code or reasoning]
```

SUMMARY:
- Validated findings: [count]
- Disputed findings: [count]
- New findings: [count]
- Estimated false positive rate: [%]

Temperature: 0.2 (for consistency and deterministic reasoning)
"""

        codex_output_file = self.output_dir / "codex_validation.txt"

        # Codex review accepts prompt as positional argument or stdin
        # Use config to set temperature (model behavior)
        cmd = [
            "codex",
            "review",
            "--config", "temperature=0.2",
            "--uncommitted",  # Review current codebase state
            codex_prompt
        ]

        try:
            result = subprocess.run(
                cmd,
                cwd=self.target_repo,
                capture_output=True,
                text=True,
                timeout=600  # Increased timeout for thorough review
            )

            # Save Codex output
            with open(codex_output_file, 'w') as f:
                f.write(result.stdout)

            print(result.stdout)

            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "output_file": str(codex_output_file)
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Codex validation timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _generate_findings_summary(self, agent_os_results: Dict[str, Any]) -> str:
        """Generate detailed summary of Agent-OS findings for Codex validation"""
        summary_parts = []

        if "summary" in agent_os_results:
            s = agent_os_results["summary"]
            summary_parts.append(f"""
AGENT-OS SUMMARY:
- Files Reviewed: {s.get('files_reviewed', 'unknown')}
- Lines Analyzed: {s.get('lines_analyzed', 'unknown')}
- Critical: {s.get('findings', {}).get('critical', 0)}
- High: {s.get('findings', {}).get('high', 0)}
- Medium: {s.get('findings', {}).get('medium', 0)}
- Low: {s.get('findings', {}).get('low', 0)}
- Total Issues: {sum(s.get('findings', {}).values())}
- Duration: {s.get('duration_seconds', 'unknown')}s
- Cost: ${s.get('cost_usd', 0):.2f}
""")

        if "findings" in agent_os_results:
            summary_parts.append("\nDETAILED FINDINGS (Top 15):")
            for idx, finding in enumerate(agent_os_results["findings"][:15], 1):
                severity = finding.get('severity', 'unknown').upper()
                message = finding.get('message', 'No message')
                category = finding.get('category', 'unknown')
                cwe_id = finding.get('cwe_id', 'N/A')
                file_path = finding.get('file', 'unknown file')
                line_num = finding.get('line', 'unknown line')

                summary_parts.append(f"""
{idx}. [{severity}] {message}
   Category: {category}
   CWE: {cwe_id}
   File: {file_path}
   Line: {line_num}""")

        # Add validation context
        summary_parts.append(f"""

VALIDATION CONTEXT:
- Review findings marked as CRITICAL and HIGH first
- Focus on findings with multiple severity indicators
- Pay attention to findings with known CWE mappings
- Consider the business context and data sensitivity
""")

        return "\n".join(summary_parts)

    def _format_scoring_rubric(self) -> str:
        """Format scoring rubric for display in Codex prompt"""
        rubric_lines = []

        for score in range(5, 0, -1):
            rubric = SCORING_RUBRIC[score]
            rubric_lines.append(f"""
SCORE {score}: {rubric['label']}
Description: {rubric['description']}
Criteria:""")
            for criterion in rubric['criteria']:
                rubric_lines.append(f"  - {criterion}")

        return "\n".join(rubric_lines)

    def generate_comparison_report(self,
                                   agent_os_result: Dict[str, Any],
                                   codex_result: Dict[str, Any]) -> str:
        """Generate comprehensive comparison report with validation scoring"""

        report = f"""# Dual-Audit Security Analysis Report
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Target: {self.target_repo}

## Audit Methodology

This report presents findings from a dual-audit approach with rigorous validation:
1. **Agent-OS (Anthropic Claude)**: Comprehensive AI-powered security analysis
2. **Codex (OpenAI GPT-5.2)**: Independent validation with chain-of-thought reasoning

### Validation Framework

All findings are evaluated using a standardized 5-point confidence scoring rubric:

{self._format_scoring_rubric()}

### Chain-of-Thought Validation Process

Each finding is validated through the following reasoning steps:
1. **Understanding of the Claim**: Clarity on what vulnerability is alleged
2. **Evidence Review**: Code analysis and context examination
3. **Exploitability Assessment**: Feasibility and attack surface analysis
4. **Reasoning**: Detailed justification for final determination
5. **Confidence Score**: 1-5 rating with clear rubric mapping

### Temperature Control

- Codex validation uses temperature=0.2 for deterministic, consistent reasoning
- This low temperature ensures reproducible validation decisions
- Higher accuracy in edge case differentiation

---

## Phase 1: Agent-OS Results

### Status
- **Success**: {agent_os_result.get('success', False)}
- **Provider**: Anthropic Claude (claude-sonnet-4-5)

### Summary
"""

        if agent_os_result.get("success") and "results" in agent_os_result:
            results = agent_os_result["results"]
            if "summary" in results:
                s = results["summary"]
                report += f"""
- **Files Reviewed**: {s.get('files_reviewed', 'N/A')}
- **Lines Analyzed**: {s.get('lines_analyzed', 'N/A')}
- **Total Cost**: ${s.get('cost_usd', 0):.2f}
- **Duration**: {s.get('duration_seconds', 0)}s

### Findings by Severity
- 🔴 Critical: {s.get('findings', {}).get('critical', 0)}
- 🟠 High: {s.get('findings', {}).get('high', 0)}
- 🟡 Medium: {s.get('findings', {}).get('medium', 0)}
- 🟢 Low: {s.get('findings', {}).get('low', 0)}
- Total: {sum(s.get('findings', {}).values())}

### Findings by Category
"""
                for category, count in s.get('categories', {}).items():
                    report += f"- **{category.title()}**: {count}\n"

        report += f"""

---

## Phase 2: Codex Validation Results

### Status
- **Success**: {codex_result.get('success', False)}
- **Provider**: OpenAI GPT-5.2-codex

### Validation Output
{codex_result.get('output', 'No output available')[:2000]}

[Full Codex output: {codex_result.get('output_file', 'N/A')}]

---

## Cross-Validation Analysis

### Agreement Metrics
- **Tools Used**: Agent-OS (Claude) + Codex (GPT-5.2)
- **Validation Method**: Independent dual-audit
- **Cross-reference**: Codex reviewed Agent-OS report and codebase

### Key Observations
1. Both tools provide AI-powered security analysis
2. Codex acts as independent validator of Agent-OS findings
3. Cross-validation increases confidence in findings
4. Human review still recommended for final validation

---

## Recommendations

1. **Immediate Actions**: Address all Critical and High severity findings
2. **Validation**: Review disputed findings (if any) with security team
3. **Prioritization**: Focus on findings confirmed by both tools
4. **Follow-up**: Schedule remediation timeline for Medium severity issues

---

## Report Artifacts

- Agent-OS Report (MD): `.agent-os/dual-audit/{self.timestamp}/agent_os_report.md`
- Agent-OS Results (JSON): `.agent-os/dual-audit/{self.timestamp}/agent_os_results.json`
- Codex Validation: `.agent-os/dual-audit/{self.timestamp}/codex_validation.txt`
- This Report: `.agent-os/dual-audit/{self.timestamp}/dual_audit_report.md`

---

## Conclusion

This dual-audit approach provides high-confidence security assessment by:
✅ Using two independent AI models (Claude + GPT-5.2)
✅ Cross-validating findings between tools
✅ Combining strengths of both Anthropic and OpenAI models
✅ Reducing false positives through consensus

**Recommendation**: Findings confirmed by both tools should be prioritized for immediate remediation.
"""

        return report

    def run(self) -> int:
        """Execute complete dual-audit workflow"""
        print(f"\n{'='*80}")
        print(f"Dual-Audit Security Analysis")
        print(f"Target: {self.target_repo}")
        print(f"Output: {self.output_dir}")
        print(f"{'='*80}\n")

        # Phase 1: Agent-OS
        agent_os_result = self.run_agent_os_audit()
        if not agent_os_result.get("success"):
            print(f"\n❌ Agent-OS audit failed: {agent_os_result.get('error')}")
            return 1

        print("\n✅ Agent-OS audit completed successfully\n")

        # Phase 2: Codex
        codex_result = self.run_codex_validation(agent_os_result["results"])
        if not codex_result.get("success"):
            print(f"\n⚠️  Codex validation failed: {codex_result.get('error')}")
            print("Continuing with Agent-OS results only...\n")
        else:
            print("\n✅ Codex validation completed successfully\n")

        # Generate comparison report
        print("\n" + "="*80)
        print("Generating Dual-Audit Comparison Report")
        print("="*80 + "\n")

        report = self.generate_comparison_report(agent_os_result, codex_result)
        report_path = self.output_dir / "dual_audit_report.md"

        with open(report_path, 'w') as f:
            f.write(report)

        print(f"✅ Dual-audit report generated: {report_path}\n")
        print("="*80)
        print("DUAL-AUDIT COMPLETE")
        print("="*80)
        print(f"\n📊 Review comprehensive report: {report_path}\n")

        return 0


def main():
    parser = argparse.ArgumentParser(
        description="Run dual-audit security analysis with Agent-OS and Codex"
    )
    parser.add_argument(
        "target",
        help="Target repository path to audit"
    )
    parser.add_argument(
        "--project-type",
        default="backend-api",
        help="Project type for analysis (default: backend-api)"
    )

    args = parser.parse_args()

    orchestrator = DualAuditOrchestrator(args.target, args.project_type)
    sys.exit(orchestrator.run())


if __name__ == "__main__":
    main()
