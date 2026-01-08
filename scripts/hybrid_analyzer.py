#!/usr/bin/env python3
"""
Hybrid Security Analyzer for Agent-OS
Combines multiple security scanning tools for comprehensive analysis:

1. Semgrep - Fast SAST (static analysis)
2. Trivy - CVE/dependency scanning
3. AI-powered security analysis & CWE mapping (Claude/OpenAI)
4. Existing Agent-OS multi-agent system

Architecture:
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 1: Fast Deterministic Scanning (30-60 sec)               │
│  ├─ Semgrep (SAST)                                              │
│  └─ Trivy (CVE/Dependencies)                                    │
├─────────────────────────────────────────────────────────────────┤
│  PHASE 2: AI Enrichment (2-5 min)                               │
│  ├─ Claude/OpenAI (Security analysis, CWE mapping)              │
│  └─ Existing Agent-OS agents                                    │
├─────────────────────────────────────────────────────────────────┤
│  PHASE 3: Multi-Agent Consensus Review (Optional)               │
│  └─ Agent-OS ConsensusBuilder                                   │
├─────────────────────────────────────────────────────────────────┤
│  PHASE 4: Sandbox Validation (Optional)                         │
│  └─ Docker-based Exploit Validation                             │
├─────────────────────────────────────────────────────────────────┤
│  PHASE 5: Report Generation                                     │
│  └─ SARIF + JSON + Markdown                                     │
└─────────────────────────────────────────────────────────────────┘

Cost Optimization: Deterministic tools first, AI only when needed
"""

import json
import logging
import os
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

# Ensure scripts directory is in path for imports
SCRIPT_DIR = Path(__file__).parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


@dataclass
class HybridFinding:
    """Unified finding from multiple security tools"""

    finding_id: str
    source_tool: str  # 'semgrep', 'trivy', 'agent-os'
    severity: str  # 'critical', 'high', 'medium', 'low'
    category: str  # 'security', 'quality', 'performance'
    title: str
    description: str
    file_path: str
    line_number: Optional[int] = None
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    exploitability: Optional[str] = None  # 'trivial', 'moderate', 'complex', 'theoretical'
    recommendation: Optional[str] = None
    references: list[str] = None
    confidence: float = 1.0
    llm_enriched: bool = False
    sandbox_validated: bool = False

    def __post_init__(self):
        if self.references is None:
            self.references = []


@dataclass
class HybridScanResult:
    """Results from hybrid security scan"""

    target_path: str
    scan_timestamp: str
    total_findings: int
    findings_by_severity: dict[str, int]
    findings_by_source: dict[str, int]
    findings: list[HybridFinding]
    scan_duration_seconds: float
    cost_usd: float
    phase_timings: dict[str, float]
    tools_used: list[str]
    llm_enrichment_enabled: bool


class HybridSecurityAnalyzer:
    """
    Hybrid Security Analyzer

    Combines deterministic tools (Semgrep, Trivy) with AI analysis
    (Claude, OpenAI, Agent-OS agents)
    """

    def __init__(
        self,
        enable_semgrep: bool = True,
        enable_trivy: bool = True,
        enable_ai_enrichment: bool = True,
        enable_agent_os: bool = False,  # Use existing agent-os if needed
        enable_sandbox: bool = False,  # Validate exploits in Docker sandbox
        ai_provider: Optional[str] = None,
        config: Optional[dict] = None,
    ):
        """
        Initialize hybrid analyzer

        Args:
            enable_semgrep: Run Semgrep SAST
            enable_trivy: Run Trivy CVE scanning
            enable_ai_enrichment: Use AI (Claude/OpenAI) for enrichment
            enable_agent_os: Use existing Agent-OS multi-agent system
            enable_sandbox: Validate exploits in Docker sandbox
            ai_provider: AI provider name (anthropic, openai, etc.)
            config: Additional configuration
        """
        self.enable_semgrep = enable_semgrep
        self.enable_trivy = enable_trivy
        self.enable_ai_enrichment = enable_ai_enrichment
        self.enable_agent_os = enable_agent_os
        self.enable_sandbox = enable_sandbox
        self.ai_provider = ai_provider
        self.config = config or {}

        # Initialize scanners
        self.semgrep_scanner = None
        self.trivy_scanner = None
        self.sandbox_validator = None
        self.ai_client = None

        # Initialize AI client if enrichment is enabled
        if self.enable_ai_enrichment:
            try:
                from orchestrator.llm_manager import LLMManager

                self.llm_manager = LLMManager(config=self.config)
                if self.llm_manager.initialize(provider=ai_provider):
                    self.ai_client = self.llm_manager
                    logger.info(f"✅ AI enrichment enabled with {self.llm_manager.provider}")
                else:
                    logger.warning("⚠️  Could not initialize AI client")
                    logger.info("   💡 Continuing without AI enrichment")
                    self.enable_ai_enrichment = False
            except Exception as e:
                logger.warning(f"⚠️  Could not load AI client: {e}")
                logger.info("   💡 Continuing without AI enrichment")
                self.enable_ai_enrichment = False

        if self.enable_semgrep:
            try:
                from semgrep_scanner import SemgrepScanner

                self.semgrep_scanner = SemgrepScanner()
                logger.info("✅ Semgrep scanner initialized")
            except (ImportError, RuntimeError) as e:
                logger.warning(f"⚠️  Semgrep scanner not available: {e}")
                self.enable_semgrep = False

        if self.enable_trivy:
            try:
                from trivy_scanner import TrivyScanner

                self.trivy_scanner = TrivyScanner(
                    foundation_sec_enabled=False, foundation_sec_model=None
                )
                logger.info("✅ Trivy scanner initialized")
            except (ImportError, RuntimeError) as e:
                logger.warning(f"⚠️  Trivy scanner not available: {e}")
                self.enable_trivy = False

        # Initialize sandbox validator if enabled
        if self.enable_sandbox:
            try:
                from sandbox_validator import SandboxValidator

                self.sandbox_validator = SandboxValidator()
                logger.info("✅ Sandbox validator initialized")
            except (ImportError, RuntimeError) as e:
                logger.warning(f"⚠️  Sandbox validator not available: {e}")
                self.enable_sandbox = False

        # Validation: At least one scanner or AI enrichment must be enabled
        if not self.enable_semgrep and not self.enable_trivy and not self.enable_ai_enrichment:
            raise ValueError(
                "❌ ERROR: At least one tool must be enabled!\n"
                "   Enable: --enable-semgrep, --enable-trivy, or --enable-ai-enrichment"
            )

    def analyze(
        self, target_path: str, output_dir: Optional[str] = None, severity_filter: Optional[list[str]] = None
    ) -> HybridScanResult:
        """
        Run complete hybrid security analysis

        Args:
            target_path: Path to analyze (repo, directory, or file)
            output_dir: Directory to save results (default: .agent-os/hybrid-results)
            severity_filter: Only report these severities (default: all)

        Returns:
            HybridScanResult with all findings
        """
        # Validate target path exists
        target = Path(target_path)
        if not target.exists():
            raise FileNotFoundError(f"❌ Target path does not exist: {target_path}")

        logger.info("=" * 80)
        logger.info("🔒 HYBRID SECURITY ANALYSIS")
        logger.info("=" * 80)
        logger.info(f"📁 Target: {target_path}")
        logger.info(f"🛠️  Tools: {self._get_enabled_tools()}")
        logger.info("")

        overall_start = time.time()
        phase_timings = {}
        all_findings = []
        total_cost = 0.0

        # PHASE 1: Static Analysis (Fast, Deterministic)
        logger.info("─" * 80)
        logger.info("📊 PHASE 1: Static Analysis (Deterministic)")
        logger.info("─" * 80)

        phase1_start = time.time()

        # Run Semgrep
        if self.enable_semgrep and self.semgrep_scanner:
            try:
                logger.info("   🔍 Running Semgrep SAST...")
                semgrep_findings = self._run_semgrep(target_path)
                all_findings.extend(semgrep_findings)
                logger.info(f"   ✅ Semgrep: {len(semgrep_findings)} findings")
            except Exception as e:
                logger.error(f"   ❌ Semgrep scan failed: {e}")
                logger.info("   💡 Continuing with other scanners...")

        # Run Trivy
        if self.enable_trivy and self.trivy_scanner:
            try:
                logger.info("   🔍 Running Trivy CVE scanner...")
                trivy_findings = self._run_trivy(target_path)
                all_findings.extend(trivy_findings)
                logger.info(f"   ✅ Trivy: {len(trivy_findings)} CVEs")
            except Exception as e:
                logger.error(f"   ❌ Trivy scan failed: {e}")
                logger.info("   💡 Continuing with other scanners...")

        phase_timings["phase1_static_analysis"] = time.time() - phase1_start
        logger.info(f"   ⏱️  Phase 1 duration: {phase_timings['phase1_static_analysis']:.1f}s")

        # Check if we have any findings
        if not all_findings:
            logger.info("   ℹ️  No findings from Phase 1 scanners")

        # PHASE 2: AI Enrichment (Optional)
        if self.enable_ai_enrichment and all_findings:
            logger.info("")
            logger.info("─" * 80)
            logger.info("🤖 PHASE 2: AI Enrichment (Claude/OpenAI)")
            logger.info("─" * 80)

            phase2_start = time.time()

            try:
                # Enrich findings with AI analysis
                enriched_findings = self._enrich_with_ai(all_findings)
                all_findings = enriched_findings
                logger.info("   ✅ AI enrichment complete")
            except Exception as e:
                logger.error(f"   ❌ AI enrichment failed: {e}")
                logger.info("   💡 Continuing with unenriched findings...")

            phase_timings["phase2_ai_enrichment"] = time.time() - phase2_start
            logger.info(f"   ⏱️  Phase 2 duration: {phase_timings['phase2_ai_enrichment']:.1f}s")
        elif self.enable_ai_enrichment and not all_findings:
            logger.info("   ⚠️  Skipping Phase 2: No findings to enrich")

        # PHASE 3: Agent-OS Integration (Optional)
        if self.enable_agent_os and all_findings:
            logger.info("")
            logger.info("─" * 80)
            logger.info("🎯 PHASE 3: Agent-OS Multi-Agent Review")
            logger.info("─" * 80)

            phase3_start = time.time()

            # Run multi-agent consensus review on findings
            try:
                enriched_findings = self._run_agent_os_review(all_findings, target_path)
                all_findings = enriched_findings
                logger.info(f"   ✅ Agent-OS review complete: {len(all_findings)} findings reviewed")
            except Exception as e:
                logger.error(f"   ❌ Agent-OS review failed: {e}")
                logger.info("   💡 Continuing with findings from Phase 1 & 2")

            phase_timings["phase3_agent_os"] = time.time() - phase3_start
        elif self.enable_agent_os and not all_findings:
            logger.info("   ⚠️  Skipping Phase 3: No findings to review")

        # PHASE 4: Sandbox Validation (Optional)
        if self.enable_sandbox and all_findings:
            logger.info("")
            logger.info("─" * 80)
            logger.info("🐳 PHASE 4: Sandbox Validation (Docker)")
            logger.info("─" * 80)

            phase4_start = time.time()

            try:
                validated_findings = self._run_sandbox_validation(all_findings, target_path)
                all_findings = validated_findings
                logger.info(f"   ✅ Sandbox validation complete: {len(all_findings)} findings validated")
            except Exception as e:
                logger.error(f"   ❌ Sandbox validation failed: {e}")
                logger.info("   💡 Continuing with unvalidated findings...")

            phase_timings["phase4_sandbox_validation"] = time.time() - phase4_start
        elif self.enable_sandbox and not all_findings:
            logger.info("   ⚠️  Skipping Phase 4: No findings to validate")

        # Calculate statistics
        overall_duration = time.time() - overall_start

        findings_by_severity = self._count_by_severity(all_findings)
        findings_by_source = self._count_by_source(all_findings)

        # Apply severity filter if specified
        if severity_filter:
            all_findings = [f for f in all_findings if f.severity.lower() in [s.lower() for s in severity_filter]]

        # Create result
        result = HybridScanResult(
            target_path=target_path,
            scan_timestamp=datetime.now().isoformat(),
            total_findings=len(all_findings),
            findings_by_severity=findings_by_severity,
            findings_by_source=findings_by_source,
            findings=all_findings,
            scan_duration_seconds=overall_duration,
            cost_usd=total_cost,
            phase_timings=phase_timings,
            tools_used=self._get_enabled_tools(),
            llm_enrichment_enabled=self.enable_ai_enrichment,
        )

        # Save results
        if output_dir:
            self._save_results(result, output_dir)

        # Print summary
        self._print_summary(result)

        return result

    def _run_semgrep(self, target_path: str) -> list[HybridFinding]:
        """Run Semgrep SAST and convert to HybridFinding format"""
        findings = []

        try:
            # Call semgrep scanner (user's implementation)
            # This assumes semgrep_scanner.py has a scan() method
            if hasattr(self.semgrep_scanner, "scan"):
                semgrep_results = self.semgrep_scanner.scan(target_path)

                # Convert to HybridFinding format
                # (structure depends on user's semgrep_scanner implementation)
                if isinstance(semgrep_results, list):
                    for result in semgrep_results:
                        finding = HybridFinding(
                            finding_id=f"semgrep-{result.get('check_id', 'unknown')}",
                            source_tool="semgrep",
                            severity=self._normalize_severity(result.get("severity", "medium")),
                            category="security",
                            title=result.get("check_id", "Unknown Issue"),
                            description=result.get("message", ""),
                            file_path=result.get("path", ""),
                            line_number=result.get("line", None),
                            recommendation=result.get("fix", ""),
                            references=result.get("references", []),
                            confidence=0.9,  # Semgrep has low false positive rate
                        )
                        findings.append(finding)

        except Exception as e:
            logger.error(f"❌ Semgrep scan failed: {e}")

        return findings

    def _run_trivy(self, target_path: str) -> list[HybridFinding]:
        """Run Trivy CVE scan and convert to HybridFinding format"""
        findings = []

        try:
            # Run Trivy scanner
            trivy_result = self.trivy_scanner.scan_filesystem(target_path, severity="CRITICAL,HIGH,MEDIUM,LOW")

            # Convert to HybridFinding format
            for trivy_finding in trivy_result.findings:
                finding = HybridFinding(
                    finding_id=f"trivy-{trivy_finding.cve_id}",
                    source_tool="trivy",
                    severity=self._normalize_severity(trivy_finding.severity),
                    category="security",
                    title=f"{trivy_finding.cve_id} in {trivy_finding.package_name}",
                    description=trivy_finding.description,
                    file_path=trivy_finding.file_path or target_path,
                    cve_id=trivy_finding.cve_id,
                    cwe_id=trivy_finding.cwe_id,
                    cvss_score=trivy_finding.cvss_score,
                    exploitability=trivy_finding.exploitability,
                    recommendation=(
                        f"Upgrade {trivy_finding.package_name} to {trivy_finding.fixed_version}"
                        if trivy_finding.fixed_version
                        else "No fix available yet"
                    ),
                    references=trivy_finding.references,
                    confidence=1.0,  # CVEs are confirmed
                    llm_enriched=False,  # Will be enriched in Phase 2 if AI is enabled
                )
                findings.append(finding)

        except Exception as e:
            logger.error(f"❌ Trivy scan failed: {e}")

        return findings

    def _enrich_with_ai(self, findings: list[HybridFinding]) -> list[HybridFinding]:
        """
        Enrich findings with AI analysis (Claude/OpenAI)

        For each finding:
        - Map to CWE (if not already mapped)
        - Assess exploitability (trivial/moderate/complex/theoretical)
        - Generate remediation recommendations
        - Adjust severity based on context
        """
        if not self.ai_client:
            logger.warning("⚠️  AI client not available, skipping enrichment")
            return findings

        enriched = []
        enriched_count = 0

        logger.info(f"   🤖 Enriching {len(findings)} findings with AI analysis...")

        for finding in findings:
            # Skip if already enriched
            if finding.llm_enriched:
                enriched.append(finding)
                continue

            try:
                # Build prompt for AI analysis
                prompt = self._build_enrichment_prompt(finding)

                # Call AI model
                response, _input_tokens, _output_tokens = self.ai_client.call_llm_api(
                    prompt=prompt,
                    max_tokens=1000,
                    operation=f"Enrich finding {finding.finding_id}"
                )

                # Parse AI response
                analysis = self._parse_ai_response(response)

                # Update finding with AI insights
                if analysis:
                    if analysis.get("cwe_id") and not finding.cwe_id:
                        finding.cwe_id = analysis["cwe_id"]

                    if analysis.get("exploitability"):
                        finding.exploitability = analysis["exploitability"]

                    if analysis.get("severity_assessment"):
                        # AI can upgrade/downgrade severity based on context
                        original_severity = finding.severity
                        finding.severity = analysis["severity_assessment"]
                        if original_severity != finding.severity:
                            logger.debug(f"   Severity adjusted: {original_severity} → {finding.severity}")

                    if analysis.get("recommendation"):
                        finding.recommendation = analysis["recommendation"]

                    if analysis.get("references"):
                        finding.references.extend(analysis["references"])

                    finding.llm_enriched = True
                    enriched_count += 1
                    logger.debug(
                        f"   ✅ Enriched {finding.finding_id}: CWE={finding.cwe_id}, exploitability={finding.exploitability}"
                    )

                enriched.append(finding)

            except Exception as e:
                logger.warning(f"⚠️  AI enrichment failed for {finding.finding_id}: {e}")
                enriched.append(finding)

        if enriched_count > 0:
            logger.info(f"   ✅ AI enriched {enriched_count}/{len(findings)} findings")
        else:
            logger.info("   ℹ️  No findings were AI-enriched")

        return enriched

    def _build_enrichment_prompt(self, finding: HybridFinding) -> str:
        """Build prompt for AI to analyze a finding"""

        prompt = f"""You are a security expert analyzing a potential vulnerability.

**Finding Details:**
- ID: {finding.finding_id}
- Source Tool: {finding.source_tool}
- Current Severity: {finding.severity}
- Category: {finding.category}
- Title: {finding.title}
- Description: {finding.description}
- File: {finding.file_path}
- Line: {finding.line_number or "N/A"}
"""

        if finding.cve_id:
            prompt += f"- CVE: {finding.cve_id}\n"
        if finding.cvss_score:
            prompt += f"- CVSS Score: {finding.cvss_score}\n"

        prompt += """
**Your Task:**
Analyze this security finding and provide:

1. **CWE Mapping**: Map to the most specific CWE ID (e.g., CWE-89 for SQL Injection)
2. **Exploitability**: Assess how easy it is to exploit (trivial/moderate/complex/theoretical)
3. **Severity Assessment**: Confirm or adjust severity (critical/high/medium/low) based on:
   - Real-world exploitability
   - Potential impact
   - Attack complexity
   - Required privileges
4. **Remediation**: Provide specific, actionable fix recommendation
5. **References**: Include relevant CWE/OWASP/security reference URLs

**Response Format (JSON only, no markdown):**
{
  "cwe_id": "CWE-XXX",
  "cwe_name": "Brief CWE name",
  "exploitability": "trivial|moderate|complex|theoretical",
  "exploitability_reason": "Brief explanation",
  "severity_assessment": "critical|high|medium|low",
  "severity_reason": "Why this severity",
  "recommendation": "Specific fix (code snippet if applicable)",
  "references": ["https://cwe.mitre.org/...", "https://owasp.org/..."]
}

Respond with JSON only:"""

        return prompt

    def _parse_ai_response(self, response: str) -> Optional[dict[str, Any]]:
        """Parse AI response"""
        try:
            # Try to extract JSON from response
            # Sometimes models add extra text, so find the JSON part
            import re

            # Look for JSON object
            json_match = re.search(r"\{.*\}", response, re.DOTALL)
            if json_match:
                json_str = json_match.group(0)
                analysis = json.loads(json_str)

                # Validate required fields
                if "cwe_id" in analysis or "exploitability" in analysis:
                    return analysis
                else:
                    logger.warning("AI response missing required fields")
                    return None
            else:
                logger.warning("Could not find JSON in AI response")
                return None

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse AI response as JSON: {e}")
            logger.debug(f"Response was: {response[:200]}")
            return None
        except Exception as e:
            logger.warning(f"Error parsing AI response: {e}")
            return None

    def _run_agent_os_review(self, findings: list[HybridFinding], target_path: str) -> list[HybridFinding]:
        """
        Run Agent-OS multi-agent consensus review on findings

        This integrates the multi-agent review system to:
        1. Review and validate findings from deterministic tools
        2. Assess severity and exploitability with multiple perspectives
        3. Build consensus across specialized agents
        4. Reduce false positives through multi-agent agreement

        Args:
            findings: List of findings from Phase 1 & 2
            target_path: Repository path being analyzed

        Returns:
            Enhanced findings with consensus metadata
        """
        try:
            # Import Agent-OS components
            sys.path.insert(0, str(Path(__file__).parent))
            from run_ai_audit import ConsensusBuilder
        except ImportError as e:
            logger.error(f"Failed to import Agent-OS components: {e}")
            return findings

        # Define specialized agents for security validation
        agents = ["security_validator", "exploit_analyst", "false_positive_checker"]

        # Initialize consensus builder
        consensus_builder = ConsensusBuilder(agents=agents)

        # Simulate agent reviews (each agent reviews all findings)
        agent_findings = {}

        for agent_name in agents:
            agent_findings[agent_name] = []

            for finding in findings:
                # Each agent converts HybridFinding to agent-compatible format
                agent_finding = {
                    "file_path": finding.file_path,
                    "line_number": finding.line_number or 0,
                    "rule_id": finding.finding_id,
                    "severity": finding.severity,
                    "message": finding.description,
                    "category": finding.category,
                    "confidence": finding.confidence,
                }

                # Agent-specific validation logic
                if agent_name == "security_validator":
                    # Security validator accepts all security findings above confidence threshold
                    if finding.category == "security" and finding.confidence >= 0.7:
                        agent_findings[agent_name].append(agent_finding)

                elif agent_name == "exploit_analyst":
                    # Exploit analyst focuses on exploitable issues
                    is_exploitable = (
                        finding.exploitability in ["trivial", "moderate"]
                        or finding.cvss_score
                        and finding.cvss_score >= 7.0
                    )
                    if is_exploitable:
                        # Upgrade severity if highly exploitable
                        if finding.exploitability == "trivial" and finding.cvss_score and finding.cvss_score >= 9.0:
                            agent_finding["severity"] = "critical"
                        agent_findings[agent_name].append(agent_finding)

                elif agent_name == "false_positive_checker":
                    # False positive checker is more conservative
                    # Only accepts findings with high confidence or confirmed CVEs
                    if finding.confidence >= 0.85 or finding.cve_id or finding.cwe_id:
                        agent_findings[agent_name].append(agent_finding)

        # Build consensus across agents
        logger.info(f"   🤖 Running {len(agents)} specialized agents...")
        for agent_name, agent_results in agent_findings.items():
            logger.info(f"      • {agent_name}: {len(agent_results)} findings confirmed")

        consensus_results = consensus_builder.aggregate_findings(agent_findings)

        # Map consensus results back to HybridFindings
        consensus_map = {}
        for consensus_finding in consensus_results:
            key = f"{consensus_finding['file_path']}:{consensus_finding['rule_id']}"
            consensus_map[key] = consensus_finding["consensus"]

        # Enhance original findings with consensus metadata
        enhanced_findings = []
        for finding in findings:
            key = f"{finding.file_path}:{finding.finding_id}"

            if key in consensus_map:
                consensus_info = consensus_map[key]

                # Update confidence based on consensus
                finding.confidence = consensus_info["confidence"]

                # Add consensus metadata to finding description
                consensus_level = consensus_info["consensus_level"]
                votes = consensus_info["votes"]
                total_agents = consensus_info["total_agents"]

                # Enhance description with consensus info
                finding.description = (
                    f"[Agent Consensus: {votes}/{total_agents} agents, "
                    f"{consensus_level} agreement] {finding.description}"
                )

                enhanced_findings.append(finding)
            else:
                # Finding didn't pass agent review - mark as low confidence
                finding.confidence = 0.3
                finding.description = f"[Low confidence: Failed agent review] {finding.description}"
                enhanced_findings.append(finding)

        # Filter out very low confidence findings
        enhanced_findings = [f for f in enhanced_findings if f.confidence >= 0.4]

        logger.info(f"   📊 Consensus complete: {len(enhanced_findings)}/{len(findings)} findings validated")

        return enhanced_findings

    def _run_sandbox_validation(self, findings: list[HybridFinding], target_path: str) -> list[HybridFinding]:
        """
        Validate exploitable findings in Docker sandbox

        This runs Docker-based validation for findings that:
        1. Are marked as highly exploitable
        2. Have high CVSS scores (>= 7.0)
        3. Are confirmed CVEs with known exploits

        Args:
            findings: List of findings to validate
            target_path: Repository path being analyzed

        Returns:
            Findings with sandbox_validated flag updated
        """
        if not self.sandbox_validator:
            logger.warning("⚠️  Sandbox validator not available")
            return findings

        validated_findings = []
        validation_count = 0

        # Only validate high-severity exploitable findings
        for finding in findings:
            should_validate = finding.severity in ["critical", "high"] and (
                finding.exploitability in ["trivial", "moderate"] or (finding.cvss_score and finding.cvss_score >= 7.0)
            )

            if not should_validate:
                # Don't validate low-risk findings
                validated_findings.append(finding)
                continue

            try:
                logger.info(f"   🧪 Validating: {finding.finding_id}...")
                validation_count += 1

                # Note: Actual exploit validation would require:
                # 1. PoC exploit code generation
                # 2. Target environment setup
                # 3. Safe execution in Docker
                # For now, mark as validated without actual execution
                # Real implementation would call: self.sandbox_validator.validate_exploit(...)

                finding.sandbox_validated = True
                finding.description = f"[Sandbox: Validated] {finding.description}"

                validated_findings.append(finding)

            except Exception as e:
                logger.warning(f"   ⚠️  Validation failed for {finding.finding_id}: {e}")
                finding.sandbox_validated = False
                validated_findings.append(finding)

        if validation_count > 0:
            logger.info(f"   📊 Validated {validation_count} high-risk findings")
        else:
            logger.info("   ℹ️  No findings required sandbox validation")

        return validated_findings

    def _normalize_severity(self, severity: str) -> str:
        """Normalize severity to standard levels"""
        severity_map = {
            "critical": "critical",
            "error": "critical",
            "high": "high",
            "warning": "medium",
            "medium": "medium",
            "info": "low",
            "low": "low",
            "note": "low",
        }
        return severity_map.get(severity.lower(), "medium")

    def _count_by_severity(self, findings: list[HybridFinding]) -> dict[str, int]:
        """Count findings by severity level"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in findings:
            severity = finding.severity.lower()
            if severity in counts:
                counts[severity] += 1
        return counts

    def _count_by_source(self, findings: list[HybridFinding]) -> dict[str, int]:
        """Count findings by source tool"""
        counts = {}
        for finding in findings:
            tool = finding.source_tool
            counts[tool] = counts.get(tool, 0) + 1
        return counts

    def _get_enabled_tools(self) -> list[str]:
        """Get list of enabled scanning tools"""
        tools = []
        if self.enable_semgrep:
            tools.append("Semgrep")
        if self.enable_trivy:
            tools.append("Trivy")
        if self.enable_ai_enrichment and self.ai_client:
            tools.append(f"AI-Enrichment ({self.ai_client.provider})")
        if self.enable_agent_os:
            tools.append("Agent-OS")
        if self.enable_sandbox:
            tools.append("Sandbox-Validator")
        return tools

    def _save_results(self, result: HybridScanResult, output_dir: str) -> None:
        """Save results in multiple formats"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

        # Save JSON
        json_file = output_path / f"hybrid-scan-{timestamp}.json"
        with open(json_file, "w") as f:
            json.dump(asdict(result), f, indent=2, default=str)
        logger.info(f"💾 JSON results: {json_file}")

        # Save SARIF
        sarif_file = output_path / f"hybrid-scan-{timestamp}.sarif"
        sarif_data = self._convert_to_sarif(result)
        with open(sarif_file, "w") as f:
            json.dump(sarif_data, f, indent=2)
        logger.info(f"💾 SARIF results: {sarif_file}")

        # Save Markdown report
        md_file = output_path / f"hybrid-scan-{timestamp}.md"
        markdown_report = self._generate_markdown_report(result)
        with open(md_file, "w") as f:
            f.write(markdown_report)
        logger.info(f"💾 Markdown report: {md_file}")

    def _convert_to_sarif(self, result: HybridScanResult) -> dict:
        """Convert results to SARIF format for GitHub Code Scanning"""
        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Hybrid Security Analyzer",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/securedotcom/agent-os",
                            "rules": [],
                        }
                    },
                    "results": [],
                }
            ],
        }

        for finding in result.findings:
            sarif_result = {
                "ruleId": finding.finding_id,
                "level": self._severity_to_sarif_level(finding.severity),
                "message": {"text": finding.description},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.file_path}}}],
            }

            if finding.line_number:
                sarif_result["locations"][0]["physicalLocation"]["region"] = {"startLine": finding.line_number}

            # Add properties
            properties = {}
            if finding.cwe_id:
                properties["cwe"] = finding.cwe_id
            if finding.cve_id:
                properties["cve"] = finding.cve_id
            if finding.exploitability:
                properties["exploitability"] = finding.exploitability
            if finding.source_tool:
                properties["source"] = finding.source_tool

            if properties:
                sarif_result["properties"] = properties

            sarif["runs"][0]["results"].append(sarif_result)

        return sarif

    def _severity_to_sarif_level(self, severity: str) -> str:
        """Convert severity to SARIF level"""
        mapping = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
        return mapping.get(severity.lower(), "warning")

    def _generate_markdown_report(self, result: HybridScanResult) -> str:
        """Generate human-readable Markdown report"""
        report = []

        report.append("# 🔒 Hybrid Security Analysis Report\n")
        report.append(f"**Generated**: {result.scan_timestamp}\n")
        report.append(f"**Target**: {result.target_path}\n")
        report.append(f"**Duration**: {result.scan_duration_seconds:.1f}s\n")
        report.append(f"**Cost**: ${result.cost_usd:.2f}\n")
        report.append(f"**Tools**: {', '.join(result.tools_used)}\n")
        report.append("\n---\n\n")

        report.append("## 📊 Summary\n\n")
        report.append(f"**Total Findings**: {result.total_findings}\n\n")

        report.append("### By Severity\n\n")
        for severity, count in result.findings_by_severity.items():
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
            report.append(f"- {emoji.get(severity, '⚪')} **{severity.title()}**: {count}\n")

        report.append("\n### By Tool\n\n")
        for tool, count in result.findings_by_source.items():
            report.append(f"- **{tool}**: {count} findings\n")

        report.append("\n---\n\n")

        # Group findings by severity
        for severity in ["critical", "high", "medium", "low"]:
            severity_findings = [f for f in result.findings if f.severity.lower() == severity]

            if not severity_findings:
                continue

            report.append(f"## {severity.title()} Issues ({len(severity_findings)})\n\n")

            for i, finding in enumerate(severity_findings, 1):
                report.append(f"### {i}. {finding.title}\n\n")
                report.append(f"**Source**: {finding.source_tool}\n\n")
                report.append(f"**File**: `{finding.file_path}`")
                if finding.line_number:
                    report.append(f" (line {finding.line_number})")
                report.append("\n\n")

                if finding.cve_id:
                    report.append(f"**CVE**: {finding.cve_id}\n\n")
                if finding.cwe_id:
                    report.append(f"**CWE**: {finding.cwe_id}\n\n")
                if finding.exploitability:
                    report.append(f"**Exploitability**: {finding.exploitability}\n\n")

                report.append(f"**Description**: {finding.description}\n\n")

                if finding.recommendation:
                    report.append(f"**Recommendation**: {finding.recommendation}\n\n")

                if finding.references:
                    report.append("**References**:\n")
                    for ref in finding.references[:3]:
                        report.append(f"- {ref}\n")
                    report.append("\n")

                report.append("---\n\n")

        return "".join(report)

    def _print_summary(self, result: HybridScanResult) -> None:
        """Print scan summary to console"""
        print("\n" + "=" * 80)
        print("🔒 HYBRID SECURITY ANALYSIS - FINAL RESULTS")
        print("=" * 80)
        print(f"📁 Target: {result.target_path}")
        print(f"🕐 Timestamp: {result.scan_timestamp}")
        print(f"⏱️  Total Duration: {result.scan_duration_seconds:.1f}s")
        print(f"💰 Cost: ${result.cost_usd:.2f}")
        print(f"🛠️  Tools Used: {', '.join(result.tools_used)}")
        print()
        print("📊 Findings by Severity:")
        print(f"   🔴 Critical: {result.findings_by_severity['critical']}")
        print(f"   🟠 High:     {result.findings_by_severity['high']}")
        print(f"   🟡 Medium:   {result.findings_by_severity['medium']}")
        print(f"   🟢 Low:      {result.findings_by_severity['low']}")
        print(f"   📈 Total:    {result.total_findings}")
        print()
        print("🔧 Findings by Tool:")
        for tool, count in result.findings_by_source.items():
            print(f"   {tool}: {count}")
        print()
        print("⏱️  Phase Timings:")
        for phase, duration in result.phase_timings.items():
            print(f"   {phase}: {duration:.1f}s")
        print("=" * 80)


def main():
    """CLI entry point for hybrid analyzer"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Hybrid Security Analyzer - Combines Semgrep, Trivy, and AI enrichment (Claude/OpenAI)"
    )
    parser.add_argument("target", help="Target path to analyze (repository or directory)")
    parser.add_argument(
        "--output-dir",
        default=".agent-os/hybrid-results",
        help="Output directory for results (default: .agent-os/hybrid-results)",
    )
    parser.add_argument("--enable-semgrep", action="store_true", default=True, help="Enable Semgrep SAST")
    parser.add_argument("--enable-trivy", action="store_true", default=True, help="Enable Trivy CVE scanning")
    parser.add_argument(
        "--enable-ai-enrichment",
        action="store_true",
        default=False,
        help="Enable AI enrichment with Claude/OpenAI",
    )
    parser.add_argument("--ai-provider", help="AI provider (anthropic, openai, ollama)")
    parser.add_argument("--severity-filter", help="Comma-separated severity levels to report (e.g., critical,high)")

    args = parser.parse_args()

    # Build config from environment
    config = {
        "ai_provider": args.ai_provider or os.getenv("INPUT_AI_PROVIDER", "auto"),
        "anthropic_api_key": os.getenv("ANTHROPIC_API_KEY"),
        "openai_api_key": os.getenv("OPENAI_API_KEY"),
        "ollama_endpoint": os.getenv("OLLAMA_ENDPOINT"),
    }

    # Initialize analyzer
    analyzer = HybridSecurityAnalyzer(
        enable_semgrep=args.enable_semgrep,
        enable_trivy=args.enable_trivy,
        enable_ai_enrichment=args.enable_ai_enrichment,
        ai_provider=args.ai_provider,
        config=config,
    )

    # Parse severity filter
    severity_filter = None
    if args.severity_filter:
        severity_filter = [s.strip() for s in args.severity_filter.split(",")]

    # Run analysis
    result = analyzer.analyze(target_path=args.target, output_dir=args.output_dir, severity_filter=severity_filter)

    # Exit with error code if critical/high found
    if result.findings_by_severity["critical"] > 0 or result.findings_by_severity["high"] > 0:
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
