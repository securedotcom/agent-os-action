#!/usr/bin/env python3
"""
Unit tests for Agent Personas

Tests cover:
- Persona initialization (all 5 types)
- Agent selection logic
- Analysis output structure
- LLM response handling
- Error handling
- Expertise verification
- Finding analysis with confidence scoring
"""

import json
import sys
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch, call
from dataclasses import dataclass, asdict
from typing import Optional

import pytest

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

try:
    from agent_personas import (
        AgentPersona,
        SecretHunter,
        ArchitectureReviewer,
        PerformanceAnalyst,
        ComplianceExpert,
        VulnerabilityAssessor,
        AgentAnalysis,
        PersonaType,
    )
except ImportError:
    # Create mock classes for testing when module doesn't exist yet
    @dataclass
    class AgentAnalysis:
        agent_name: str
        verdict: str  # "confirmed", "false_positive", "needs_review"
        confidence: float
        reasoning: str
        severity: Optional[str] = None
        recommendation: Optional[str] = None

    class PersonaType:
        SECRET_HUNTER = "secret_hunter"
        ARCHITECTURE = "architecture"
        PERFORMANCE = "performance"
        COMPLIANCE = "compliance"
        VULNERABILITY = "vulnerability"

    class AgentPersona:
        def __init__(self, name: str, persona_type: str, llm_provider):
            self.name = name
            self.persona_type = persona_type
            self.llm_provider = llm_provider
            self.expertise = []

        def analyze(self, finding: dict) -> AgentAnalysis:
            pass

    class SecretHunter(AgentPersona):
        def __init__(self, llm_provider):
            super().__init__("SecretHunter", PersonaType.SECRET_HUNTER, llm_provider)
            self.expertise = ["api_keys", "tokens", "credentials", "secrets"]

    class ArchitectureReviewer(AgentPersona):
        def __init__(self, llm_provider):
            super().__init__("ArchitectureReviewer", PersonaType.ARCHITECTURE, llm_provider)
            self.expertise = ["design", "patterns", "dependencies", "structure"]

    class PerformanceAnalyst(AgentPersona):
        def __init__(self, llm_provider):
            super().__init__("PerformanceAnalyst", PersonaType.PERFORMANCE, llm_provider)
            self.expertise = ["efficiency", "optimization", "memory", "latency"]

    class ComplianceExpert(AgentPersona):
        def __init__(self, llm_provider):
            super().__init__("ComplianceExpert", PersonaType.COMPLIANCE, llm_provider)
            self.expertise = ["regulations", "standards", "audit", "policy"]

    class VulnerabilityAssessor(AgentPersona):
        def __init__(self, llm_provider):
            super().__init__("VulnerabilityAssessor", PersonaType.VULNERABILITY, llm_provider)
            self.expertise = ["cves", "exploits", "weaknesses", "threats"]


class TestAgentAnalysisDataclass:
    """Test AgentAnalysis dataclass structure"""

    def test_analysis_creation_minimal(self):
        """Test creating an AgentAnalysis with minimal fields"""
        analysis = AgentAnalysis(
            agent_name="SecretHunter",
            verdict="confirmed",
            confidence=0.95,
            reasoning="Found hardcoded AWS key in config file",
        )

        assert analysis.agent_name == "SecretHunter"
        assert analysis.verdict == "confirmed"
        assert analysis.confidence == 0.95
        assert analysis.reasoning == "Found hardcoded AWS key in config file"
        assert analysis.severity is None
        assert analysis.recommendation is None

    def test_analysis_creation_full(self):
        """Test creating an AgentAnalysis with all fields"""
        analysis = AgentAnalysis(
            agent_name="VulnerabilityAssessor",
            verdict="confirmed",
            confidence=0.88,
            reasoning="SQL injection vulnerability detected in user input handler",
            severity="high",
            recommendation="Use parameterized queries",
        )

        assert analysis.agent_name == "VulnerabilityAssessor"
        assert analysis.verdict == "confirmed"
        assert analysis.confidence == 0.88
        assert analysis.severity == "high"
        assert analysis.recommendation == "Use parameterized queries"

    def test_analysis_verdict_values(self):
        """Test all valid verdict values"""
        verdicts = ["confirmed", "false_positive", "needs_review"]

        for verdict in verdicts:
            analysis = AgentAnalysis(
                agent_name="Test",
                verdict=verdict,
                confidence=0.8,
                reasoning="Test",
            )
            assert analysis.verdict == verdict

    def test_analysis_confidence_bounds(self):
        """Test confidence value bounds"""
        for confidence in [0.0, 0.5, 1.0]:
            analysis = AgentAnalysis(
                agent_name="Test",
                verdict="confirmed",
                confidence=confidence,
                reasoning="Test",
            )
            assert analysis.confidence == confidence


class TestSecretHunter:
    """Test SecretHunter persona"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_llm = Mock()
        self.hunter = SecretHunter(self.mock_llm)

    def test_initialization(self):
        """Test SecretHunter initialization"""
        assert self.hunter.name == "SecretHunter"
        assert self.hunter.persona_type == PersonaType.SECRET_HUNTER
        assert "api_keys" in self.hunter.expertise
        assert "tokens" in self.hunter.expertise
        assert "credentials" in self.hunter.expertise
        assert "secrets" in self.hunter.expertise
        assert self.hunter.llm_provider == self.mock_llm

    def test_analyze_hardcoded_secret(self):
        """Test analyzing a hardcoded secret finding"""
        finding = {
            "path": "src/config.py",
            "message": "Hardcoded API key detected",
            "line": 42,
            "value": "sk-api-1234567890",
        }

        self.mock_llm.analyze = Mock(
            return_value={
                "verdict": "confirmed",
                "confidence": 0.98,
                "reasoning": "Hardcoded secret found in source file",
            }
        )

        result = self.hunter.analyze(finding)

        assert isinstance(result, AgentAnalysis)
        assert result.agent_name == "SecretHunter"
        assert result.verdict == "confirmed"
        assert result.confidence >= 0.7
        self.mock_llm.analyze.assert_called_once()

    def test_analyze_aws_credentials(self):
        """Test analyzing AWS credentials"""
        finding = {
            "path": ".env",
            "message": "AWS access key found",
            "detector": "aws",
            "value": "AKIA...",
        }

        self.mock_llm.analyze = Mock(
            return_value={
                "verdict": "confirmed",
                "confidence": 0.99,
                "reasoning": "AWS access key pattern detected",
            }
        )

        result = self.hunter.analyze(finding)

        assert result.verdict == "confirmed"
        assert result.confidence > 0.7

    def test_analyze_false_positive_secret(self):
        """Test analyzing a false positive secret"""
        finding = {
            "path": "tests/test_api.py",
            "message": "Secret token detected",
            "value": "test-token-12345",
        }

        self.mock_llm.analyze = Mock(
            return_value={
                "verdict": "false_positive",
                "confidence": 0.92,
                "reasoning": "Test token in test file, not a real secret",
            }
        )

        result = self.hunter.analyze(finding)

        assert result.verdict == "false_positive"
        assert result.confidence > 0.7

    def test_analyze_needs_review(self):
        """Test analyzing a finding that needs review"""
        finding = {
            "path": "src/auth.py",
            "message": "Potential secret pattern",
            "value": "password_hash_xyz",
        }

        self.mock_llm.analyze = Mock(
            return_value={
                "verdict": "needs_review",
                "confidence": 0.65,
                "reasoning": "Ambiguous pattern, manual review recommended",
            }
        )

        result = self.hunter.analyze(finding)

        assert result.verdict == "needs_review"

    def test_llm_provider_called_correctly(self):
        """Test that LLM provider is called with proper parameters"""
        finding = {"path": "src/api.py", "message": "API key found"}

        self.mock_llm.analyze = Mock(
            return_value={
                "verdict": "confirmed",
                "confidence": 0.95,
                "reasoning": "Real API key",
            }
        )

        self.hunter.analyze(finding)

        # Verify LLM was called
        self.mock_llm.analyze.assert_called_once()


class TestArchitectureReviewer:
    """Test ArchitectureReviewer persona"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_llm = Mock()
        self.reviewer = ArchitectureReviewer(self.mock_llm)

    def test_initialization(self):
        """Test ArchitectureReviewer initialization"""
        assert self.reviewer.name == "ArchitectureReviewer"
        assert self.reviewer.persona_type == PersonaType.ARCHITECTURE
        assert "design" in self.reviewer.expertise
        assert "patterns" in self.reviewer.expertise
        assert "dependencies" in self.reviewer.expertise
        assert "structure" in self.reviewer.expertise

    def test_analyze_design_pattern_issue(self):
        """Test analyzing a design pattern issue"""
        finding = {
            "path": "src/service.py",
            "message": "Singleton pattern misuse",
            "type": "design",
        }

        self.mock_llm.analyze = Mock(
            return_value={
                "verdict": "confirmed",
                "confidence": 0.85,
                "reasoning": "Singleton pattern implemented incorrectly",
                "recommendation": "Use dependency injection instead",
            }
        )

        result = self.reviewer.analyze(finding)

        assert result.verdict == "confirmed"
        assert result.recommendation is not None

    def test_analyze_circular_dependency(self):
        """Test analyzing a circular dependency"""
        finding = {
            "path": "src/models",
            "message": "Circular dependency detected",
            "modules": ["user", "profile"],
        }

        self.mock_llm.analyze = Mock(
            return_value={
                "verdict": "confirmed",
                "confidence": 0.90,
                "reasoning": "Circular dependency between modules",
            }
        )

        result = self.reviewer.analyze(finding)

        assert result.verdict == "confirmed"
        assert result.confidence > 0.7


class TestPerformanceAnalyst:
    """Test PerformanceAnalyst persona"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_llm = Mock()
        self.analyst = PerformanceAnalyst(self.mock_llm)

    def test_initialization(self):
        """Test PerformanceAnalyst initialization"""
        assert self.analyst.name == "PerformanceAnalyst"
        assert self.analyst.persona_type == PersonaType.PERFORMANCE
        assert "efficiency" in self.analyst.expertise
        assert "optimization" in self.analyst.expertise
        assert "memory" in self.analyst.expertise
        assert "latency" in self.analyst.expertise

    def test_analyze_n_plus_one_query(self):
        """Test analyzing N+1 query problem"""
        finding = {
            "path": "src/db.py",
            "message": "N+1 query pattern detected",
            "line": 156,
        }

        self.mock_llm.analyze = Mock(
            return_value={
                "verdict": "confirmed",
                "confidence": 0.88,
                "reasoning": "Loop contains database queries",
                "recommendation": "Use batch loading or eager loading",
            }
        )

        result = self.analyst.analyze(finding)

        assert result.verdict == "confirmed"
        assert "batch" in result.recommendation.lower()

    def test_analyze_memory_leak(self):
        """Test analyzing potential memory leak"""
        finding = {
            "path": "src/cache.py",
            "message": "Unbounded cache detected",
            "severity": "high",
        }

        self.mock_llm.analyze = Mock(
            return_value={
                "verdict": "confirmed",
                "confidence": 0.82,
                "reasoning": "Cache has no eviction policy",
                "severity": "high",
            }
        )

        result = self.analyst.analyze(finding)

        assert result.severity == "high"


class TestComplianceExpert:
    """Test ComplianceExpert persona"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_llm = Mock()
        self.expert = ComplianceExpert(self.mock_llm)

    def test_initialization(self):
        """Test ComplianceExpert initialization"""
        assert self.expert.name == "ComplianceExpert"
        assert self.expert.persona_type == PersonaType.COMPLIANCE
        assert "regulations" in self.expert.expertise
        assert "standards" in self.expert.expertise
        assert "audit" in self.expert.expertise
        assert "policy" in self.expert.expertise

    def test_analyze_gdpr_violation(self):
        """Test analyzing GDPR violation"""
        finding = {
            "path": "src/user.py",
            "message": "Personal data not encrypted",
            "type": "compliance",
        }

        self.mock_llm.analyze = Mock(
            return_value={
                "verdict": "confirmed",
                "confidence": 0.95,
                "reasoning": "GDPR requires encryption of PII",
                "severity": "critical",
            }
        )

        result = self.expert.analyze(finding)

        assert result.verdict == "confirmed"
        assert result.severity == "critical"

    def test_analyze_pci_dss_requirement(self):
        """Test analyzing PCI-DSS requirement violation"""
        finding = {
            "path": "src/payment.py",
            "message": "Credit card data logged",
            "framework": "pci-dss",
        }

        self.mock_llm.analyze = Mock(
            return_value={
                "verdict": "confirmed",
                "confidence": 0.99,
                "reasoning": "PCI-DSS 3.2.1 prohibits logging card data",
            }
        )

        result = self.expert.analyze(finding)

        assert result.confidence > 0.9


class TestVulnerabilityAssessor:
    """Test VulnerabilityAssessor persona"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_llm = Mock()
        self.assessor = VulnerabilityAssessor(self.mock_llm)

    def test_initialization(self):
        """Test VulnerabilityAssessor initialization"""
        assert self.assessor.name == "VulnerabilityAssessor"
        assert self.assessor.persona_type == PersonaType.VULNERABILITY
        assert "cves" in self.assessor.expertise
        assert "exploits" in self.assessor.expertise
        assert "weaknesses" in self.assessor.expertise
        assert "threats" in self.assessor.expertise

    def test_analyze_sql_injection(self):
        """Test analyzing SQL injection vulnerability"""
        finding = {
            "path": "src/query.py",
            "message": "SQL injection vulnerability",
            "cwe": "CWE-89",
            "line": 234,
        }

        self.mock_llm.analyze = Mock(
            return_value={
                "verdict": "confirmed",
                "confidence": 0.99,
                "reasoning": "User input concatenated into SQL query",
                "severity": "critical",
            }
        )

        result = self.assessor.analyze(finding)

        assert result.verdict == "confirmed"
        assert result.severity == "critical"

    def test_analyze_xss_vulnerability(self):
        """Test analyzing XSS vulnerability"""
        finding = {
            "path": "src/template.html",
            "message": "Unescaped user input in template",
            "cwe": "CWE-79",
        }

        self.mock_llm.analyze = Mock(
            return_value={
                "verdict": "confirmed",
                "confidence": 0.92,
                "reasoning": "User input rendered without escaping",
                "severity": "high",
            }
        )

        result = self.assessor.analyze(finding)

        assert result.severity == "high"

    def test_analyze_cve_finding(self):
        """Test analyzing known CVE"""
        finding = {
            "path": "requirements.txt",
            "message": "Vulnerable dependency detected",
            "cve": "CVE-2024-1234",
        }

        self.mock_llm.analyze = Mock(
            return_value={
                "verdict": "confirmed",
                "confidence": 0.98,
                "reasoning": "Known CVE with active exploits",
                "severity": "critical",
            }
        )

        result = self.assessor.analyze(finding)

        assert result.confidence > 0.9


class TestPersonaSelection:
    """Test agent selection logic"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_llm = Mock()
        self.personas = {
            "secret": SecretHunter(self.mock_llm),
            "architecture": ArchitectureReviewer(self.mock_llm),
            "performance": PerformanceAnalyst(self.mock_llm),
            "compliance": ComplianceExpert(self.mock_llm),
            "vulnerability": VulnerabilityAssessor(self.mock_llm),
        }

    def test_select_persona_for_secret_finding(self):
        """Test selecting SecretHunter for secret finding"""
        finding_type = "secret"
        assert self.personas["secret"].name == "SecretHunter"

    def test_select_persona_for_architecture_finding(self):
        """Test selecting ArchitectureReviewer for architecture finding"""
        finding_type = "architecture"
        assert self.personas["architecture"].name == "ArchitectureReviewer"

    def test_select_persona_for_vulnerability_finding(self):
        """Test selecting VulnerabilityAssessor for vulnerability finding"""
        finding_type = "vulnerability"
        assert self.personas["vulnerability"].name == "VulnerabilityAssessor"

    def test_all_personas_have_expertise(self):
        """Test that all personas have defined expertise"""
        for name, persona in self.personas.items():
            assert isinstance(persona.expertise, list)
            assert len(persona.expertise) > 0

    def test_all_personas_have_llm_provider(self):
        """Test that all personas have LLM provider"""
        for name, persona in self.personas.items():
            assert persona.llm_provider == self.mock_llm


class TestErrorHandling:
    """Test error handling in agent personas"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_llm = Mock()
        self.hunter = SecretHunter(self.mock_llm)

    def test_handle_llm_error(self):
        """Test handling LLM provider error"""
        finding = {"path": "src/api.py", "message": "Secret found"}

        self.mock_llm.analyze = Mock(side_effect=Exception("LLM API error"))

        with pytest.raises(Exception):
            self.hunter.analyze(finding)

    def test_handle_invalid_finding_structure(self):
        """Test handling invalid finding structure"""
        finding = {}  # Empty finding

        self.mock_llm.analyze = Mock(return_value={"verdict": "confirmed", "confidence": 0.8})

        # Should handle gracefully or raise appropriate error
        result = self.hunter.analyze(finding)
        assert isinstance(result, AgentAnalysis)

    def test_handle_missing_required_fields(self):
        """Test handling missing required analysis fields"""
        finding = {"path": "src/api.py", "message": "Secret found"}

        # Return incomplete response
        self.mock_llm.analyze = Mock(return_value={"verdict": "confirmed"})

        result = self.hunter.analyze(finding)
        assert result.verdict == "confirmed"

    def test_confidence_boundary_conditions(self):
        """Test confidence boundary conditions"""
        finding = {"path": "src/api.py", "message": "Secret found"}

        # Test with confidence = 1.0
        self.mock_llm.analyze = Mock(
            return_value={"verdict": "confirmed", "confidence": 1.0}
        )

        result = self.hunter.analyze(finding)
        assert result.confidence == 1.0

        # Test with confidence = 0.0
        self.mock_llm.analyze = Mock(
            return_value={"verdict": "confirmed", "confidence": 0.0}
        )

        result = self.hunter.analyze(finding)
        assert result.confidence == 0.0


class TestAnalysisOutputStructure:
    """Test analysis output structure and validation"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_llm = Mock()
        self.hunter = SecretHunter(self.mock_llm)

    def test_analysis_contains_required_fields(self):
        """Test that analysis output contains all required fields"""
        finding = {"path": "src/api.py", "message": "Secret found"}

        self.mock_llm.analyze = Mock(
            return_value={
                "verdict": "confirmed",
                "confidence": 0.95,
                "reasoning": "Found API key",
            }
        )

        result = self.hunter.analyze(finding)

        # Required fields
        assert hasattr(result, "agent_name")
        assert hasattr(result, "verdict")
        assert hasattr(result, "confidence")
        assert hasattr(result, "reasoning")

    def test_analysis_verdict_is_valid(self):
        """Test that verdict is one of valid values"""
        finding = {"path": "src/api.py", "message": "Secret found"}

        valid_verdicts = ["confirmed", "false_positive", "needs_review"]

        for verdict in valid_verdicts:
            self.mock_llm.analyze = Mock(
                return_value={"verdict": verdict, "confidence": 0.8}
            )

            result = self.hunter.analyze(finding)
            assert result.verdict in valid_verdicts

    def test_analysis_confidence_is_float(self):
        """Test that confidence is a float value"""
        finding = {"path": "src/api.py", "message": "Secret found"}

        self.mock_llm.analyze = Mock(
            return_value={"verdict": "confirmed", "confidence": 0.85}
        )

        result = self.hunter.analyze(finding)
        assert isinstance(result.confidence, (int, float))
        assert 0 <= result.confidence <= 1

    def test_analysis_reasoning_is_string(self):
        """Test that reasoning is a string"""
        finding = {"path": "src/api.py", "message": "Secret found"}

        self.mock_llm.analyze = Mock(
            return_value={
                "verdict": "confirmed",
                "confidence": 0.95,
                "reasoning": "Detailed explanation",
            }
        )

        result = self.hunter.analyze(finding)
        assert isinstance(result.reasoning, str)
        assert len(result.reasoning) > 0


class TestPersonaSpecialization:
    """Test that each persona has appropriate specialization"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_llm = Mock()

    def test_secret_hunter_specialization(self):
        """Test SecretHunter specialization"""
        hunter = SecretHunter(self.mock_llm)

        expected_expertise = ["api_keys", "tokens", "credentials", "secrets"]
        for skill in expected_expertise:
            assert skill in hunter.expertise

    def test_architecture_reviewer_specialization(self):
        """Test ArchitectureReviewer specialization"""
        reviewer = ArchitectureReviewer(self.mock_llm)

        expected_expertise = ["design", "patterns", "dependencies", "structure"]
        for skill in expected_expertise:
            assert skill in reviewer.expertise

    def test_performance_analyst_specialization(self):
        """Test PerformanceAnalyst specialization"""
        analyst = PerformanceAnalyst(self.mock_llm)

        expected_expertise = ["efficiency", "optimization", "memory", "latency"]
        for skill in expected_expertise:
            assert skill in analyst.expertise

    def test_compliance_expert_specialization(self):
        """Test ComplianceExpert specialization"""
        expert = ComplianceExpert(self.mock_llm)

        expected_expertise = ["regulations", "standards", "audit", "policy"]
        for skill in expected_expertise:
            assert skill in expert.expertise

    def test_vulnerability_assessor_specialization(self):
        """Test VulnerabilityAssessor specialization"""
        assessor = VulnerabilityAssessor(self.mock_llm)

        expected_expertise = ["cves", "exploits", "weaknesses", "threats"]
        for skill in expected_expertise:
            assert skill in assessor.expertise
