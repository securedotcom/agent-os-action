#!/usr/bin/env python3
"""
Unit tests for Spontaneous Discovery

Tests cover:
- Discovery categories (secrets, vulnerabilities, design issues, performance, compliance)
- Confidence filtering (>0.7 threshold)
- Deduplication with existing findings
- Architecture analysis
- LLM discovery generation
- File list integration
- Discovery output structure
"""

import json
import sys
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch, call
from dataclasses import dataclass
from typing import Optional, List

import pytest

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

try:
    from spontaneous_discovery import (
        SpontaneousDiscovery,
        Discovery,
        DiscoveryCategory,
    )
except ImportError:
    # Create mock classes for testing when module doesn't exist yet
    class DiscoveryCategory:
        SECRET = "secret"
        VULNERABILITY = "vulnerability"
        DESIGN_ISSUE = "design_issue"
        PERFORMANCE = "performance"
        COMPLIANCE = "compliance"
        ARCHITECTURE = "architecture"

    @dataclass
    class Discovery:
        category: str
        location: str  # File path and line
        issue_description: str
        evidence: str
        confidence: float
        severity: Optional[str] = None
        recommendation: Optional[str] = None
        related_findings: Optional[List[str]] = None

    class SpontaneousDiscovery:
        def __init__(self, llm_provider, file_list: List[str]):
            self.llm_provider = llm_provider
            self.file_list = file_list
            self.discoveries = []
            self.existing_findings = []

        def analyze_architecture(self) -> List[Discovery]:
            pass

        def discover_issues(self) -> List[Discovery]:
            pass

        def filter_high_confidence(self, confidence_threshold: float = 0.7) -> List[Discovery]:
            pass

        def deduplicate_with_findings(self, existing_findings: List[dict]) -> List[Discovery]:
            pass


class TestDiscoveryDataclass:
    """Test Discovery dataclass structure"""

    def test_discovery_creation_minimal(self):
        """Test creating a Discovery with minimal fields"""
        discovery = Discovery(
            category=DiscoveryCategory.SECRET,
            location="src/config.py:42",
            issue_description="Hardcoded API key",
            evidence="pattern matches AWS key format",
            confidence=0.92,
        )

        assert discovery.category == DiscoveryCategory.SECRET
        assert discovery.location == "src/config.py:42"
        assert discovery.issue_description == "Hardcoded API key"
        assert discovery.confidence == 0.92
        assert discovery.severity is None
        assert discovery.recommendation is None

    def test_discovery_creation_full(self):
        """Test creating a Discovery with all fields"""
        discovery = Discovery(
            category=DiscoveryCategory.VULNERABILITY,
            location="src/db.py:156",
            issue_description="SQL injection in user query",
            evidence="User input concatenated into query",
            confidence=0.95,
            severity="critical",
            recommendation="Use parameterized queries",
            related_findings=["finding-001", "finding-002"],
        )

        assert discovery.category == DiscoveryCategory.VULNERABILITY
        assert discovery.severity == "critical"
        assert discovery.recommendation is not None
        assert len(discovery.related_findings) == 2

    def test_discovery_categories(self):
        """Test all discovery categories"""
        categories = [
            DiscoveryCategory.SECRET,
            DiscoveryCategory.VULNERABILITY,
            DiscoveryCategory.DESIGN_ISSUE,
            DiscoveryCategory.PERFORMANCE,
            DiscoveryCategory.COMPLIANCE,
            DiscoveryCategory.ARCHITECTURE,
        ]

        for category in categories:
            discovery = Discovery(
                category=category,
                location="test.py:1",
                issue_description="Test",
                evidence="Test",
                confidence=0.8,
            )
            assert discovery.category == category

    def test_discovery_confidence_bounds(self):
        """Test confidence value bounds"""
        for confidence in [0.0, 0.5, 0.7, 0.99, 1.0]:
            discovery = Discovery(
                category=DiscoveryCategory.SECRET,
                location="test.py:1",
                issue_description="Test",
                evidence="Test",
                confidence=confidence,
            )
            assert discovery.confidence == confidence


class TestSpontaneousDiscoveryInitialization:
    """Test SpontaneousDiscovery initialization"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_llm = Mock()
        self.file_list = [
            "src/api.py",
            "src/db.py",
            "src/auth.py",
            "config/settings.py",
        ]

    def test_initialization(self):
        """Test SpontaneousDiscovery initialization"""
        discovery = SpontaneousDiscovery(self.mock_llm, self.file_list)

        assert discovery.llm_provider == self.mock_llm
        assert discovery.file_list == self.file_list
        assert isinstance(discovery.discoveries, list)
        assert isinstance(discovery.existing_findings, list)

    def test_initialization_empty_file_list(self):
        """Test initialization with empty file list"""
        discovery = SpontaneousDiscovery(self.mock_llm, [])

        assert discovery.file_list == []

    def test_initialization_large_file_list(self):
        """Test initialization with large file list"""
        large_file_list = [f"src/module_{i}.py" for i in range(100)]
        discovery = SpontaneousDiscovery(self.mock_llm, large_file_list)

        assert len(discovery.file_list) == 100


class TestArchitectureAnalysis:
    """Test architecture analysis discovery"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_llm = Mock()
        self.file_list = ["src/models.py", "src/services.py", "src/api.py"]
        self.discovery = SpontaneousDiscovery(self.mock_llm, self.file_list)

    def test_analyze_architecture_circular_dependency(self):
        """Test discovering circular dependency"""
        self.mock_llm.analyze = Mock(
            return_value={
                "discoveries": [
                    {
                        "category": DiscoveryCategory.ARCHITECTURE,
                        "location": "src/models.py",
                        "issue": "Circular dependency between models and services",
                        "evidence": "models imports services, services imports models",
                        "confidence": 0.88,
                        "severity": "high",
                    }
                ]
            }
        )

        discoveries = self.discovery.analyze_architecture()

        assert len(discoveries) > 0
        assert any(d.category == DiscoveryCategory.ARCHITECTURE for d in discoveries)

    def test_analyze_architecture_tight_coupling(self):
        """Test discovering tight coupling"""
        self.mock_llm.analyze = Mock(
            return_value={
                "discoveries": [
                    {
                        "category": DiscoveryCategory.DESIGN_ISSUE,
                        "location": "src/api.py",
                        "issue": "Tight coupling to database layer",
                        "evidence": "Direct database calls in API routes",
                        "confidence": 0.82,
                        "recommendation": "Introduce service layer",
                    }
                ]
            }
        )

        discoveries = self.discovery.analyze_architecture()

        assert any(d.category == DiscoveryCategory.DESIGN_ISSUE for d in discoveries)

    def test_analyze_architecture_missing_abstraction(self):
        """Test discovering missing abstraction"""
        self.mock_llm.analyze = Mock(
            return_value={
                "discoveries": [
                    {
                        "category": DiscoveryCategory.DESIGN_ISSUE,
                        "location": "src/services.py",
                        "issue": "Missing abstraction layer",
                        "evidence": "Services directly access external APIs",
                        "confidence": 0.75,
                    }
                ]
            }
        )

        discoveries = self.discovery.analyze_architecture()

        assert isinstance(discoveries, list)


class TestIssueDiscovery:
    """Test issue discovery"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_llm = Mock()
        self.file_list = [
            "src/api.py",
            "src/db.py",
            "src/cache.py",
        ]
        self.discovery = SpontaneousDiscovery(self.mock_llm, self.file_list)

    def test_discover_hardcoded_secrets(self):
        """Test discovering hardcoded secrets"""
        self.mock_llm.analyze = Mock(
            return_value={
                "discoveries": [
                    {
                        "category": DiscoveryCategory.SECRET,
                        "location": "src/api.py:15",
                        "issue": "Hardcoded API key",
                        "evidence": "sk_live_51234567890",
                        "confidence": 0.98,
                        "severity": "critical",
                    }
                ]
            }
        )

        discoveries = self.discovery.discover_issues()

        assert len(discoveries) > 0
        assert discoveries[0].confidence > 0.7

    def test_discover_sql_injection(self):
        """Test discovering SQL injection"""
        self.mock_llm.analyze = Mock(
            return_value={
                "discoveries": [
                    {
                        "category": DiscoveryCategory.VULNERABILITY,
                        "location": "src/db.py:42",
                        "issue": "SQL injection vulnerability",
                        "evidence": "Query constructed with string concatenation",
                        "confidence": 0.94,
                        "severity": "critical",
                        "recommendation": "Use parameterized queries",
                    }
                ]
            }
        )

        discoveries = self.discovery.discover_issues()

        assert any(d.category == DiscoveryCategory.VULNERABILITY for d in discoveries)

    def test_discover_performance_issues(self):
        """Test discovering performance issues"""
        self.mock_llm.analyze = Mock(
            return_value={
                "discoveries": [
                    {
                        "category": DiscoveryCategory.PERFORMANCE,
                        "location": "src/db.py:156",
                        "issue": "N+1 query problem",
                        "evidence": "Loop contains database queries",
                        "confidence": 0.85,
                        "severity": "medium",
                        "recommendation": "Use batch loading",
                    }
                ]
            }
        )

        discoveries = self.discovery.discover_issues()

        assert any(d.category == DiscoveryCategory.PERFORMANCE for d in discoveries)

    def test_discover_compliance_issues(self):
        """Test discovering compliance issues"""
        self.mock_llm.analyze = Mock(
            return_value={
                "discoveries": [
                    {
                        "category": DiscoveryCategory.COMPLIANCE,
                        "location": "src/api.py:89",
                        "issue": "PII not encrypted in transit",
                        "evidence": "User data sent over HTTP",
                        "confidence": 0.92,
                        "severity": "critical",
                    }
                ]
            }
        )

        discoveries = self.discovery.discover_issues()

        assert any(d.category == DiscoveryCategory.COMPLIANCE for d in discoveries)

    def test_discover_mixed_categories(self):
        """Test discovering issues from multiple categories"""
        self.mock_llm.analyze = Mock(
            return_value={
                "discoveries": [
                    {
                        "category": DiscoveryCategory.SECRET,
                        "location": "src/api.py:10",
                        "issue": "Hardcoded secret",
                        "evidence": "API key found",
                        "confidence": 0.95,
                    },
                    {
                        "category": DiscoveryCategory.VULNERABILITY,
                        "location": "src/db.py:40",
                        "issue": "SQL injection",
                        "evidence": "Query concatenation",
                        "confidence": 0.90,
                    },
                    {
                        "category": DiscoveryCategory.PERFORMANCE,
                        "location": "src/cache.py:50",
                        "issue": "Unbounded cache",
                        "evidence": "No eviction policy",
                        "confidence": 0.88,
                    },
                ]
            }
        )

        discoveries = self.discovery.discover_issues()

        assert len(discoveries) == 3
        categories = {d.category for d in discoveries}
        assert DiscoveryCategory.SECRET in categories
        assert DiscoveryCategory.VULNERABILITY in categories
        assert DiscoveryCategory.PERFORMANCE in categories


class TestConfidenceFiltering:
    """Test confidence filtering"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_llm = Mock()
        self.file_list = ["src/api.py"]
        self.discovery = SpontaneousDiscovery(self.mock_llm, self.file_list)

        # Create discoveries with various confidence levels
        self.discovery.discoveries = [
            Discovery(
                category=DiscoveryCategory.SECRET,
                location="src/api.py:10",
                issue_description="High confidence finding",
                evidence="Strong evidence",
                confidence=0.95,
            ),
            Discovery(
                category=DiscoveryCategory.VULNERABILITY,
                location="src/api.py:20",
                issue_description="Medium confidence finding",
                evidence="Moderate evidence",
                confidence=0.72,
            ),
            Discovery(
                category=DiscoveryCategory.PERFORMANCE,
                location="src/api.py:30",
                issue_description="Low confidence finding",
                evidence="Weak evidence",
                confidence=0.65,
            ),
            Discovery(
                category=DiscoveryCategory.COMPLIANCE,
                location="src/api.py:40",
                issue_description="Threshold finding",
                evidence="Edge case",
                confidence=0.70,
            ),
        ]

    def test_filter_high_confidence_default_threshold(self):
        """Test filtering with default threshold (0.7)"""
        filtered = self.discovery.filter_high_confidence()

        assert len(filtered) == 2  # 0.95 and 0.72 (above or equal to 0.7)
        assert all(d.confidence >= 0.7 for d in filtered)

    def test_filter_high_confidence_custom_threshold(self):
        """Test filtering with custom threshold"""
        filtered = self.discovery.filter_high_confidence(confidence_threshold=0.80)

        assert len(filtered) == 1  # Only 0.95
        assert all(d.confidence >= 0.80 for d in filtered)

    def test_filter_high_confidence_low_threshold(self):
        """Test filtering with low threshold"""
        filtered = self.discovery.filter_high_confidence(confidence_threshold=0.6)

        assert len(filtered) == 4  # All discoveries
        assert all(d.confidence >= 0.6 for d in filtered)

    def test_filter_high_confidence_high_threshold(self):
        """Test filtering with high threshold"""
        filtered = self.discovery.filter_high_confidence(confidence_threshold=0.95)

        assert len(filtered) == 1  # Only the 0.95 discovery
        assert filtered[0].confidence == 0.95

    def test_filter_high_confidence_empty_result(self):
        """Test filtering that results in empty list"""
        filtered = self.discovery.filter_high_confidence(confidence_threshold=1.0)

        assert len(filtered) == 0

    def test_filter_preserves_discovery_order(self):
        """Test that filtering preserves discovery order"""
        filtered = self.discovery.filter_high_confidence(confidence_threshold=0.7)

        assert filtered[0].confidence == 0.95
        assert filtered[1].confidence == 0.72


class TestDeduplication:
    """Test deduplication with existing findings"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_llm = Mock()
        self.file_list = ["src/api.py", "src/db.py"]
        self.discovery = SpontaneousDiscovery(self.mock_llm, self.file_list)

        self.discovery.discoveries = [
            Discovery(
                category=DiscoveryCategory.SECRET,
                location="src/api.py:10",
                issue_description="API key found",
                evidence="sk_live_123",
                confidence=0.95,
            ),
            Discovery(
                category=DiscoveryCategory.VULNERABILITY,
                location="src/db.py:42",
                issue_description="SQL injection",
                evidence="Query concatenation",
                confidence=0.90,
            ),
            Discovery(
                category=DiscoveryCategory.PERFORMANCE,
                location="src/api.py:50",
                issue_description="N+1 query",
                evidence="Loop with queries",
                confidence=0.88,
            ),
        ]

        self.existing_findings = [
            {
                "file": "src/api.py",
                "line": 10,
                "type": "secret",
                "message": "API key",
            },
            {
                "file": "src/other.py",
                "line": 5,
                "type": "vulnerability",
                "message": "XSS vulnerability",
            },
        ]

    def test_deduplicate_removes_existing(self):
        """Test that deduplication removes existing findings"""
        deduplicated = self.discovery.deduplicate_with_findings(self.existing_findings)

        # Should remove the API key discovery as it matches existing finding
        assert len(deduplicated) < len(self.discovery.discoveries)

    def test_deduplicate_keeps_new(self):
        """Test that deduplication keeps new findings"""
        deduplicated = self.discovery.deduplicate_with_findings(self.existing_findings)

        # Should keep SQL injection and N+1 query as they're new
        assert any(d.category == DiscoveryCategory.VULNERABILITY for d in deduplicated)
        assert any(d.category == DiscoveryCategory.PERFORMANCE for d in deduplicated)

    def test_deduplicate_empty_existing(self):
        """Test deduplication with no existing findings"""
        deduplicated = self.discovery.deduplicate_with_findings([])

        # Should keep all discoveries
        assert len(deduplicated) == len(self.discovery.discoveries)

    def test_deduplicate_all_exist(self):
        """Test deduplication when all findings exist"""
        existing = [
            {"file": "src/api.py", "line": 10, "type": "secret"},
            {"file": "src/db.py", "line": 42, "type": "vulnerability"},
            {"file": "src/api.py", "line": 50, "type": "performance"},
        ]

        deduplicated = self.discovery.deduplicate_with_findings(existing)

        # Should remove all
        assert len(deduplicated) == 0

    def test_deduplicate_similar_but_different(self):
        """Test deduplication with similar but different findings"""
        existing = [
            {
                "file": "src/api.py",
                "line": 11,  # Different line number
                "type": "secret",
            },
        ]

        deduplicated = self.discovery.deduplicate_with_findings(existing)

        # Should keep because location differs
        assert len(deduplicated) > 0


class TestDiscoveryOutput:
    """Test discovery output structure"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_llm = Mock()
        self.file_list = ["src/api.py"]
        self.discovery = SpontaneousDiscovery(self.mock_llm, self.file_list)

    def test_discovery_contains_required_fields(self):
        """Test that discovery contains all required fields"""
        disc = Discovery(
            category=DiscoveryCategory.SECRET,
            location="src/api.py:10",
            issue_description="Test issue",
            evidence="Test evidence",
            confidence=0.85,
        )

        assert hasattr(disc, "category")
        assert hasattr(disc, "location")
        assert hasattr(disc, "issue_description")
        assert hasattr(disc, "evidence")
        assert hasattr(disc, "confidence")

    def test_discovery_can_include_optional_fields(self):
        """Test that discovery can include optional fields"""
        disc = Discovery(
            category=DiscoveryCategory.VULNERABILITY,
            location="src/db.py:42",
            issue_description="SQL injection",
            evidence="Evidence",
            confidence=0.94,
            severity="critical",
            recommendation="Use parameterized queries",
            related_findings=["f1", "f2"],
        )

        assert disc.severity == "critical"
        assert disc.recommendation is not None
        assert len(disc.related_findings) == 2

    def test_discovery_location_format(self):
        """Test discovery location format"""
        locations = [
            "src/api.py:10",
            "src/db.py:42",
            "src/models.py",
            "tests/test_api.py:100",
        ]

        for loc in locations:
            disc = Discovery(
                category=DiscoveryCategory.SECRET,
                location=loc,
                issue_description="Test",
                evidence="Test",
                confidence=0.8,
            )
            assert disc.location == loc


class TestLLMIntegration:
    """Test LLM integration"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_llm = Mock()
        self.file_list = ["src/api.py", "src/db.py"]
        self.discovery = SpontaneousDiscovery(self.mock_llm, self.file_list)

    def test_llm_called_for_discovery(self):
        """Test that LLM is called during discovery"""
        self.mock_llm.analyze = Mock(return_value={"discoveries": []})

        self.discovery.discover_issues()

        self.mock_llm.analyze.assert_called()

    def test_llm_handles_error(self):
        """Test error handling from LLM"""
        self.mock_llm.analyze = Mock(side_effect=Exception("LLM error"))

        with pytest.raises(Exception):
            self.discovery.discover_issues()

    def test_llm_response_parsed(self):
        """Test parsing LLM response"""
        self.mock_llm.analyze = Mock(
            return_value={
                "discoveries": [
                    {
                        "category": DiscoveryCategory.SECRET,
                        "location": "src/api.py:10",
                        "issue": "Secret",
                        "evidence": "Evidence",
                        "confidence": 0.9,
                    }
                ]
            }
        )

        discoveries = self.discovery.discover_issues()

        assert len(discoveries) > 0


class TestEdgeCases:
    """Test edge cases"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_llm = Mock()

    def test_empty_file_list(self):
        """Test with empty file list"""
        discovery = SpontaneousDiscovery(self.mock_llm, [])

        assert discovery.file_list == []

    def test_single_file(self):
        """Test with single file"""
        discovery = SpontaneousDiscovery(self.mock_llm, ["src/api.py"])

        assert len(discovery.file_list) == 1

    def test_special_characters_in_file_names(self):
        """Test files with special characters"""
        files = ["src/test-api.py", "src/test_db.py", "src/test@service.py"]
        discovery = SpontaneousDiscovery(self.mock_llm, files)

        assert discovery.file_list == files

    def test_discovery_confidence_precision(self):
        """Test confidence precision"""
        disc = Discovery(
            category=DiscoveryCategory.SECRET,
            location="test.py:1",
            issue_description="Test",
            evidence="Test",
            confidence=0.123456789,
        )

        assert disc.confidence == 0.123456789

    def test_long_issue_description(self):
        """Test handling long issue descriptions"""
        long_desc = "A" * 1000
        disc = Discovery(
            category=DiscoveryCategory.VULNERABILITY,
            location="test.py:1",
            issue_description=long_desc,
            evidence="Test",
            confidence=0.8,
        )

        assert len(disc.issue_description) == 1000

    def test_unicode_in_issue_description(self):
        """Test handling unicode in issue descriptions"""
        disc = Discovery(
            category=DiscoveryCategory.COMPLIANCE,
            location="test.py:1",
            issue_description="GDPR violation: données personnelles 🔒",
            evidence="Evidence",
            confidence=0.9,
        )

        assert "données" in disc.issue_description
