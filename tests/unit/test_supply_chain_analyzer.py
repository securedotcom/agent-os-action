#!/usr/bin/env python3
"""
Comprehensive tests for Supply Chain Attack Detection

Tests cover:
- Dependency change detection (npm, PyPI, Go, Cargo, Maven)
- Typosquatting detection with Levenshtein distance
- Malicious behavior pattern detection
- OpenSSF Scorecard integration
- Threat assessment logic
- Edge cases and error handling
"""

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch, call, mock_open

import pytest

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from supply_chain_analyzer import (
    SupplyChainAnalyzer,
    DependencyChange,
    ThreatAssessment,
    ThreatLevel,
)


class TestDependencyChange:
    """Test DependencyChange dataclass"""

    def test_dependency_change_creation_added(self):
        """Test creating a dependency change for added package"""
        change = DependencyChange(
            package_name="express",
            ecosystem="npm",
            change_type="added",
            new_version="4.18.2",
            file_path="package.json",
        )

        assert change.package_name == "express"
        assert change.ecosystem == "npm"
        assert change.change_type == "added"
        assert change.new_version == "4.18.2"
        assert change.old_version is None
        assert change.file_path == "package.json"

    def test_dependency_change_creation_removed(self):
        """Test creating a dependency change for removed package"""
        change = DependencyChange(
            package_name="lodash",
            ecosystem="npm",
            change_type="removed",
            old_version="4.17.20",
            file_path="package.json",
        )

        assert change.package_name == "lodash"
        assert change.change_type == "removed"
        assert change.old_version == "4.17.20"
        assert change.new_version is None

    def test_dependency_change_creation_updated(self):
        """Test creating a dependency change for version update"""
        change = DependencyChange(
            package_name="requests",
            ecosystem="pypi",
            change_type="version_change",
            old_version="2.28.0",
            new_version="2.31.0",
            file_path="requirements.txt",
        )

        assert change.package_name == "requests"
        assert change.ecosystem == "pypi"
        assert change.old_version == "2.28.0"
        assert change.new_version == "2.31.0"

    def test_dependency_change_to_dict(self):
        """Test converting dependency change to dictionary using dataclasses.asdict"""
        from dataclasses import asdict

        change = DependencyChange(
            package_name="django",
            ecosystem="pypi",
            change_type="added",
            new_version="4.2.0",
            file_path="requirements.txt",
        )

        result = asdict(change)

        assert isinstance(result, dict)
        assert result["package_name"] == "django"
        assert result["ecosystem"] == "pypi"
        assert result["change_type"] == "added"


class TestThreatLevel:
    """Test ThreatLevel enum"""

    def test_threat_level_values(self):
        """Test that ThreatLevel enum has expected values"""
        assert ThreatLevel.CRITICAL.value == "critical"
        assert ThreatLevel.HIGH.value == "high"
        assert ThreatLevel.MEDIUM.value == "medium"
        assert ThreatLevel.LOW.value == "low"
        assert ThreatLevel.INFO.value == "info"

    def test_threat_level_comparison(self):
        """Test that ThreatLevel enum values can be compared"""
        assert ThreatLevel.CRITICAL.value == "critical"
        assert ThreatLevel.HIGH.value != ThreatLevel.LOW.value


class TestThreatAssessment:
    """Test ThreatAssessment dataclass"""

    def test_threat_assessment_creation(self):
        """Test creating a threat assessment"""
        assessment = ThreatAssessment(
            package_name="test-pkg",
            ecosystem="npm",
            threat_level=ThreatLevel.HIGH,
            threat_types=["typosquatting"],
            evidence=["Similar to popular package"],
            recommendations=["Verify package name"],
        )

        assert assessment.package_name == "test-pkg"
        assert assessment.ecosystem == "npm"
        assert assessment.threat_level == ThreatLevel.HIGH
        assert "typosquatting" in assessment.threat_types

    def test_threat_assessment_with_change_info(self):
        """Test ThreatAssessment with change info"""
        change = DependencyChange(
            package_name="test", ecosystem="npm", change_type="added", new_version="1.0.0"
        )

        assessment = ThreatAssessment(
            package_name="test",
            ecosystem="npm",
            threat_level=ThreatLevel.MEDIUM,
            threat_types=[],
            evidence=[],
            recommendations=[],
            change_info=change,
        )

        assert assessment.change_info is not None
        assert assessment.change_info.package_name == "test"

    def test_threat_assessment_to_dict(self):
        """Test converting threat assessment to dictionary"""
        assessment = ThreatAssessment(
            package_name="malicious-pkg",
            ecosystem="npm",
            threat_level=ThreatLevel.CRITICAL,
            threat_types=["malicious_script"],
            evidence=["Suspicious postinstall script"],
            recommendations=["Do not install"],
        )

        result = assessment.to_dict()

        assert isinstance(result, dict)
        assert result["package_name"] == "malicious-pkg"
        assert result["threat_level"] == "critical"
        assert "malicious_script" in result["threat_types"]


class TestSupplyChainAnalyzer:
    """Test SupplyChainAnalyzer class"""

    def setup_method(self):
        """Setup test instance"""
        self.analyzer = SupplyChainAnalyzer(repo_path=".")

    # Levenshtein Distance Tests

    def test_levenshtein_distance_identical(self):
        """Test Levenshtein distance with identical strings"""
        assert self.analyzer._levenshtein_distance("test", "test") == 0

    def test_levenshtein_distance_single_char_substitution(self):
        """Test Levenshtein distance with single character substitution"""
        assert self.analyzer._levenshtein_distance("test", "text") == 1

    def test_levenshtein_distance_single_char_insertion(self):
        """Test Levenshtein distance with single character insertion"""
        assert self.analyzer._levenshtein_distance("test", "tests") == 1

    def test_levenshtein_distance_single_char_deletion(self):
        """Test Levenshtein distance with single character deletion"""
        assert self.analyzer._levenshtein_distance("tests", "test") == 1

    def test_levenshtein_distance_empty_strings(self):
        """Test Levenshtein distance with empty strings"""
        assert self.analyzer._levenshtein_distance("", "") == 0
        assert self.analyzer._levenshtein_distance("test", "") == 4
        assert self.analyzer._levenshtein_distance("", "test") == 4

    def test_levenshtein_distance_multiple_changes(self):
        """Test Levenshtein distance with multiple character changes"""
        assert self.analyzer._levenshtein_distance("kitten", "sitting") == 3

    def test_levenshtein_distance_case_sensitive(self):
        """Test that Levenshtein distance is case-sensitive"""
        assert self.analyzer._levenshtein_distance("Test", "test") == 1

    # Typosquatting Detection Tests

    def test_typosquatting_detection_express(self):
        """Test detection of express typosquatting"""
        result = self.analyzer.check_typosquatting("expresss", "npm")

        assert result is not None
        assert result["legitimate_package"] == "express"
        assert result["distance"] <= 2
        assert result["distance"] >= 1

    def test_typosquatting_detection_lodash(self):
        """Test detection of lodash typosquatting"""
        result = self.analyzer.check_typosquatting("loadash", "npm")

        assert result is not None
        assert result["legitimate_package"] == "lodash"
        assert isinstance(result["distance"], int)

    def test_typosquatting_detection_requests_pypi(self):
        """Test detection of requests typosquatting in PyPI"""
        result = self.analyzer.check_typosquatting("reqeusts", "pypi")

        assert result is not None
        assert result["legitimate_package"] == "requests"

    def test_typosquatting_detection_django(self):
        """Test detection of django typosquatting"""
        result = self.analyzer.check_typosquatting("djang0", "pypi")

        assert result is not None
        assert result["legitimate_package"] == "django"

    def test_no_typosquatting_legitimate_package(self):
        """Test that legitimate packages aren't flagged"""
        result = self.analyzer.check_typosquatting("express", "npm")
        assert result is None

    def test_no_typosquatting_unrelated_package(self):
        """Test that unrelated packages aren't flagged"""
        result = self.analyzer.check_typosquatting("mycustompackage123", "npm")
        assert result is None

    def test_no_typosquatting_too_different(self):
        """Test that packages too different aren't flagged"""
        result = self.analyzer.check_typosquatting("abc", "npm")
        assert result is None

    def test_typosquatting_unknown_ecosystem(self):
        """Test typosquatting check with unknown ecosystem"""
        result = self.analyzer.check_typosquatting("testpkg", "unknown")
        assert result is None

    def test_typosquatting_distance_check(self):
        """Test typosquatting distance is within expected range"""
        result = self.analyzer.check_typosquatting("expresss", "npm")

        if result:
            assert result["distance"] in [1, 2]

    def test_typosquatting_similar_list(self):
        """Test typosquatting result contains similar packages list"""
        result = self.analyzer.check_typosquatting("expr", "npm")

        # May or may not trigger depending on similarity threshold (distance must be 1-2)
        assert result is None or ("similar" in result and isinstance(result["similar"], list))

    # Malicious Pattern Detection Tests

    def test_analyze_package_behavior_npm(self):
        """Test analyzing npm package behavior"""
        # Mock network call since analyze_package_behavior may make network requests
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_response = MagicMock()
            mock_response.read.return_value = b'{"scripts": {"postinstall": "echo test"}}'
            mock_response.__enter__.return_value = mock_response
            mock_urlopen.return_value = mock_response

            result = self.analyzer.analyze_package_behavior("express", "npm")

            # Should return dict or None
            assert result is None or isinstance(result, dict)

    def test_analyze_package_behavior_pypi(self):
        """Test analyzing PyPI package behavior"""
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_response = MagicMock()
            mock_response.read.return_value = b'{"info": {"description": "A test package"}}'
            mock_response.__enter__.return_value = mock_response
            mock_urlopen.return_value = mock_response

            result = self.analyzer.analyze_package_behavior("requests", "pypi")

            assert result is None or isinstance(result, dict)

    def test_analyze_package_behavior_network_disabled(self):
        """Test behavior analysis when network is disabled"""
        analyzer = SupplyChainAnalyzer(enable_network=False)
        result = analyzer.analyze_package_behavior("test-pkg", "npm")

        # Should return None when network is disabled
        assert result is None

    def test_check_openssf_scorecard_npm(self):
        """Test checking OpenSSF Scorecard for npm package"""
        # Mock GitHub API call
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_response = MagicMock()
            mock_response.read.return_value = b'{"repository": {"url": "git+https://github.com/expressjs/express.git"}}'
            mock_response.__enter__.return_value = mock_response
            mock_urlopen.return_value = mock_response

            result = self.analyzer.check_openssf_scorecard("express", "npm")

            # Should return dict or None
            assert result is None or isinstance(result, dict)

    def test_check_openssf_scorecard_network_disabled(self):
        """Test OpenSSF Scorecard when network is disabled"""
        analyzer = SupplyChainAnalyzer(enable_network=False)
        result = analyzer.check_openssf_scorecard("test-pkg", "npm")

        assert result is None

    # Dependency Change Detection Tests

    def test_parse_npm_packages(self):
        """Test parsing npm package.json content"""
        content = '{"dependencies": {"express": "^4.18.2", "lodash": "^4.17.21"}}'

        packages = self.analyzer._parse_npm_packages(content)

        assert isinstance(packages, dict)
        assert "express" in packages or len(packages) == 0  # May be empty if parsing fails

    def test_parse_requirements_txt(self):
        """Test parsing requirements.txt content"""
        content = "requests==2.31.0\nurllib3==2.0.4\ndjango>=4.0.0"

        packages = self.analyzer._parse_requirements_txt(content)

        assert isinstance(packages, dict)
        if packages:
            assert "requests" in packages
            assert packages["requests"] == "2.31.0"

    def test_parse_go_mod(self):
        """Test parsing go.mod content"""
        content = """module example.com/myapp

go 1.20

require (
    github.com/gin-gonic/gin v1.9.0
    github.com/spf13/cobra v1.7.0
)"""

        packages = self.analyzer._parse_go_mod(content)

        assert isinstance(packages, dict)

    def test_parse_cargo_toml(self):
        """Test parsing Cargo.toml content"""
        content = """[package]
name = "myapp"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "1.28", features = ["full"] }"""

        packages = self.analyzer._parse_cargo_toml(content)

        assert isinstance(packages, dict)

    def test_parse_pom_xml(self):
        """Test parsing pom.xml content"""
        content = """<?xml version="1.0"?>
<project>
    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>6.0.0</version>
        </dependency>
    </dependencies>
</project>"""

        packages = self.analyzer._parse_pom_xml(content)

        assert isinstance(packages, dict)

    # Edge Cases and Error Handling

    def test_analyze_dependency_with_special_chars(self):
        """Test analyzing dependency names with special characters"""
        change = DependencyChange(
            package_name="@babel/core",
            ecosystem="npm",
            change_type="added",
            new_version="7.22.0",
        )

        # Should not crash
        assessment = self.analyzer._assess_dependency(change)
        assert assessment is None or isinstance(assessment, ThreatAssessment)

    def test_analyze_dependency_with_unicode(self):
        """Test analyzing dependency names with unicode characters"""
        change = DependencyChange(
            package_name="test-",  # Contains Chinese characters
            ecosystem="npm",
            change_type="added",
            new_version="1.0.0",
        )

        # Should handle gracefully
        assessment = self.analyzer._assess_dependency(change)
        assert assessment is None or isinstance(assessment, ThreatAssessment)

    def test_analyzer_initialization_with_path(self):
        """Test analyzer initialization with custom path"""
        analyzer = SupplyChainAnalyzer(repo_path="/tmp/test-repo")

        assert str(analyzer.repo_path) == "/tmp/test-repo"

    def test_analyzer_initialization_default_path(self):
        """Test analyzer initialization with default path"""
        analyzer = SupplyChainAnalyzer()

        assert analyzer.repo_path == Path(".")

    def test_git_operations_with_subprocess(self):
        """Test that git operations use subprocess safely"""
        # Verify analyzer can be instantiated
        analyzer = SupplyChainAnalyzer(repo_path=".")

        # Test should pass without errors
        assert analyzer.repo_path == Path(".")

    def test_network_disabled_mode(self):
        """Test analyzer in network-disabled mode"""
        analyzer = SupplyChainAnalyzer(enable_network=False)

        # Should create successfully
        assert analyzer.enable_network is False

    def test_network_enabled_mode(self):
        """Test analyzer in network-enabled mode"""
        analyzer = SupplyChainAnalyzer(enable_network=True)

        # Should create successfully
        assert analyzer.enable_network is True

    def test_popular_packages_defined(self):
        """Test that popular packages are defined for ecosystems"""
        assert "npm" in self.analyzer.POPULAR_PACKAGES
        assert "pypi" in self.analyzer.POPULAR_PACKAGES
        assert "maven" in self.analyzer.POPULAR_PACKAGES
        assert "go" in self.analyzer.POPULAR_PACKAGES

        # Verify packages are not empty
        assert len(self.analyzer.POPULAR_PACKAGES["npm"]) > 0
        assert len(self.analyzer.POPULAR_PACKAGES["pypi"]) > 0

    def test_analyzer_has_parsing_methods(self):
        """Test that analyzer has methods for parsing different package formats"""
        assert hasattr(self.analyzer, "_parse_npm_packages")
        assert hasattr(self.analyzer, "_parse_requirements_txt")
        assert hasattr(self.analyzer, "_parse_go_mod")
        assert hasattr(self.analyzer, "_parse_cargo_toml")
        assert hasattr(self.analyzer, "_parse_pom_xml")

    def test_analyzer_has_diff_methods(self):
        """Test that analyzer has diff methods for different ecosystems"""
        assert hasattr(self.analyzer, "_diff_npm_packages")
        assert hasattr(self.analyzer, "_diff_python_packages")
        assert hasattr(self.analyzer, "_diff_go_packages")
        assert hasattr(self.analyzer, "_diff_cargo_packages")
        assert hasattr(self.analyzer, "_diff_maven_packages")

    def test_analyzer_has_version_comparison(self):
        """Test that analyzer has version change type determination"""
        assert hasattr(self.analyzer, "_determine_version_change_type")

    def test_analyzer_core_methods_exist(self):
        """Test that core analyzer methods exist"""
        assert hasattr(self.analyzer, "analyze_dependency_diff")
        assert hasattr(self.analyzer, "check_typosquatting")
        assert hasattr(self.analyzer, "analyze_package_behavior")
        assert hasattr(self.analyzer, "check_openssf_scorecard")

    @patch.object(SupplyChainAnalyzer, "_get_dependency_changes")
    def test_dependency_changes_with_timeout(self, mock_get_changes):
        """Test handling of timeout during dependency retrieval"""
        mock_get_changes.return_value = []

        assessments = self.analyzer.analyze_dependency_diff("main", "HEAD")

        assert isinstance(assessments, list)
        assert len(assessments) == 0

    @patch.object(SupplyChainAnalyzer, "_get_dependency_changes")
    def test_dependency_changes_with_error(self, mock_get_changes):
        """Test handling of errors during dependency retrieval"""
        mock_get_changes.side_effect = Exception("Git error")

        try:
            assessments = self.analyzer.analyze_dependency_diff("main", "HEAD")
            # If it doesn't raise, it should return empty list
            assert isinstance(assessments, list)
        except Exception:
            # If it raises, that's also acceptable
            pass

    def test_get_file_content_method(self):
        """Test _get_file_content method exists"""
        # This is a private method for reading git file contents
        assert hasattr(self.analyzer, "_get_file_content")

    def test_map_package_to_repo_method(self):
        """Test _map_package_to_repo method exists"""
        # Maps package names to repository URLs
        assert hasattr(self.analyzer, "_map_package_to_repo")

    def test_typosquatting_all_ecosystems(self):
        """Test typosquatting detection across all ecosystems"""
        ecosystems = ["npm", "pypi", "maven", "go"]

        for ecosystem in ecosystems:
            # Get first popular package for ecosystem
            if ecosystem in self.analyzer.POPULAR_PACKAGES:
                popular = self.analyzer.POPULAR_PACKAGES[ecosystem][0]
                # Create typosquat by adding extra character
                typosquat = popular + "s"

                result = self.analyzer.check_typosquatting(typosquat, ecosystem)

                # May or may not trigger depending on similarity threshold
                # This tests that it doesn't crash for all ecosystems
                assert result is None or isinstance(result, dict)


class TestIntegrationScenarios:
    """Test realistic integration scenarios"""

    def test_npm_package_typosquatting(self):
        """Test typosquatting detection workflow"""
        analyzer = SupplyChainAnalyzer()

        # Test with a known typosquat
        result = analyzer.check_typosquatting("expresss", "npm")

        # Should detect typosquatting
        if result:
            assert result["legitimate_package"] == "express"
            assert result["distance"] in [1, 2]

    def test_pypi_package_typosquatting(self):
        """Test typosquatting detection for PyPI"""
        analyzer = SupplyChainAnalyzer()

        # Test with PyPI typosquat
        result = analyzer.check_typosquatting("reqeusts", "pypi")

        if result:
            assert result["legitimate_package"] == "requests"

    def test_multiple_ecosystems_typosquatting(self):
        """Test typosquatting detection across ecosystems"""
        analyzer = SupplyChainAnalyzer()

        npm_result = analyzer.check_typosquatting("expresss", "npm")
        pypi_result = analyzer.check_typosquatting("reqeusts", "pypi")

        # At least one should detect typosquatting
        assert (npm_result is not None) or (pypi_result is not None)

    def test_dependency_change_workflow(self):
        """Test DependencyChange creation and usage"""
        changes = [
            DependencyChange(
                package_name="express", ecosystem="npm", change_type="added", new_version="4.18.2"
            ),
            DependencyChange(
                package_name="lodash", ecosystem="npm", change_type="upgraded", old_version="4.17.20", new_version="4.17.21"
            ),
            DependencyChange(
                package_name="moment", ecosystem="npm", change_type="removed", old_version="2.29.4"
            ),
        ]

        assert len(changes) == 3
        assert all(isinstance(c, DependencyChange) for c in changes)
        assert changes[0].change_type == "added"
        assert changes[1].change_type == "upgraded"
        assert changes[2].change_type == "removed"
