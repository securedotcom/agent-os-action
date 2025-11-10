"""Unit tests for ThreatModelGenerator class"""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add scripts directory to path for imports
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from threat_model_generator import ThreatModelGenerator


class TestThreatModelGenerator:
    """Test suite for ThreatModelGenerator class"""

    @pytest.fixture
    def api_key(self):
        """Mock API key for testing"""
        return "sk-ant-test-key"

    @pytest.fixture
    def mock_anthropic_client(self):
        """Mock Anthropic client"""
        with patch("threat_model_generator.Anthropic") as mock:
            yield mock

    @pytest.fixture
    def temp_repo(self, tmp_path):
        """Create a temporary test repository"""
        repo = tmp_path / "test-repo"
        repo.mkdir()

        # Create some test files
        (repo / "README.md").write_text("# Test Repository\nA sample project")
        (repo / "package.json").write_text('{"name": "test", "dependencies": {"react": "^18.0.0"}}')

        src = repo / "src"
        src.mkdir()
        (src / "app.js").write_text("console.log('Hello');")
        (src / "api.py").write_text("def handler(): pass")

        return repo

    def test_initialization(self, api_key, mock_anthropic_client):
        """Test ThreatModelGenerator initialization"""
        generator = ThreatModelGenerator(api_key)
        assert generator.client is not None
        mock_anthropic_client.assert_called_once_with(api_key=api_key)

    def test_analyze_repository_basic(self, api_key, mock_anthropic_client, temp_repo):
        """Test basic repository analysis"""
        generator = ThreatModelGenerator(api_key)
        context = generator.analyze_repository(str(temp_repo))

        assert context["name"] == "test-repo"
        assert context["path"] == str(temp_repo)
        assert len(context["languages"]) > 0
        assert len(context["key_files"]) >= 2  # README.md and package.json
        assert len(context["file_tree"]) > 0

    def test_analyze_repository_detects_languages(self, api_key, mock_anthropic_client, temp_repo):
        """Test language detection"""
        generator = ThreatModelGenerator(api_key)
        context = generator.analyze_repository(str(temp_repo))

        # Should detect JavaScript and Python
        assert "JavaScript" in context["languages"]
        assert "Python" in context["languages"]

    def test_analyze_repository_detects_frameworks(self, api_key, mock_anthropic_client, temp_repo):
        """Test framework detection"""
        generator = ThreatModelGenerator(api_key)
        context = generator.analyze_repository(str(temp_repo))

        # Should detect React from package.json
        assert "React" in context["frameworks"]

    def test_analyze_repository_finds_key_files(self, api_key, mock_anthropic_client, temp_repo):
        """Test key file identification"""
        generator = ThreatModelGenerator(api_key)
        context = generator.analyze_repository(str(temp_repo))

        key_file_names = [kf["name"] for kf in context["key_files"]]
        assert "README.md" in key_file_names
        assert "package.json" in key_file_names

    def test_analyze_repository_skips_ignored_dirs(self, api_key, mock_anthropic_client, temp_repo):
        """Test that ignored directories are skipped"""
        # Create directories that should be ignored
        (temp_repo / "node_modules").mkdir()
        (temp_repo / "node_modules" / "test.js").write_text("ignored")
        (temp_repo / ".git").mkdir()
        (temp_repo / ".git" / "config").write_text("ignored")

        generator = ThreatModelGenerator(api_key)
        context = generator.analyze_repository(str(temp_repo))

        # Check that ignored files are not in file tree
        file_paths = [str(Path(f)) for f in context["file_tree"]]
        assert not any("node_modules" in p for p in file_paths)
        assert not any(".git" in p for p in file_paths)

    def test_detect_frameworks_python(self, api_key, mock_anthropic_client):
        """Test Python framework detection"""
        generator = ThreatModelGenerator(api_key)
        context = {
            "frameworks": set(),
            "technologies": set(),
            "key_files": [{"name": "requirements.txt", "content": "django==4.0\nflask==2.0\npytest==7.0"}],
        }

        generator._detect_frameworks(context)

        assert "Django" in context["frameworks"]
        assert "Flask" in context["frameworks"]
        assert "pytest" in context["technologies"]

    def test_detect_frameworks_javascript(self, api_key, mock_anthropic_client):
        """Test JavaScript framework detection"""
        generator = ThreatModelGenerator(api_key)
        context = {
            "frameworks": set(),
            "technologies": set(),
            "key_files": [
                {
                    "name": "package.json",
                    "content": '{"dependencies": {"react": "^18.0", "next": "^13.0", "express": "^4.0"}}',
                }
            ],
        }

        generator._detect_frameworks(context)

        assert "React" in context["frameworks"]
        assert "Next.js" in context["frameworks"]
        assert "Express" in context["frameworks"]

    def test_detect_technologies_database(self, api_key, mock_anthropic_client):
        """Test database technology detection"""
        generator = ThreatModelGenerator(api_key)
        context = {
            "frameworks": set(),
            "technologies": set(),
            "key_files": [{"name": "package.json", "content": "postgresql mongodb redis mysql"}],
        }

        generator._detect_frameworks(context)

        assert "PostgreSQL" in context["technologies"]
        assert "MongoDB" in context["technologies"]
        assert "Redis" in context["technologies"]
        assert "MySQL" in context["technologies"]

    def test_generate_threat_model_success(self, api_key, mock_anthropic_client):
        """Test successful threat model generation"""
        # Mock the API response
        mock_message = Mock()
        mock_message.content = [
            Mock(
                text=json.dumps(
                    {
                        "attack_surface": {
                            "entry_points": ["API endpoint"],
                            "external_dependencies": ["npm"],
                            "authentication_methods": ["JWT"],
                            "data_stores": ["PostgreSQL"],
                        },
                        "trust_boundaries": [
                            {"name": "Public API", "trust_level": "untrusted", "description": "External"}
                        ],
                        "assets": [{"name": "User data", "sensitivity": "high", "description": "PII"}],
                        "threats": [
                            {
                                "id": "THREAT-001",
                                "name": "SQL Injection",
                                "category": "injection",
                                "likelihood": "high",
                                "impact": "critical",
                                "affected_components": ["database"],
                                "description": "Test threat",
                                "mitigation": "Use parameterized queries",
                            }
                        ],
                        "security_objectives": ["Protect data"],
                    }
                )
            )
        ]
        mock_message.usage = Mock(input_tokens=1000, output_tokens=500)

        mock_client = Mock()
        mock_client.messages.create.return_value = mock_message
        mock_anthropic_client.return_value = mock_client

        generator = ThreatModelGenerator(api_key)
        repo_context = {
            "name": "test-repo",
            "languages": ["Python"],
            "frameworks": ["Django"],
            "technologies": ["PostgreSQL"],
            "key_files": [],
            "file_tree": [],
        }

        threat_model = generator.generate_threat_model(repo_context)

        assert threat_model["version"] == "1.0"
        assert threat_model["repository"] == "test-repo"
        assert "generated_at" in threat_model
        assert len(threat_model["threats"]) == 1
        assert threat_model["threats"][0]["id"] == "THREAT-001"

    def test_generate_threat_model_json_error(self, api_key, mock_anthropic_client):
        """Test threat model generation with JSON parsing error"""
        # Mock API response with invalid JSON
        mock_message = Mock()
        mock_message.content = [Mock(text="Invalid JSON response")]
        mock_message.usage = Mock(input_tokens=1000, output_tokens=500)

        mock_client = Mock()
        mock_client.messages.create.return_value = mock_message
        mock_anthropic_client.return_value = mock_client

        generator = ThreatModelGenerator(api_key)
        repo_context = {
            "name": "test-repo",
            "languages": ["Python"],
            "frameworks": [],
            "technologies": [],
            "key_files": [],
            "file_tree": [],
        }

        # Should return fallback threat model
        threat_model = generator.generate_threat_model(repo_context)

        assert threat_model["version"] == "1.0"
        assert threat_model["repository"] == "test-repo"
        assert len(threat_model["threats"]) >= 1  # At least one generic threat

    def test_save_threat_model(self, api_key, mock_anthropic_client, tmp_path):
        """Test saving threat model to file"""
        generator = ThreatModelGenerator(api_key)
        threat_model = {"version": "1.0", "repository": "test", "threats": []}

        output_path = tmp_path / "threat-model.json"
        generator.save_threat_model(threat_model, str(output_path))

        assert output_path.exists()
        with open(output_path, "r") as f:
            loaded = json.load(f)
        assert loaded["version"] == "1.0"
        assert loaded["repository"] == "test"

    def test_load_existing_threat_model(self, api_key, mock_anthropic_client, tmp_path):
        """Test loading existing threat model"""
        generator = ThreatModelGenerator(api_key)

        # Create a threat model file
        threat_model = {"version": "1.0", "repository": "test", "threats": []}
        output_path = tmp_path / "threat-model.json"
        with open(output_path, "w") as f:
            json.dump(threat_model, f)

        # Load it
        loaded = generator.load_existing_threat_model(str(output_path))

        assert loaded is not None
        assert loaded["version"] == "1.0"
        assert loaded["repository"] == "test"

    def test_load_existing_threat_model_not_found(self, api_key, mock_anthropic_client, tmp_path):
        """Test loading non-existent threat model"""
        generator = ThreatModelGenerator(api_key)
        output_path = tmp_path / "nonexistent.json"

        loaded = generator.load_existing_threat_model(str(output_path))

        assert loaded is None

    def test_create_fallback_threat_model(self, api_key, mock_anthropic_client):
        """Test fallback threat model creation"""
        generator = ThreatModelGenerator(api_key)
        repo_context = {
            "name": "test-repo",
            "languages": ["Python"],
            "frameworks": ["Django"],
            "technologies": ["PostgreSQL"],
        }

        threat_model = generator._create_fallback_threat_model(repo_context)

        assert threat_model["version"] == "1.0"
        assert threat_model["repository"] == "test-repo"
        assert "generated_at" in threat_model
        assert len(threat_model["threats"]) >= 1
        assert len(threat_model["trust_boundaries"]) >= 1
        assert len(threat_model["assets"]) >= 1

    def test_update_threat_model(self, api_key, mock_anthropic_client):
        """Test updating existing threat model"""
        # Mock API response
        mock_message = Mock()
        mock_message.content = [
            Mock(
                text=json.dumps(
                    {
                        "attack_surface": {
                            "entry_points": [],
                            "external_dependencies": [],
                            "authentication_methods": [],
                            "data_stores": [],
                        },
                        "trust_boundaries": [],
                        "assets": [],
                        "threats": [],
                        "security_objectives": [],
                    }
                )
            )
        ]
        mock_message.usage = Mock(input_tokens=1000, output_tokens=500)

        mock_client = Mock()
        mock_client.messages.create.return_value = mock_message
        mock_anthropic_client.return_value = mock_client

        generator = ThreatModelGenerator(api_key)

        existing = {"version": "1.0", "repository": "old"}
        new_context = {
            "name": "new-repo",
            "languages": [],
            "frameworks": [],
            "technologies": [],
            "key_files": [],
            "file_tree": [],
        }

        updated = generator.update_threat_model(existing, new_context)

        # For now, update regenerates the threat model
        assert updated["repository"] == "new-repo"


class TestReviewMetricsThreatModel:
    """Test threat model metrics integration"""

    def test_record_threat_model(self):
        """Test recording threat model metrics"""
        # Import from run_ai_audit
        sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
        from run_ai_audit import ReviewMetrics

        metrics = ReviewMetrics()
        threat_model = {
            "threats": [{"id": "T1"}, {"id": "T2"}, {"id": "T3"}],
            "attack_surface": {"entry_points": ["API1", "API2", "API3", "API4"]},
            "trust_boundaries": [{"name": "B1"}, {"name": "B2"}],
            "assets": [{"name": "A1"}, {"name": "A2"}, {"name": "A3"}],
        }

        metrics.record_threat_model(threat_model)

        assert metrics.metrics["threat_model"]["generated"] is True
        assert metrics.metrics["threat_model"]["threats_identified"] == 3
        assert metrics.metrics["threat_model"]["attack_surface_size"] == 4
        assert metrics.metrics["threat_model"]["trust_boundaries"] == 2
        assert metrics.metrics["threat_model"]["assets_cataloged"] == 3

    def test_threat_model_metrics_initialization(self):
        """Test that threat model metrics are initialized"""
        sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
        from run_ai_audit import ReviewMetrics

        metrics = ReviewMetrics()

        assert "threat_model" in metrics.metrics
        assert metrics.metrics["threat_model"]["generated"] is False
        assert metrics.metrics["threat_model"]["threats_identified"] == 0
        assert metrics.metrics["threat_model"]["attack_surface_size"] == 0
        assert metrics.metrics["threat_model"]["trust_boundaries"] == 0
        assert metrics.metrics["threat_model"]["assets_cataloged"] == 0
