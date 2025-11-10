"""Pytest configuration and shared fixtures"""

import os
import sys
from collections.abc import Generator
from pathlib import Path

import pytest

# Add scripts directory to path for imports
scripts_dir = Path(__file__).parent.parent / "scripts"
if str(scripts_dir) not in sys.path:
    sys.path.insert(0, str(scripts_dir))


@pytest.fixture
def temp_repo(tmp_path: Path) -> Generator[Path, None, None]:
    """Create a temporary repository for testing"""
    repo_dir = tmp_path / "test_repo"
    repo_dir.mkdir()

    # Create sample files
    (repo_dir / "main.py").write_text("def hello():\n    print('Hello, World!')\n")
    (repo_dir / "config.js").write_text("const apiKey = 'sk-test-123';\n")

    yield repo_dir


@pytest.fixture
def mock_config() -> dict:
    """Mock configuration for tests"""
    return {
        "ai_provider": "anthropic",
        "anthropic_api_key": "test-key",
        "model": "claude-sonnet-4-5-20250929",
        "multi_agent_mode": "single",
        "only_changed": False,
        "include_paths": "",
        "exclude_paths": "",
        "max_file_size": "50000",
        "max_files": "50",
        "max_tokens": "8000",
        "cost_limit": "1.0",
        "fail_on": "",
    }


@pytest.fixture
def sample_files() -> list:
    """Sample file data for testing"""
    return [
        {"path": "src/main.py", "content": "def main():\n    pass\n", "lines": 2, "size": 20},
        {"path": "src/utils.py", "content": "def util():\n    pass\n", "lines": 2, "size": 20},
    ]


@pytest.fixture(autouse=True)
def reset_env():
    """Reset environment variables before each test"""
    original_env = os.environ.copy()
    yield
    os.environ.clear()
    os.environ.update(original_env)
