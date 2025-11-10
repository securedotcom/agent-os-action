"""Unit tests for file selection logic"""

import pytest
from run_ai_audit import estimate_cost, matches_glob_patterns


class TestFileSelection:
    """Test suite for file selection functionality"""

    def test_matches_glob_patterns_single(self):
        """Test glob pattern matching with single pattern"""
        patterns = ["*.py"]
        assert matches_glob_patterns("test.py", patterns) is True
        assert matches_glob_patterns("test.js", patterns) is False

    def test_matches_glob_patterns_multiple(self):
        """Test glob pattern matching with multiple patterns"""
        patterns = ["*.py", "*.js", "*.ts"]
        assert matches_glob_patterns("test.py", patterns) is True
        assert matches_glob_patterns("test.js", patterns) is True
        assert matches_glob_patterns("test.ts", patterns) is True
        assert matches_glob_patterns("test.txt", patterns) is False

    def test_matches_glob_patterns_wildcard(self):
        """Test glob pattern matching with wildcards"""
        # ** requires at least one directory level, so src/main.py won't match src/**/*.py
        patterns = ["src/**/*.py"]
        assert matches_glob_patterns("src/main.py", patterns) is False  # No subdirectory
        assert matches_glob_patterns("src/utils/helper.py", patterns) is True  # Has subdirectory
        assert matches_glob_patterns("test/main.py", patterns) is False

        # Test pattern that matches both
        patterns_flexible = ["src/**"]
        assert matches_glob_patterns("src/main.py", patterns_flexible) is True
        assert matches_glob_patterns("src/utils/helper.py", patterns_flexible) is True

    def test_matches_glob_patterns_empty(self):
        """Test glob pattern matching with empty patterns"""
        assert matches_glob_patterns("test.py", []) is False
        assert matches_glob_patterns("test.py", None) is False

    def test_estimate_cost_anthropic(self, sample_files):
        """Test cost estimation for Anthropic"""
        cost, input_tokens, output_tokens = estimate_cost(sample_files, 8000, "anthropic")

        assert input_tokens > 0
        assert output_tokens == 8000
        assert cost > 0
        # Anthropic: $3/1M input, $15/1M output
        expected_cost = (input_tokens / 1_000_000) * 3.0 + (output_tokens / 1_000_000) * 15.0
        assert pytest.approx(cost, 0.001) == expected_cost

    def test_estimate_cost_openai(self, sample_files):
        """Test cost estimation for OpenAI"""
        cost, input_tokens, output_tokens = estimate_cost(sample_files, 8000, "openai")

        assert input_tokens > 0
        assert output_tokens == 8000
        assert cost > 0
        # OpenAI: $10/1M input, $30/1M output
        expected_cost = (input_tokens / 1_000_000) * 10.0 + (output_tokens / 1_000_000) * 30.0
        assert pytest.approx(cost, 0.001) == expected_cost

    def test_estimate_cost_ollama(self, sample_files):
        """Test cost estimation for Ollama (free)"""
        cost, input_tokens, output_tokens = estimate_cost(sample_files, 8000, "ollama")

        assert input_tokens > 0
        assert output_tokens == 8000
        assert cost == 0.0
