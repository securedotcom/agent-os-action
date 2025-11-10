"""Unit tests for ReviewMetrics class"""

import pytest
from run_ai_audit import ReviewMetrics


class TestReviewMetrics:
    """Test suite for ReviewMetrics class"""

    def test_initialization(self):
        """Test ReviewMetrics initialization"""
        metrics = ReviewMetrics()
        assert metrics.metrics["version"] == "1.0.16"
        assert metrics.metrics["files_reviewed"] == 0
        assert metrics.metrics["lines_analyzed"] == 0
        assert metrics.metrics["tokens_input"] == 0
        assert metrics.metrics["tokens_output"] == 0
        assert metrics.metrics["cost_usd"] == 0.0

    def test_record_file(self):
        """Test recording file metrics"""
        metrics = ReviewMetrics()
        metrics.record_file(100)
        metrics.record_file(200)

        assert metrics.metrics["files_reviewed"] == 2
        assert metrics.metrics["lines_analyzed"] == 300

    def test_record_llm_call_anthropic(self):
        """Test recording Anthropic LLM call"""
        metrics = ReviewMetrics()
        metrics.record_llm_call(1000, 500, "anthropic")

        # Anthropic: $3/1M input, $15/1M output
        expected_cost = (1000 / 1_000_000) * 3.0 + (500 / 1_000_000) * 15.0
        assert metrics.metrics["tokens_input"] == 1000
        assert metrics.metrics["tokens_output"] == 500
        assert pytest.approx(metrics.metrics["cost_usd"], 0.001) == expected_cost

    def test_record_llm_call_openai(self):
        """Test recording OpenAI LLM call"""
        metrics = ReviewMetrics()
        metrics.record_llm_call(1000, 500, "openai")

        # OpenAI: $10/1M input, $30/1M output
        expected_cost = (1000 / 1_000_000) * 10.0 + (500 / 1_000_000) * 30.0
        assert pytest.approx(metrics.metrics["cost_usd"], 0.001) == expected_cost

    def test_record_llm_call_ollama(self):
        """Test recording Ollama LLM call (free)"""
        metrics = ReviewMetrics()
        metrics.record_llm_call(1000, 500, "ollama")

        assert metrics.metrics["cost_usd"] == 0.0

    def test_record_finding(self):
        """Test recording findings"""
        metrics = ReviewMetrics()
        metrics.record_finding("critical", "security")
        metrics.record_finding("high", "performance")
        metrics.record_finding("medium", "testing")

        assert metrics.metrics["findings"]["critical"] == 1
        assert metrics.metrics["findings"]["high"] == 1
        assert metrics.metrics["findings"]["medium"] == 1
        assert metrics.metrics["categories"]["security"] == 1
        assert metrics.metrics["categories"]["performance"] == 1
        assert metrics.metrics["categories"]["testing"] == 1

    def test_finalize(self):
        """Test finalizing metrics"""
        metrics = ReviewMetrics()
        result = metrics.finalize()

        assert "duration_seconds" in result
        assert result["duration_seconds"] >= 0
