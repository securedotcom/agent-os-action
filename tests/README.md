# Agent OS Code Reviewer - Test Suite

This directory contains the test suite for the Agent OS Code Reviewer system.

## Structure

```
tests/
├── __init__.py              # Test package initialization
├── conftest.py              # Shared pytest fixtures and configuration
├── unit/                    # Unit tests
│   ├── test_metrics.py      # ReviewMetrics class tests
│   ├── test_ai_providers.py # AI provider detection and configuration tests
│   └── test_file_selection.py # File selection and cost estimation tests
├── integration/             # Integration tests
│   └── test_sarif_generation.py # SARIF report generation tests
└── README.md                # This file
```

## Running Tests

### Install Dependencies

```bash
# Install development dependencies
pip install -e ".[dev]"

# Or install dependencies directly
pip install pytest pytest-cov pytest-mock
```

### Run All Tests

```bash
# Run all tests with coverage
pytest

# Run with verbose output
pytest -v

# Run with coverage report
pytest --cov=scripts --cov-report=html
```

### Run Specific Test Categories

```bash
# Run only unit tests
pytest tests/unit/

# Run only integration tests
pytest tests/integration/

# Run specific test file
pytest tests/unit/test_metrics.py

# Run specific test class
pytest tests/unit/test_metrics.py::TestReviewMetrics

# Run specific test method
pytest tests/unit/test_metrics.py::TestReviewMetrics::test_initialization
```

### Run with Markers

```bash
# Run only fast tests (exclude slow tests)
pytest -m "not slow"

# Run only integration tests
pytest -m integration

# Run only unit tests
pytest -m unit
```

## Code Coverage

After running tests with coverage, open the HTML report:

```bash
# Generate coverage report
pytest --cov=scripts --cov-report=html

# Open in browser (macOS)
open htmlcov/index.html

# Open in browser (Linux)
xdg-open htmlcov/index.html
```

## Writing Tests

### Unit Tests

Unit tests should:
- Test individual functions and classes in isolation
- Use mocks for external dependencies
- Be fast and deterministic
- Have clear test names describing what they test

Example:
```python
def test_record_file_increments_counters():
    """Test that record_file increments file and line counters"""
    metrics = ReviewMetrics()
    metrics.record_file(100)

    assert metrics.metrics['files_reviewed'] == 1
    assert metrics.metrics['lines_analyzed'] == 100
```

### Integration Tests

Integration tests should:
- Test multiple components working together
- Use real file systems (via temp_repo fixture)
- Test end-to-end scenarios
- Be marked with `@pytest.mark.integration`

Example:
```python
@pytest.mark.integration
def test_audit_generates_reports(temp_repo):
    """Test that running audit generates all expected reports"""
    # Test implementation
```

## Fixtures

Common fixtures available in `conftest.py`:

- `temp_repo`: Creates a temporary repository with sample files
- `mock_config`: Provides mock configuration dictionary
- `sample_files`: Returns sample file data for testing
- `reset_env`: Automatically resets environment variables between tests

## Best Practices

1. **Isolation**: Tests should not depend on each other
2. **Clarity**: Use descriptive test names and docstrings
3. **Coverage**: Aim for 70%+ code coverage
4. **Speed**: Keep unit tests fast (<100ms each)
5. **Mocking**: Mock external API calls and file system operations where appropriate
6. **Fixtures**: Use fixtures for common test setup
7. **Assertions**: Use specific assertions with clear error messages

## Continuous Integration

Tests run automatically on:
- Every push to main/develop branches
- Every pull request
- Scheduled daily runs

See `.github/workflows/tests.yml` for CI configuration.
