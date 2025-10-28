# Quick Start Guide - v1.0.15

## ⚡ What Changed?

All critical and high-priority issues from the code review have been fixed! Here's what's new:

### ✅ Fixed
- Repository references in workflows (now uses correct repo)
- Version inconsistencies (all files now v1.0.15)
- Security issues (all GitHub Actions pinned by SHA)
- Error handling (retry logic + structured logging)

### 🎉 Added
- Complete test suite (pytest with 70%+ coverage target)
- Code quality tools (black, pylint, mypy)
- Pre-commit hooks
- CI/CD pipeline for tests
- Comprehensive documentation (CHANGELOG, ADRs)

---

## 🚀 Get Started in 3 Steps

### Step 1: Install Dependencies
```bash
# Navigate to the project directory
cd agent-os

# Install with dev dependencies
pip install -e ".[dev]"

# Or install manually
pip install anthropic openai tenacity pytest pytest-cov black pylint mypy pre-commit
```

### Step 2: Set Up Development Environment
```bash
# Install pre-commit hooks (runs on every commit)
pre-commit install

# Verify installation
pre-commit run --all-files
```

### Step 3: Run Tests
```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=scripts --cov-report=html

# Open coverage report
open htmlcov/index.html  # macOS
```

---

## 🔍 Quick Commands

### Testing
```bash
pytest                          # Run all tests
pytest -v                       # Verbose output
pytest tests/unit/              # Unit tests only
pytest tests/integration/       # Integration tests only
pytest --cov=scripts            # With coverage
```

### Code Quality
```bash
black scripts/ tests/           # Format code
black --check scripts/          # Check formatting
pylint scripts/*.py             # Run linter
mypy scripts/*.py               # Type checking
pre-commit run --all-files      # Run all checks
```

### Development
```bash
# Make changes to code
vim scripts/run-ai-audit.py

# Run tests
pytest

# Format code
black scripts/

# Commit (pre-commit runs automatically)
git add .
git commit -m "Your message"
```

---

## 📊 What to Review

### Key New Files
1. **pyproject.toml** - Modern Python project configuration
2. **tests/** - Complete test suite
3. **CHANGELOG.md** - Version history (see v1.0.15 section)
4. **docs/ADRs/** - Architecture decisions
5. **.github/workflows/tests.yml** - CI pipeline

### Modified Files
1. **README.md** - Updated version badge
2. **scripts/run-ai-audit.py** - Added logging & retry logic
3. **.github/workflows/automated-audit.yml** - Fixed repo ref, pinned actions
4. **.github/workflows/code-review.yml** - Pinned actions, added disclaimer

---

## ✨ New Features You Can Use

### 1. Retry Logic
LLM API calls now automatically retry on transient failures:
```python
# Automatically retries up to 3 times with exponential backoff
# Handles ConnectionError, TimeoutError
call_llm_api(client, provider, model, prompt, max_tokens)
```

### 2. Structured Logging
Better error messages and debugging:
```python
import logging
logger = logging.getLogger(__name__)
logger.info("Found 5 changed files")
logger.warning("Git diff timed out")
logger.error("LLM API call failed: RateLimitError")
```

### 3. Pre-commit Hooks
Automatic code quality checks on commit:
- Trailing whitespace removal
- End-of-file fixer
- YAML/JSON validation
- Black formatting
- Pylint linting
- Mypy type checking

### 4. CI/CD Pipeline
Tests run automatically on:
- Push to main/develop
- Pull requests
- Manual dispatch

View at: https://github.com/YOUR-ORG/agent-os/actions

---

## 🎯 Next Actions

### Immediate (Do Now)
1. ✅ Install dependencies: `pip install -e ".[dev]"`
2. ✅ Install pre-commit: `pre-commit install`
3. ✅ Run tests: `pytest`
4. ✅ Review changes: `git status`

### Soon (This Week)
1. ⭐ Review CHANGELOG.md for all changes
2. ⭐ Read ADRs in docs/ADRs/
3. ⭐ Check test coverage: `pytest --cov=scripts --cov-report=html`
4. ⭐ Review docs/IMPROVEMENTS-v1.0.15.md

### Later (This Month)
1. 📝 Write more tests (target 70%+ coverage)
2. 📝 Add type hints to functions
3. 📝 Fix any pylint warnings
4. 📝 Add performance benchmarks

---

## 📚 Documentation Map

| Document | Purpose |
|----------|---------|
| `README.md` | Main project documentation |
| `CHANGELOG.md` | Version history (see v1.0.15) |
| `QUICK-START-v1.0.15.md` | This file - quick reference |
| `docs/IMPROVEMENTS-v1.0.15.md` | Detailed improvements summary |
| `docs/ADRs/` | Architecture decisions |
| `tests/README.md` | Testing guide |

---

## 🔧 Troubleshooting

### "Module not found" errors
```bash
pip install -e ".[dev]"
```

### Pre-commit hook failures
```bash
# Fix formatting issues
black scripts/ tests/

# Run checks
pre-commit run --all-files
```

### Test failures
```bash
# Run in verbose mode
pytest -v

# Run specific test
pytest tests/unit/test_metrics.py -v
```

---

## 📞 Getting Help

- **Issues**: Open an issue on GitHub
- **Docs**: Check `docs/` directory
- **Tests**: See `tests/README.md`
- **Improvements**: Read `docs/IMPROVEMENTS-v1.0.15.md`

---

## ✅ Success Checklist

- [ ] Dependencies installed
- [ ] Pre-commit hooks set up
- [ ] All tests passing
- [ ] Coverage report generated
- [ ] Reviewed CHANGELOG.md
- [ ] Reviewed key ADRs
- [ ] Understand new error handling
- [ ] Know how to run quality checks

---

**Version**: 1.0.15
**Date**: January 28, 2025
**Status**: ✅ Production Ready
