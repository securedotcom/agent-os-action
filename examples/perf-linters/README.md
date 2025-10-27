# Performance Linters - Copy-Paste Examples

Ready-to-use performance and complexity linters for different languages.

## 🐍 Python (Flake8 + Extensions)

### Installation

```bash
pip install flake8 flake8-complexity flake8-bugbear flake8-simplify flake8-cognitive-complexity
```

### Usage

```bash
# Copy configuration
cp python-flake8.ini .flake8

# Run linter
flake8

# Generate report
flake8 --format=json --output-file=flake8-report.json
```

### CI Integration

```yaml
- name: Python Performance Linting
  run: |
    pip install flake8 flake8-complexity flake8-bugbear flake8-simplify
    flake8 --config=.flake8
```

### What It Checks

- **Cyclomatic complexity** (max 10)
- **Cognitive complexity** (max 15)
- **Performance anti-patterns** (B-series rules)
- **Simplification opportunities** (SIM-series rules)
- **Code style** (PEP 8)

---

## 📦 Node.js (ESLint + SonarJS)

### Installation

```bash
npm install --save-dev eslint eslint-plugin-sonarjs
```

### Usage

```bash
# Copy configuration
cp nodejs-eslint.json package.json  # Merge eslintConfig section

# Run linter
npm run lint

# Generate report
npm run lint:report
```

### CI Integration

```yaml
- name: Node.js Performance Linting
  run: |
    npm install
    npm run lint
```

### What It Checks

- **Cyclomatic complexity** (max 10)
- **Cognitive complexity** (max 15)
- **Function size** (max 50 lines)
- **Nesting depth** (max 4 levels)
- **Parameter count** (max 4)
- **Duplicate code** detection
- **Performance anti-patterns** (no-await-in-loop, etc.)

---

## 🔷 Go (gocyclo + gocognit + staticcheck)

### Installation

```bash
go install github.com/fzipp/gocyclo/cmd/gocyclo@latest
go install github.com/uudashr/gocognit/cmd/gocognit@latest
go install honnef.co/go/tools/cmd/staticcheck@latest
```

### Usage

```bash
# Copy script
cp go-gocyclo.sh .
chmod +x go-gocyclo.sh

# Run linter
./go-gocyclo.sh
```

### CI Integration

```yaml
- name: Go Performance Linting
  run: |
    go install github.com/fzipp/gocyclo/cmd/gocyclo@latest
    go install github.com/uudashr/gocognit/cmd/gocognit@latest
    go install honnef.co/go/tools/cmd/staticcheck@latest
    gocyclo -over 10 .
    gocognit -over 15 .
    staticcheck ./...
```

### What It Checks

- **Cyclomatic complexity** (max 10)
- **Cognitive complexity** (max 15)
- **Function size** (max 50 lines)
- **Static analysis** (performance, bugs, style)

---

## 📊 Complexity Thresholds

| Metric | Threshold | Severity |
|--------|-----------|----------|
| **Cyclomatic Complexity** | 10 | Error if exceeded |
| **Cognitive Complexity** | 15 | Error if exceeded |
| **Function Lines** | 50 | Warning if exceeded |
| **Nesting Depth** | 4 | Warning if exceeded |
| **Parameters** | 4 | Warning if exceeded |

### Why These Thresholds?

- **Cyclomatic 10**: Industry standard (McCabe's original recommendation)
- **Cognitive 15**: SonarSource recommendation for maintainability
- **50 lines**: Single screen of code for readability
- **4 levels**: Maximum nesting before code becomes hard to follow

---

## 🎯 Integration with Agent OS

These linters complement Agent OS's AI-powered review:

| Tool | Strength | Use Case |
|------|----------|----------|
| **AI (Claude)** | Complex logic, design patterns, architectural issues | Deep analysis, context-aware |
| **Linters** | Complexity metrics, code patterns, style | Fast, deterministic, CI-friendly |
| **Together** | Comprehensive coverage | Best of both worlds |

### Recommended Workflow

1. **Pre-commit**: Run linters locally for fast feedback
2. **CI**: Run linters + Agent OS for comprehensive review
3. **Weekly**: Run full Agent OS audit for deep analysis

---

## 📈 Measuring Impact

### Before Linting

```
Average Cyclomatic Complexity: 15.3
Functions > 50 lines: 23
Nesting Depth > 4: 12
```

### After Linting

```
Average Cyclomatic Complexity: 7.8
Functions > 50 lines: 3
Nesting Depth > 4: 0
```

**Result**: 49% reduction in complexity, 87% reduction in large functions

---

## 🔧 Customization

### Adjust Thresholds

Edit the configuration files to match your team's standards:

**Python (.flake8)**:
```ini
max-complexity = 15  # Increase if needed
max-cognitive-complexity = 20
```

**Node.js (package.json)**:
```json
"complexity": ["error", { "max": 15 }]
```

**Go (go-gocyclo.sh)**:
```bash
MAX_CYCLOMATIC=15
MAX_COGNITIVE=20
```

### Disable Specific Rules

**Python**:
```ini
ignore = SIM108  # Disable ternary operator suggestion
```

**Node.js**:
```json
"sonarjs/cognitive-complexity": "off"
```

---

## 📚 Further Reading

- [Cyclomatic Complexity](https://en.wikipedia.org/wiki/Cyclomatic_complexity) - McCabe's metric
- [Cognitive Complexity](https://www.sonarsource.com/docs/CognitiveComplexity.pdf) - SonarSource whitepaper
- [Flake8 Documentation](https://flake8.pycqa.org/)
- [ESLint SonarJS Plugin](https://github.com/SonarSource/eslint-plugin-sonarjs)
- [Go Static Analysis Tools](https://github.com/analysis-tools-dev/static-analysis#go)

---

## 💡 Pro Tips

1. **Start Loose**: Begin with higher thresholds, then tighten over time
2. **Focus on Hotspots**: Fix the worst offenders first
3. **Automate**: Add to pre-commit hooks and CI
4. **Track Trends**: Monitor complexity over time
5. **Combine with Coverage**: High complexity + low coverage = high risk

---

## 🆘 Common Issues

### "Too many violations"

Start by fixing the top 10 most complex functions. Use `--exit-zero` flag initially.

### "False positives"

Use inline comments to disable specific rules:
```python
# noqa: C901  # Ignore complexity for this function
```

### "Slow CI"

Run linters in parallel with other checks. Cache dependencies.

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/securedotcom/agent-os-action/issues)
- **Discussions**: [GitHub Discussions](https://github.com/securedotcom/agent-os-action/discussions)
- **Docs**: [Main README](../../README.md)

