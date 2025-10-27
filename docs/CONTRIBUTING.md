# Contributing to Agent OS Code Reviewer

Thank you for your interest in contributing to Agent OS! This document provides guidelines and instructions for contributing to the project.

---

## 🎯 Ways to Contribute

### 1. Report Bugs 🐛
Found a bug? Help us fix it!

### 2. Suggest Features 💡
Have an idea? We'd love to hear it!

### 3. Improve Documentation 📝
Documentation can always be better!

### 4. Submit Code 🔧
Want to fix a bug or add a feature? Awesome!

### 5. Share Your Experience 📣
Write a blog post, create a video, or share on social media!

---

## 🐛 Reporting Bugs

### Before Reporting

1. **Search existing issues** - Your bug might already be reported
2. **Check documentation** - Make sure it's not expected behavior
3. **Try latest version** - Bug might already be fixed

### Bug Report Template

```markdown
**Description**
A clear description of the bug.

**To Reproduce**
Steps to reproduce the behavior:
1. Go to '...'
2. Click on '....'
3. See error

**Expected Behavior**
What you expected to happen.

**Actual Behavior**
What actually happened.

**Environment**
- OS: [e.g., Ubuntu 22.04]
- GitHub Actions Runner: [e.g., ubuntu-latest]
- Agent OS Version: [e.g., v1.0.14]
- Node Version: [e.g., 18.x]

**Logs**
```
Paste relevant logs here
```

**Additional Context**
Any other information about the problem.
```

### Where to Report

Open an issue: https://github.com/securedotcom/agent-os-action/issues/new

---

## 💡 Suggesting Features

### Before Suggesting

1. **Check roadmap** - Feature might already be planned
2. **Search discussions** - Someone might have suggested it
3. **Consider scope** - Does it fit the project's goals?

### Feature Request Template

```markdown
**Problem Statement**
What problem does this feature solve?

**Proposed Solution**
How would you like it to work?

**Alternatives Considered**
What other solutions have you considered?

**Use Cases**
Who would benefit from this feature?

**Additional Context**
Mockups, examples, or references.
```

### Where to Suggest

Start a discussion: https://github.com/securedotcom/agent-os-action/discussions/new

---

## 📝 Improving Documentation

Documentation improvements are always welcome!

### What to Improve

- Fix typos or grammar
- Add missing information
- Clarify confusing sections
- Add examples
- Create tutorials
- Add screenshots or diagrams

### How to Contribute Docs

1. Fork the repository
2. Edit the markdown files
3. Submit a pull request
4. No need for local testing - just edit on GitHub!

### Documentation Standards

- Use clear, simple language
- Include code examples
- Add screenshots where helpful
- Link to related documentation
- Test all commands and code snippets

---

## 🔧 Contributing Code

### Development Setup

#### Prerequisites

- Git
- GitHub account
- Text editor (VS Code recommended)
- Basic knowledge of:
  - Bash scripting
  - Python
  - YAML
  - GitHub Actions

#### Fork and Clone

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/agent-os-action.git
cd agent-os-action

# Add upstream remote
git remote add upstream https://github.com/securedotcom/agent-os-action.git
```

#### Create a Branch

```bash
# Update main
git checkout main
git pull upstream main

# Create feature branch
git checkout -b feature/your-feature-name
```

### Project Structure

```
agent-os-action/
├── action.yml                 # Main action definition
├── config.yml                 # Configuration
├── scripts/
│   ├── run-ai-audit.py       # Main analysis script
│   ├── detect-project-type.sh # Project detection
│   └── ...
├── profiles/default/
│   ├── agents/               # AI reviewer profiles
│   ├── standards/            # Review checklists
│   ├── workflows/            # Review workflows
│   └── commands/             # Command definitions
├── docs/                     # Documentation
├── examples/                 # Example files
└── README.md
```

### Coding Standards

#### Bash Scripts

```bash
#!/bin/bash
# Use strict mode
set -euo pipefail

# Add comments for complex logic
# Use descriptive variable names
# Quote all variables: "$variable"
# Use functions for reusable code
```

#### Python Scripts

```python
"""Module docstring."""

# Follow PEP 8
# Use type hints
# Add docstrings to functions
# Handle errors gracefully
# Keep functions small and focused

def function_name(param: str) -> bool:
    """Function docstring.
    
    Args:
        param: Description
        
    Returns:
        Description
    """
    pass
```

#### YAML Files

```yaml
# Use 2 spaces for indentation
# Add comments for complex sections
# Keep lines under 100 characters
# Use descriptive names

name: Descriptive Name

on:
  workflow_dispatch:  # Comment explaining when this runs
```

### Testing Your Changes

#### Test Locally (Limited)

```bash
# Test bash scripts
bash scripts/detect-project-type.sh

# Test Python scripts
python3 scripts/run-ai-audit.py /path/to/test/repo
```

#### Test in GitHub Actions

1. Push to your fork
2. Create a test repository
3. Add workflow using your fork:
```yaml
uses: YOUR_USERNAME/agent-os-action@your-branch
```
4. Run workflow and verify

### Commit Guidelines

#### Commit Message Format

```
type(scope): short description

Longer description if needed.

Fixes #123
```

#### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

#### Examples

```bash
feat(security): add XSS detection to security reviewer

Added cross-site scripting detection to the security reviewer
agent. Now checks for unescaped user input in HTML contexts.

Fixes #45

---

fix(action): correct file path resolution

Fixed issue where action couldn't find scripts when running
from composite action context. Now uses $GITHUB_ACTION_PATH.

Fixes #67

---

docs(readme): add monorepo setup example

Added example workflow for monorepo setups showing how to
analyze multiple packages independently.
```

### Pull Request Process

#### Before Submitting

- [ ] Code follows project standards
- [ ] Tested changes (manually or in test repo)
- [ ] Updated documentation if needed
- [ ] Added/updated examples if needed
- [ ] Commit messages follow guidelines
- [ ] No merge conflicts with main

#### PR Template

```markdown
**Description**
What does this PR do?

**Motivation**
Why is this change needed?

**Changes**
- Change 1
- Change 2
- Change 3

**Testing**
How was this tested?

**Screenshots** (if applicable)
Add screenshots here.

**Checklist**
- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] Tests pass
- [ ] No breaking changes (or documented)

**Related Issues**
Fixes #123
Relates to #456
```

#### Review Process

1. **Automated Checks** - Must pass
2. **Code Review** - At least one approval required
3. **Testing** - Maintainer will test in real environment
4. **Merge** - Maintainer will merge when ready

#### After Merge

- Your changes will be in the next release
- You'll be added to contributors list
- Thank you! 🎉

---

## 🎨 Design Guidelines

### User Experience

- **Simple by default** - Easy for beginners
- **Powerful when needed** - Advanced options available
- **Clear feedback** - Users know what's happening
- **Helpful errors** - Error messages guide to solution

### API Design

- **Consistent naming** - Follow existing patterns
- **Sensible defaults** - Works out of the box
- **Backward compatible** - Don't break existing users
- **Well documented** - Clear examples and descriptions

---

## 🏗️ Architecture Decisions

### When Adding Features

Consider:
1. **Does it fit the project's goals?**
2. **Is it maintainable long-term?**
3. **Does it add complexity?**
4. **Are there simpler alternatives?**
5. **Will users actually use it?**

### When Making Changes

Consider:
1. **Is this a breaking change?**
2. **Can it be done backward-compatibly?**
3. **Does it affect performance?**
4. **Does it require new dependencies?**
5. **Is it well-tested?**

---

## 🧪 Testing Guidelines

### What to Test

- **Happy path** - Normal usage works
- **Error cases** - Handles errors gracefully
- **Edge cases** - Unusual inputs handled
- **Backward compatibility** - Doesn't break existing usage

### How to Test

1. **Manual Testing** - Run in test repository
2. **Integration Testing** - Full workflow in GitHub Actions
3. **User Testing** - Get feedback from real users

---

## 📚 Resources for Contributors

### Learning Resources

- **GitHub Actions**: https://docs.github.com/en/actions
- **Composite Actions**: https://docs.github.com/en/actions/creating-actions/creating-a-composite-action
- **Anthropic API**: https://docs.anthropic.com/
- **Bash Scripting**: https://www.gnu.org/software/bash/manual/
- **Python**: https://docs.python.org/3/

### Project Resources

- **Architecture**: [docs/ARCHITECTURE.md](ARCHITECTURE.md)
- **Troubleshooting**: [docs/TROUBLESHOOTING.md](TROUBLESHOOTING.md)
- **Examples**: [examples/](../examples/)

---

## 🤝 Community Guidelines

### Be Respectful

- Treat everyone with respect
- Welcome newcomers
- Be patient with questions
- Assume good intentions

### Be Helpful

- Answer questions when you can
- Share your knowledge
- Provide constructive feedback
- Help others learn

### Be Professional

- Keep discussions on-topic
- Avoid spam or self-promotion
- Respect maintainers' time
- Follow the code of conduct

---

## 🏆 Recognition

### Contributors

All contributors are recognized in:
- GitHub contributors page
- Release notes
- Project README (for significant contributions)

### Types of Contributions

We value all contributions:
- Code contributions
- Documentation improvements
- Bug reports
- Feature suggestions
- Community support
- Spreading the word

---

## 📞 Getting Help

### Questions?

- **Documentation**: Check [docs/](../docs/)
- **Discussions**: https://github.com/securedotcom/agent-os-action/discussions
- **Issues**: https://github.com/securedotcom/agent-os-action/issues

### Stuck?

Don't hesitate to ask for help! We're here to support you.

---

## 🗺️ Roadmap

### Current Focus (v1.1)

- OpenAI API support
- Improved error messages
- One-command setup
- Docker image

### Future Plans (v1.2+)

- Web dashboard
- IDE extensions
- Custom rules engine
- Local LLM support

See full roadmap in [README.md](../README.md#roadmap)

---

## 📜 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

## 🙏 Thank You!

Thank you for contributing to Agent OS Code Reviewer! Your contributions help make code reviews better for everyone.

**Questions?** Open a discussion!  
**Ready to contribute?** Fork the repo and get started!

---

**Last Updated**: October 27, 2025

