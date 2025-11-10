"""
Shared fixtures for integration tests
"""

import json
import os
from collections.abc import Generator
from pathlib import Path

import pytest


@pytest.fixture
def sample_vulnerable_repo(tmp_path: Path) -> Generator[Path, None, None]:
    """Create a repository with known vulnerabilities for testing"""
    repo_dir = tmp_path / "vulnerable_repo"
    repo_dir.mkdir()

    # SQL Injection vulnerabilities
    (repo_dir / "sql_injection.py").write_text(
        '''
"""Module with SQL injection vulnerabilities"""

def search_users(name):
    # VULNERABLE: String interpolation in SQL
    query = f"SELECT * FROM users WHERE name = '{name}'"
    return db.execute(query)

def get_user_by_id(user_id):
    # VULNERABLE: String formatting in SQL
    query = "SELECT * FROM users WHERE id = %s" % user_id
    return db.execute(query)

def login(username, password):
    # VULNERABLE: Concatenation in SQL
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    return db.execute(query)
'''
    )

    # XSS vulnerabilities
    (repo_dir / "xss_vuln.js").write_text(
        """
// Module with XSS vulnerabilities

function displayUserMessage(msg) {
    // VULNERABLE: Direct innerHTML assignment
    document.getElementById('output').innerHTML = msg;
}

function showNotification(text) {
    // VULNERABLE: document.write with user input
    document.write(text);
}

function renderTemplate(data) {
    // VULNERABLE: eval with user data
    eval("var result = " + data);
    return result;
}
"""
    )

    # Command Injection vulnerabilities
    (repo_dir / "command_injection.py").write_text(
        '''
"""Module with command injection vulnerabilities"""
import os
import subprocess

def ping_host(hostname):
    # VULNERABLE: os.system with user input
    os.system(f"ping -c 1 {hostname}")

def run_script(script_name):
    # VULNERABLE: shell=True with user input
    subprocess.call("bash " + script_name, shell=True)

def check_file(filename):
    # VULNERABLE: os.popen with user input
    output = os.popen(f"cat {filename}").read()
    return output
'''
    )

    # Path Traversal vulnerability
    (repo_dir / "path_traversal.py").write_text(
        '''
"""Module with path traversal vulnerability"""

def read_user_file(filename):
    # VULNERABLE: No path validation
    with open(f"/data/{filename}", 'r') as f:
        return f.read()

def serve_file(filepath):
    # VULNERABLE: Direct file access
    return open(filepath).read()
'''
    )

    # Hardcoded credentials
    (repo_dir / "credentials.py").write_text(
        '''
"""Module with hardcoded credentials"""

# VULNERABLE: Hardcoded credentials
DATABASE_PASSWORD = "supersecret123"
API_KEY = "sk-1234567890abcdef"
AWS_SECRET = "aws_secret_key_12345"

def connect_to_db():
    return db.connect(password="hardcoded_password")
'''
    )

    # Insecure deserialization
    (repo_dir / "deserialization.py").write_text(
        '''
"""Module with insecure deserialization"""
import pickle
import yaml

def load_user_data(data):
    # VULNERABLE: pickle.loads on untrusted data
    return pickle.loads(data)

def parse_config(yaml_str):
    # VULNERABLE: yaml.load without Loader
    return yaml.load(yaml_str)
'''
    )

    # Safe file for comparison
    (repo_dir / "safe_module.py").write_text(
        '''
"""Module with safe code"""

def safe_function(data):
    """Safe data processing"""
    cleaned = data.strip().lower()
    return cleaned.capitalize()

def validate_input(user_input):
    """Proper input validation"""
    allowed_chars = set('abcdefghijklmnopqrstuvwxyz0123456789')
    return all(c in allowed_chars for c in user_input.lower())
'''
    )

    # Package metadata
    (repo_dir / "package.json").write_text(
        json.dumps(
            {
                "name": "vulnerable-test-app",
                "version": "1.0.0",
                "dependencies": {"express": "^4.17.1", "mysql": "^2.18.1"},
            }
        )
    )

    # README
    (repo_dir / "README.md").write_text(
        """# Test Vulnerable Repository

This repository contains intentional security vulnerabilities for testing purposes.

## Vulnerabilities Included:
- SQL Injection
- XSS
- Command Injection
- Path Traversal
- Hardcoded Credentials
- Insecure Deserialization

**DO NOT USE IN PRODUCTION**
"""
    )

    yield repo_dir


@pytest.fixture
def sample_safe_repo(tmp_path: Path) -> Generator[Path, None, None]:
    """Create a repository with safe, well-written code"""
    repo_dir = tmp_path / "safe_repo"
    repo_dir.mkdir()

    # Safe database module
    (repo_dir / "database.py").write_text(
        '''
"""Safe database module with parameterized queries"""
import sqlite3

def search_users(name: str):
    """Safe user search with parameterized query"""
    query = "SELECT * FROM users WHERE name = ?"
    return db.execute(query, (name,))

def login(username: str, password: str):
    """Safe login with prepared statement"""
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    return db.execute(query, (username, password))
'''
    )

    # Safe web module
    (repo_dir / "web_utils.py").write_text(
        '''
"""Safe web utilities with proper escaping"""
import html

def display_message(msg: str):
    """Safe display with HTML escaping"""
    escaped = html.escape(msg)
    return f"<div>{escaped}</div>"

def render_template(data: dict):
    """Safe template rendering"""
    return json.dumps(data)
'''
    )

    # Safe utilities
    (repo_dir / "utils.py").write_text(
        '''
"""Safe utility functions"""
from pathlib import Path

def read_file_safe(filename: str):
    """Safe file reading with path validation"""
    base_path = Path("/data")
    full_path = (base_path / filename).resolve()

    if not str(full_path).startswith(str(base_path)):
        raise ValueError("Path traversal detected")

    with open(full_path, 'r') as f:
        return f.read()
'''
    )

    (repo_dir / "README.md").write_text("# Safe Repository\nWell-written secure code")

    yield repo_dir


@pytest.fixture
def mock_api_key() -> str:
    """Provide test API key"""
    return os.getenv("ANTHROPIC_API_KEY", "sk-ant-test-key-12345")


@pytest.fixture
def mock_config() -> dict:
    """Mock configuration for tests"""
    return {
        "ai_provider": "anthropic",
        "anthropic_api_key": "test-key-12345",
        "model": "claude-sonnet-4-5-20250929",
        "multi_agent_mode": "single",
        "enable_threat_modeling": False,
        "enable_sandbox_validation": False,
        "foundation_sec_enabled": False,
        "max_files": "20",
        "max_tokens": "4000",
        "cost_limit": "1.0",
        "max_file_size": "50000",
    }


@pytest.fixture
def phase1_config(mock_api_key: str) -> dict:
    """Configuration with all Phase 1 features enabled"""
    return {
        "ai_provider": "anthropic",
        "anthropic_api_key": mock_api_key,
        "model": "claude-sonnet-4-5-20250929",
        "multi_agent_mode": "sequential",
        "enable_threat_modeling": True,
        "enable_sandbox_validation": True,
        "foundation_sec_enabled": False,  # Don't require model download
        "max_files": "10",
        "max_tokens": "2000",
        "cost_limit": "2.0",
    }


@pytest.fixture
def foundation_sec_config() -> dict:
    """Configuration for Foundation-Sec-8B provider"""
    return {
        "ai_provider": "foundation-sec",
        "foundation_sec_enabled": True,
        "enable_threat_modeling": True,
        "enable_sandbox_validation": False,
        "max_files": "10",
        "max_tokens": "2000",
    }


@pytest.fixture
def sample_findings() -> list:
    """Sample security findings for testing"""
    return [
        {
            "category": "security",
            "severity": "critical",
            "title": "SQL Injection vulnerability",
            "description": "User input is directly concatenated into SQL query without sanitization",
            "file": "sql_injection.py",
            "line": 5,
            "code": "query = f\"SELECT * FROM users WHERE name = '{name}'\"",
            "recommendation": "Use parameterized queries with placeholders instead of string interpolation",
            "cwe": "CWE-89",
            "owasp": "A03:2021 - Injection",
        },
        {
            "category": "security",
            "severity": "high",
            "title": "Cross-Site Scripting (XSS)",
            "description": "User input assigned directly to innerHTML allows script execution",
            "file": "xss_vuln.js",
            "line": 4,
            "code": "document.getElementById('output').innerHTML = msg;",
            "recommendation": "Use textContent instead of innerHTML, or sanitize HTML input",
            "cwe": "CWE-79",
            "owasp": "A03:2021 - Injection",
        },
        {
            "category": "security",
            "severity": "critical",
            "title": "Command Injection",
            "description": "User input passed to os.system allows arbitrary command execution",
            "file": "command_injection.py",
            "line": 6,
            "code": 'os.system(f"ping -c 1 {hostname}")',
            "recommendation": "Use subprocess with argument list instead of shell commands",
            "cwe": "CWE-78",
            "owasp": "A03:2021 - Injection",
        },
        {
            "category": "security",
            "severity": "high",
            "title": "Hardcoded Credentials",
            "description": "Database password hardcoded in source code",
            "file": "credentials.py",
            "line": 4,
            "code": 'DATABASE_PASSWORD = "supersecret123"',
            "recommendation": "Use environment variables or secure credential management",
            "cwe": "CWE-798",
            "owasp": "A07:2021 - Identification and Authentication Failures",
        },
        {
            "category": "security",
            "severity": "medium",
            "title": "Path Traversal",
            "description": "File path not validated, allows directory traversal",
            "file": "path_traversal.py",
            "line": 4,
            "code": 'with open(f"/data/{filename}", "r") as f:',
            "recommendation": "Validate and sanitize file paths, use Path.resolve()",
            "cwe": "CWE-22",
            "owasp": "A01:2021 - Broken Access Control",
        },
    ]


@pytest.fixture
def sample_threat_model() -> dict:
    """Sample threat model for testing"""
    return {
        "version": "1.0",
        "repository": "test-repo",
        "generated_at": "2025-01-01T00:00:00Z",
        "attack_surface": {
            "entry_points": ["Web API endpoints", "Database connections", "File upload functionality"],
            "external_dependencies": ["npm packages", "Python libraries", "External APIs"],
            "authentication_methods": ["JWT tokens", "Session cookies", "API keys"],
            "data_stores": ["PostgreSQL database", "Redis cache", "File system"],
        },
        "trust_boundaries": [
            {
                "name": "Public Internet / Application",
                "trust_level": "untrusted",
                "description": "External users accessing web application",
            },
            {
                "name": "Application / Database",
                "trust_level": "trusted",
                "description": "Internal communication between app and database",
            },
        ],
        "assets": [
            {
                "name": "User credentials",
                "sensitivity": "critical",
                "description": "Usernames, passwords, authentication tokens",
            },
            {"name": "Personal data", "sensitivity": "high", "description": "User profile information, PII"},
            {"name": "Application code", "sensitivity": "medium", "description": "Source code and configuration"},
        ],
        "threats": [
            {
                "id": "THREAT-001",
                "name": "SQL Injection Attack",
                "category": "injection",
                "likelihood": "high",
                "impact": "critical",
                "affected_components": ["database", "api"],
                "description": "Attacker injects SQL code through user inputs",
                "mitigation": "Use parameterized queries and input validation",
            },
            {
                "id": "THREAT-002",
                "name": "Cross-Site Scripting (XSS)",
                "category": "injection",
                "likelihood": "high",
                "impact": "high",
                "affected_components": ["web", "frontend"],
                "description": "Attacker injects malicious scripts into web pages",
                "mitigation": "Implement output encoding and Content Security Policy",
            },
            {
                "id": "THREAT-003",
                "name": "Authentication Bypass",
                "category": "authentication",
                "likelihood": "medium",
                "impact": "critical",
                "affected_components": ["authentication", "api"],
                "description": "Attacker bypasses authentication mechanisms",
                "mitigation": "Implement robust authentication and authorization",
            },
        ],
        "security_objectives": [
            "Protect user credentials and personal data",
            "Prevent unauthorized access to system resources",
            "Maintain data integrity and availability",
            "Detect and respond to security incidents",
        ],
    }


@pytest.fixture(autouse=True)
def reset_environment():
    """Reset environment variables before each test"""
    original_env = os.environ.copy()
    yield
    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env)


@pytest.fixture
def temp_output_dir(tmp_path: Path) -> Generator[Path, None, None]:
    """Create temporary directory for output files"""
    output_dir = tmp_path / ".agent-os"
    output_dir.mkdir()
    yield output_dir
