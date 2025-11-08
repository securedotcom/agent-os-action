"""Setup script for agent-os-code-reviewer package."""
from setuptools import setup, find_packages

setup(
    name="agent-os-code-reviewer",
    version="1.0.15",
    packages=find_packages(where="."),
    py_modules=[
        "scripts.run_ai_audit",
        "scripts.audit_cli",
        "scripts.threat_model_generator",
        "scripts.sandbox_validator",
        "scripts.real_multi_agent_review",
    ],
    package_dir={"": "."},
)
