
import pytest
from app.file_processor import process_file

def test_command_injection_regression():
    """Regression test: Ensure command injection is still fixed"""
    malicious_inputs = [
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "& cat /etc/passwd",
        "$(cat /etc/passwd)",
        "`cat /etc/passwd`",
    ]

    for malicious_input in malicious_inputs:
        # Should not execute command
        try:
            result = process_file(malicious_input)
            # If no exception, verify command wasn't executed
            result_str = str(result)
            assert "root:" not in result_str, f"Command injection possible with: {malicious_input}"
            assert "/bin/bash" not in result_str, "System files accessible"
        except (ValueError, SecurityError, PermissionError):
            # Expected: should raise error for malicious input
            pass

def test_command_injection_normal_input():
    """Ensure fix doesn't break normal functionality"""
    normal_input = "test.txt"
    result = process_file(normal_input)
    assert result is not None, "Function broken for normal input"
