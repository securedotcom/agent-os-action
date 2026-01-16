
import pytest
from app.file_handler import read_file

def test_path_traversal_regression():
    """Regression test: Ensure path traversal is still fixed"""
    traversal_payloads = [
        "../../etc/passwd",
        "....//....//etc/passwd",
        "..\\..\\windows\\system32",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ]

    for payload in traversal_payloads:
        try:
            result = read_file(payload)
            # Should not access sensitive files
            result_str = str(result)
            assert "root:" not in result_str, f"Path traversal possible: {payload}"
            assert "system32" not in result_str.lower(), "Windows system files accessible"
        except (ValueError, FileNotFoundError, PermissionError):
            # Expected: should reject or sanitize path
            pass

def test_path_traversal_normal_input():
    """Ensure fix doesn't break normal functionality"""
    normal_input = "safe/path/file.txt"
    result = read_file(normal_input)
    assert result is not None, "Function broken for normal path"
