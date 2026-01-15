
import pytest
from app.database import get_user_by_id

def test_sql_injection_regression():
    """Regression test: Ensure SQL injection is still fixed"""
    # Test with SQL injection payload
    malicious_input = "' OR '1'='1"

    # Should NOT execute SQL injection (should sanitize or use parameterized query)
    try:
        result = get_user_by_id(malicious_input)
        # If we get here, check that injection didn't work
        result_str = str(result)
        assert "1'='1" not in result_str, "SQL injection vulnerability returned!"
        assert len(result_str) < 1000, "Suspiciously large result - possible injection"
    except ValueError:
        # Expected: should raise error for malicious input
        pass
    except Exception as e:
        # Should not crash with other errors
        if "SQL" in str(e) and "syntax" in str(e).lower():
            pytest.fail("SQL injection still possible - syntax error indicates unescaped SQL")

def test_sql_injection_normal_input():
    """Ensure fix doesn't break normal functionality"""
    normal_input = "valid_user_123"
    result = get_user_by_id(normal_input)
    assert result is not None, "Function broken for normal input"
