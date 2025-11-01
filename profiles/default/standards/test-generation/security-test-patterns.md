# Security Test Patterns

Common patterns for security testing across different vulnerability types.

## Injection Vulnerabilities (SQL, NoSQL, Command, etc.)

### Pattern: Payload Testing
```python
@pytest.mark.parametrize("malicious_payload", [
    "' OR '1'='1 --",
    "'; DROP TABLE users; --",
    "admin' --",
    "' UNION SELECT password FROM users --"
])
def test_injection_payloads_blocked(malicious_payload):
    response = make_request(malicious_payload)
    assert response.status_code == 400
    assert is_error_safe(response.body)
```

### Pattern: Safe Alternative Verification
```python
def test_uses_parameterized_queries():
    """Verify parameterized queries are used, not string concatenation"""
    # Check code or execution plan
    # Or verify by testing safe inputs work correctly
    pass
```

## Authentication Vulnerabilities

### Pattern: Auth Bypass Testing
```python
def test_requires_authentication():
    """Verify endpoint requires authentication"""
    response = client.get('/api/admin/users')  # No auth header
    assert response.status_code == 401

def test_invalid_token_rejected():
    """Verify invalid tokens are rejected"""
    response = client.get('/api/users/me', headers={
        'Authorization': 'Bearer invalid_token'
    })
    assert response.status_code == 401

def test_expired_token_rejected():
    """Verify expired tokens are rejected"""
    expired_token = generate_expired_token()
    response = client.get('/api/users/me', headers={
        'Authorization': f'Bearer {expired_token}'
    })
    assert response.status_code == 401
```

## Authorization Vulnerabilities (IDOR, Privilege Escalation)

### Pattern: Permission Boundary Testing
```python
def test_cannot_access_other_users_data():
    """Test IDOR protection"""
    # Login as user A
    user_a_token = login('user_a')

    # Try to access user B's data
    response = client.get('/api/users/user_b/profile', headers={
        'Authorization': f'Bearer {user_a_token}'
    })

    assert response.status_code == 403

def test_user_cannot_access_admin_endpoint():
    """Test privilege escalation protection"""
    user_token = login('regular_user')

    response = client.get('/api/admin/settings', headers={
        'Authorization': f'Bearer {user_token}'
    })

    assert response.status_code == 403
```

## Cryptographic Vulnerabilities

### Pattern: Secure Defaults Testing
```python
def test_uses_strong_encryption():
    """Verify strong encryption algorithm is used"""
    encrypted = encrypt_data("sensitive")

    # Should not use weak algorithms
    assert not encrypted.startswith('DES')
    assert not encrypted.startswith('MD5')

    # Should use strong algorithms
    assert 'AES-256' in get_algorithm_info(encrypted)

def test_no_hardcoded_keys():
    """Verify cryptographic keys are not hardcoded"""
    # Check that keys come from secure storage
    key = get_encryption_key()
    assert key != "hardcoded_key_value"
    assert is_from_secure_storage(key)
```

## Input Validation Vulnerabilities

### Pattern: Boundary Testing
```python
@pytest.mark.parametrize("boundary_input", [
    "",  # Empty
    "a" * 10000,  # Very long
    None,  # Null
    "<script>alert(1)</script>",  # XSS
    "../../../etc/passwd",  # Path traversal
    "\x00",  # Null byte
])
def test_input_validation(boundary_input):
    response = process_input(boundary_input)
    assert response.is_valid or response.is_safe_error
```

## SSRF Vulnerabilities

### Pattern: URL Validation Testing
```python
@pytest.mark.parametrize("malicious_url", [
    "http://localhost/admin",
    "http://169.254.169.254/latest/meta-data/",
    "file:///etc/passwd",
    "http://internal-service:8080/",
])
def test_ssrf_protection(malicious_url):
    """Test SSRF protection blocks internal URLs"""
    response = fetch_url(malicious_url)
    assert response.status_code == 400
    assert "blocked" in response.body.lower()
```

## XSS Vulnerabilities

### Pattern: Output Encoding Testing
```python
@pytest.mark.parametrize("xss_payload", [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg/onload=alert(1)>",
])
def test_xss_protection(xss_payload):
    """Test XSS payloads are properly encoded"""
    response = render_user_input(xss_payload)

    # Should be HTML encoded
    assert "<script>" not in response
    assert "&lt;script&gt;" in response or html.escape(xss_payload) in response
```

## File Upload Vulnerabilities

### Pattern: File Type Validation
```python
@pytest.mark.parametrize("malicious_file", [
    ("shell.php", b"<?php system($_GET['cmd']); ?>"),
    ("exploit.jsp", b"<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>"),
    ("malware.exe", generate_exe_header()),
])
def test_file_upload_restrictions(malicious_file):
    """Test file upload only allows safe file types"""
    filename, content = malicious_file

    response = upload_file(filename, content)
    assert response.status_code == 400
    assert "not allowed" in response.body.lower()
```

## Rate Limiting / DoS Vulnerabilities

### Pattern: Rate Limit Testing
```python
def test_rate_limiting_enforced():
    """Test rate limiting prevents abuse"""
    # Make requests up to limit
    for i in range(100):
        response = make_request()
        assert response.status_code == 200

    # Next request should be rate limited
    response = make_request()
    assert response.status_code == 429  # Too Many Requests
```
