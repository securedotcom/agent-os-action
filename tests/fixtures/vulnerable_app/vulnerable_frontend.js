/**
 * Vulnerable JavaScript frontend for testing security scanners
 * Contains intentional security vulnerabilities for testing purposes
 */

// Hardcoded API key (Gitleaks/TruffleHog should detect)
const API_KEY = 'AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe';
const GITHUB_TOKEN = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz';

// XSS vulnerability (Semgrep CWE-79)
function displayMessage(message) {
    // Vulnerable: innerHTML with user input
    document.getElementById('output').innerHTML = message;
}

// DOM-based XSS
function loadUserProfile() {
    const userId = new URLSearchParams(window.location.search).get('id');
    // Vulnerable: No sanitization
    document.write('<h1>User ID: ' + userId + '</h1>');
}

// Insecure randomness (Semgrep)
function generateToken() {
    // Vulnerable: Math.random() is not cryptographically secure
    return Math.random().toString(36).substring(2);
}

// Client-side authentication (Semgrep)
function checkAuth() {
    const password = document.getElementById('password').value;
    // Vulnerable: Client-side password check
    if (password === 'admin123') {
        localStorage.setItem('authenticated', 'true');
        return true;
    }
    return false;
}

// Prototype pollution
function merge(target, source) {
    // Vulnerable: No key validation
    for (let key in source) {
        target[key] = source[key];
    }
    return target;
}

// Open redirect
function redirect() {
    const url = new URLSearchParams(window.location.search).get('redirect');
    // Vulnerable: No URL validation
    window.location.href = url;
}

// CSRF vulnerability
function deleteAccount() {
    // Vulnerable: No CSRF token
    fetch('/api/account/delete', {
        method: 'POST',
        credentials: 'include'
    });
}

// Regex DoS
function validateEmail(email) {
    // Vulnerable: Catastrophic backtracking
    const regex = /^([a-zA-Z0-9._%-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})*$/;
    return regex.test(email);
}

// Insecure eval usage
function executeCode(code) {
    // Vulnerable: eval on user input
    eval(code);
}

// Local storage of sensitive data
function saveCredentials(username, password) {
    // Vulnerable: Storing credentials in localStorage
    localStorage.setItem('username', username);
    localStorage.setItem('password', password);
}

// Cookie without secure flags
document.cookie = 'session=abc123; path=/';

// Missing HTTPS enforcement
if (window.location.protocol !== 'https:') {
    console.warn('Not using HTTPS');
}
