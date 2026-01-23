"""
Vulnerable Python API for testing security scanners
Contains intentional security vulnerabilities for testing purposes
"""
import os
import sqlite3
import subprocess
from flask import Flask, request, render_template_string

app = Flask(__name__)

# Hardcoded secret (TruffleHog/Gitleaks should detect)
API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DATABASE_URL = "postgresql://user:SecretPassword123@localhost:5432/mydb"


@app.route('/search')
def search():
    """SQL Injection vulnerability (Semgrep CWE-89)"""
    query = request.args.get('q', '')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Vulnerable: Direct string concatenation
    sql = f"SELECT * FROM users WHERE name = '{query}'"
    cursor.execute(sql)
    results = cursor.fetchall()
    return {"results": results}


@app.route('/user/<user_id>')
def get_user(user_id):
    """XSS vulnerability (Semgrep CWE-79)"""
    # Vulnerable: No escaping of user input
    template = f"<html><body><h1>User: {user_id}</h1></body></html>"
    return render_template_string(template)


@app.route('/execute')
def execute_command():
    """Command Injection vulnerability (Semgrep CWE-78)"""
    cmd = request.args.get('cmd', 'ls')
    # Vulnerable: Direct command execution
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return {"output": result.stdout, "error": result.stderr}


@app.route('/read_file')
def read_file():
    """Path Traversal vulnerability (Semgrep CWE-22)"""
    filename = request.args.get('file', 'readme.txt')
    # Vulnerable: No path sanitization
    with open(filename, 'r') as f:
        content = f.read()
    return {"content": content}


@app.route('/eval')
def eval_code():
    """Code Injection vulnerability (Semgrep CWE-94)"""
    code = request.args.get('code', '1+1')
    # Vulnerable: eval on user input
    result = eval(code)
    return {"result": result}


@app.route('/ssrf')
def ssrf():
    """SSRF vulnerability (Semgrep CWE-918)"""
    import requests
    url = request.args.get('url', '')
    # Vulnerable: No URL validation
    response = requests.get(url)
    return {"content": response.text}


def get_password():
    """Weak cryptography (Semgrep)"""
    import hashlib
    password = "admin123"
    # Vulnerable: MD5 is weak
    hashed = hashlib.md5(password.encode()).hexdigest()
    return hashed


def unsafe_deserialization():
    """Unsafe deserialization (Semgrep CWE-502)"""
    import pickle
    data = request.data
    # Vulnerable: pickle is unsafe
    obj = pickle.loads(data)
    return obj


if __name__ == '__main__':
    # Vulnerable: Debug mode in production
    app.run(debug=True, host='0.0.0.0', port=5000)
