#!/usr/bin/env python3
"""
Agent OS AI-Powered Code Audit Script
Uses Anthropic Claude API to perform real code analysis
"""

import os
import sys
import json
import subprocess
from pathlib import Path
from anthropic import Anthropic

def get_codebase_context(repo_path):
    """Get relevant codebase files for analysis"""
    important_files = []
    extensions = {'.py', '.js', '.ts', '.java', '.go', '.rs', '.rb', '.php', '.cs'}
    
    for root, dirs, files in os.walk(repo_path):
        # Skip common directories
        dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', 'venv', '__pycache__', 'dist', 'build', '.next'}]
        
        for file in files:
            if any(file.endswith(ext) for ext in extensions):
                file_path = Path(root) / file
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if len(content) < 50000:  # Skip very large files
                            important_files.append({
                                'path': str(file_path.relative_to(repo_path)),
                                'content': content[:10000]  # Limit content size
                            })
                except Exception as e:
                    print(f"Warning: Could not read {file_path}: {e}")
    
    return important_files[:50]  # Limit to 50 files

def run_audit(repo_path, api_key, review_type='audit'):
    """Run AI-powered code audit"""
    
    print(f"🤖 Starting AI-powered {review_type} analysis...")
    print(f"📁 Repository: {repo_path}")
    
    # Initialize Anthropic client
    client = Anthropic(api_key=api_key)
    
    # Get codebase context
    print("📂 Analyzing codebase structure...")
    files = get_codebase_context(repo_path)
    print(f"✅ Found {len(files)} files to analyze")
    
    # Build context for Claude
    codebase_context = "\n\n".join([
        f"File: {f['path']}\n```\n{f['content']}\n```"
        for f in files
    ])
    
    # Load audit command
    audit_command_path = Path.home() / '.agent-os/profiles/default/commands/audit-codebase/multi-agent/audit-codebase.md'
    if audit_command_path.exists():
        with open(audit_command_path, 'r') as f:
            audit_instructions = f.read()
    else:
        audit_instructions = """
Perform a comprehensive code audit focusing on:
1. Security vulnerabilities (hardcoded secrets, injection flaws, auth issues)
2. Performance issues (N+1 queries, memory leaks, inefficient algorithms)
3. Test coverage gaps (missing tests for critical logic)
4. Code quality issues (maintainability, documentation, error handling)

For each issue found, classify it as:
- [BLOCKER] - Must fix before merge
- [SUGGESTION] - Good to have improvement
- [NIT] - Minor issue, can ignore
"""
    
    # Create prompt
    prompt = f"""You are an expert code reviewer performing a comprehensive codebase audit.

{audit_instructions}

Here is the codebase to analyze:

{codebase_context}

Please provide a detailed audit report in Markdown format with the following structure:

# Codebase Audit Report

## Executive Summary
- Overall Status (APPROVED / REQUIRES FIXES / CRITICAL)
- Risk Level (LOW / MEDIUM / HIGH / CRITICAL)
- Total Issues Found
- Merge Blockers count
- Suggestions count

## Merge Blockers (Must Fix Before Merge)

### Security Issues
List critical security vulnerabilities with file:line references

### Performance Issues
List critical performance problems with file:line references

### Testing Issues
List critical testing gaps with file:line references

### Code Quality Issues
List critical code quality problems with file:line references

## Suggestions (Good to Have)

### Security Improvements
### Performance Optimizations
### Testing Enhancements
### Code Quality Improvements

## Action Items

### Immediate (Merge Blockers)
Numbered list of critical fixes

### Follow-up (Suggestions)
Numbered list of recommended improvements

## Recommendation
Final recommendation: APPROVED / REQUIRES FIXES / DO NOT MERGE

Be specific with file names and line numbers. Focus on real, actionable issues.
"""
    
    print("🧠 Analyzing code with Claude Sonnet 4...")
    
    try:
        # Call Claude API
        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=8000,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        
        report = message.content[0].text
        
        # Save report
        report_dir = Path(repo_path) / '.agent-os/reviews'
        report_dir.mkdir(parents=True, exist_ok=True)
        
        report_file = report_dir / f'{review_type}-report.md'
        with open(report_file, 'w') as f:
            f.write(report)
        
        print(f"✅ Audit complete! Report saved to: {report_file}")
        
        # Count blockers
        blocker_count = report.count('[BLOCKER]')
        suggestion_count = report.count('[SUGGESTION]')
        
        print(f"\n📊 Results:")
        print(f"   Blockers: {blocker_count}")
        print(f"   Suggestions: {suggestion_count}")
        
        # Output for GitHub Actions
        print(f"\n::set-output name=blockers::{blocker_count}")
        print(f"::set-output name=suggestions::{suggestion_count}")
        
        return blocker_count, suggestion_count
        
    except Exception as e:
        print(f"❌ Error during AI analysis: {e}")
        print(f"Error type: {type(e).__name__}")
        sys.exit(1)

if __name__ == '__main__':
    repo_path = sys.argv[1] if len(sys.argv) > 1 else '.'
    review_type = sys.argv[2] if len(sys.argv) > 2 else 'audit'
    
    # Get API key from environment
    api_key = os.environ.get('ANTHROPIC_API_KEY') or os.environ.get('CURSOR_API_KEY')
    
    if not api_key:
        print("❌ Error: ANTHROPIC_API_KEY or CURSOR_API_KEY environment variable not set")
        sys.exit(1)
    
    run_audit(repo_path, api_key, review_type)

