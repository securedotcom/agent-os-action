#!/usr/bin/env python3
"""
Agent OS AI-Powered Code Audit Script
Uses Anthropic Claude API to perform real code analysis with:
- Cost/latency guardrails
- SARIF and JSON output
- Observability metrics
"""

import os
import sys
import json
import time
import glob
import subprocess
from pathlib import Path
from datetime import datetime
from anthropic import Anthropic

class ReviewMetrics:
    """Track observability metrics for the review"""
    def __init__(self):
        self.start_time = time.time()
        self.metrics = {
            "version": "1.0.14",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "repository": os.environ.get('GITHUB_REPOSITORY', 'unknown'),
            "commit": os.environ.get('GITHUB_SHA', 'unknown'),
            "files_reviewed": 0,
            "lines_analyzed": 0,
            "tokens_input": 0,
            "tokens_output": 0,
            "cost_usd": 0.0,
            "duration_seconds": 0,
            "model": "claude-sonnet-4-20250514",
            "findings": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            },
            "categories": {
                "security": 0,
                "performance": 0,
                "testing": 0,
                "quality": 0
            }
        }
    
    def record_file(self, lines):
        self.metrics["files_reviewed"] += 1
        self.metrics["lines_analyzed"] += lines
    
    def record_llm_call(self, input_tokens, output_tokens):
        self.metrics["tokens_input"] += input_tokens
        self.metrics["tokens_output"] += output_tokens
        # Claude Sonnet 4 pricing: $3/1M input, $15/1M output
        input_cost = (input_tokens / 1_000_000) * 3.0
        output_cost = (output_tokens / 1_000_000) * 15.0
        self.metrics["cost_usd"] += input_cost + output_cost
    
    def record_finding(self, severity, category):
        if severity in self.metrics["findings"]:
            self.metrics["findings"][severity] += 1
        if category in self.metrics["categories"]:
            self.metrics["categories"][category] += 1
    
    def finalize(self):
        self.metrics["duration_seconds"] = int(time.time() - self.start_time)
        return self.metrics
    
    def save(self, path):
        with open(path, 'w') as f:
            json.dump(self.metrics, f, indent=2)
        print(f"📊 Metrics saved to: {path}")

def get_changed_files():
    """Get list of changed files in PR"""
    try:
        result = subprocess.run(
            ['git', 'diff', '--name-only', 'HEAD^', 'HEAD'],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            return [f.strip() for f in result.stdout.split('\n') if f.strip()]
    except Exception as e:
        print(f"Warning: Could not get changed files: {e}")
    return []

def matches_glob_patterns(file_path, patterns):
    """Check if file matches any glob pattern"""
    if not patterns:
        return False
    for pattern in patterns:
        if glob.fnmatch.fnmatch(file_path, pattern):
            return True
    return False

def get_codebase_context(repo_path, config):
    """Get relevant codebase files for analysis with cost guardrails"""
    important_files = []
    extensions = {'.py', '.js', '.ts', '.java', '.go', '.rs', '.rb', '.php', '.cs', '.jsx', '.tsx'}
    
    # Parse configuration
    only_changed = config.get('only_changed', False)
    include_patterns = [p.strip() for p in config.get('include_paths', '').split(',') if p.strip()]
    exclude_patterns = [p.strip() for p in config.get('exclude_paths', '').split(',') if p.strip()]
    max_file_size = int(config.get('max_file_size', 50000))
    max_files = int(config.get('max_files', 50))
    
    # Get changed files if in PR mode
    changed_files = []
    if only_changed:
        changed_files = get_changed_files()
        print(f"📝 PR mode: Found {len(changed_files)} changed files")
    
    total_lines = 0
    
    for root, dirs, files in os.walk(repo_path):
        # Skip common directories
        dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', 'venv', '__pycache__', 'dist', 'build', '.next', 'target'}]
        
        for file in files:
            if any(file.endswith(ext) for ext in extensions):
                file_path = Path(root) / file
                rel_path = str(file_path.relative_to(repo_path))
                
                # Apply filters
                if only_changed and rel_path not in changed_files:
                    continue
                
                if include_patterns and not matches_glob_patterns(rel_path, include_patterns):
                    continue
                
                if exclude_patterns and matches_glob_patterns(rel_path, exclude_patterns):
                    continue
                
                try:
                    file_size = file_path.stat().st_size
                    if file_size > max_file_size:
                        print(f"⏭️  Skipping {rel_path} (too large: {file_size} bytes)")
                        continue
                    
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        lines = len(content.split('\n'))
                        
                        if len(content) < max_file_size:
                            important_files.append({
                                'path': rel_path,
                                'content': content[:10000],  # Limit content size
                                'lines': lines
                            })
                            total_lines += lines
                            
                            if len(important_files) >= max_files:
                                print(f"⚠️  Reached max files limit ({max_files})")
                                break
                                
                except Exception as e:
                    print(f"Warning: Could not read {file_path}: {e}")
        
        if len(important_files) >= max_files:
            break
    
    print(f"✅ Selected {len(important_files)} files ({total_lines} lines)")
    return important_files

def estimate_cost(files, max_tokens):
    """Estimate cost before running analysis"""
    total_chars = sum(len(f['content']) for f in files)
    # Rough estimate: 4 chars per token
    estimated_input_tokens = total_chars // 4
    estimated_output_tokens = max_tokens
    
    input_cost = (estimated_input_tokens / 1_000_000) * 3.0
    output_cost = (estimated_output_tokens / 1_000_000) * 15.0
    total_cost = input_cost + output_cost
    
    return total_cost, estimated_input_tokens, estimated_output_tokens

def generate_sarif(findings, repo_path):
    """Generate SARIF 2.1.0 format for GitHub Code Scanning"""
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Agent OS Code Reviewer",
                    "version": "1.0.14",
                    "informationUri": "https://github.com/securedotcom/agent-os-action",
                    "rules": []
                }
            },
            "results": []
        }]
    }
    
    for finding in findings:
        # Map severity to SARIF level
        level_map = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note"
        }
        
        result = {
            "ruleId": finding.get('rule_id', 'AGENT-OS-001'),
            "level": level_map.get(finding.get('severity', 'medium'), 'warning'),
            "message": {
                "text": finding.get('message', 'Issue found')
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.get('file_path', 'unknown')
                    },
                    "region": {
                        "startLine": finding.get('line_number', 1)
                    }
                }
            }]
        }
        
        if 'cwe' in finding:
            result['properties'] = {'cwe': finding['cwe']}
        
        sarif['runs'][0]['results'].append(result)
    
    return sarif

def parse_findings_from_report(report_text):
    """Parse findings from markdown report"""
    findings = []
    lines = report_text.split('\n')
    
    current_file = None
    current_line = None
    
    for line in lines:
        # Look for severity markers
        if '[BLOCKER]' in line or '[CRITICAL]' in line:
            severity = 'critical'
        elif '[HIGH]' in line:
            severity = 'high'
        elif '[MEDIUM]' in line or '[SUGGESTION]' in line:
            severity = 'medium'
        elif '[LOW]' in line:
            severity = 'low'
        else:
            continue
        
        # Extract file path and line number if present
        # Format: file.js:123
        import re
        match = re.search(r'`([^`]+):(\d+)`', line)
        if match:
            current_file = match.group(1)
            current_line = int(match.group(2))
        
        # Determine category
        category = 'quality'
        if 'security' in line.lower() or 'sql' in line.lower() or 'xss' in line.lower():
            category = 'security'
        elif 'performance' in line.lower() or 'n+1' in line.lower() or 'memory' in line.lower():
            category = 'performance'
        elif 'test' in line.lower() or 'coverage' in line.lower():
            category = 'testing'
        
        findings.append({
            'severity': severity,
            'category': category,
            'message': line.strip(),
            'file_path': current_file or 'unknown',
            'line_number': current_line or 1,
            'rule_id': f'{category.upper()}-001'
        })
    
    return findings

def run_audit(repo_path, api_key, config, review_type='audit'):
    """Run AI-powered code audit with guardrails"""
    
    metrics = ReviewMetrics()
    
    print(f"🤖 Starting AI-powered {review_type} analysis...")
    print(f"📁 Repository: {repo_path}")
    
    # Check cost limit
    cost_limit = float(config.get('cost_limit', 1.0))
    max_tokens = int(config.get('max_tokens', 8000))
    
    # Determine if this is a Cursor API key or Anthropic API key
    is_cursor_key = api_key.startswith('key_')
    
    if is_cursor_key:
        print("🔑 Using Cursor API endpoint")
        client = Anthropic(
            api_key=api_key,
            base_url="https://api.cursor.sh/v1"
        )
    else:
        print("🔑 Using Anthropic API endpoint")
        client = Anthropic(api_key=api_key)
    
    # Get codebase context with guardrails
    print("📂 Analyzing codebase structure...")
    files = get_codebase_context(repo_path, config)
    
    if not files:
        print("⚠️  No files to analyze")
        return 0, 0, metrics
    
    # Record file metrics
    for f in files:
        metrics.record_file(f['lines'])
    
    # Estimate cost
    estimated_cost, est_input, est_output = estimate_cost(files, max_tokens)
    print(f"💰 Estimated cost: ${estimated_cost:.2f}")
    
    if estimated_cost > cost_limit:
        print(f"⚠️  Estimated cost ${estimated_cost:.2f} exceeds limit ${cost_limit:.2f}")
        print(f"💡 Reduce max-files, use path filters, or increase cost-limit")
        sys.exit(2)
    
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
- [CRITICAL] - Severe security or data loss risk
- [HIGH] - Important issue that should be fixed soon
- [MEDIUM] - Moderate issue, good to fix
- [LOW] - Minor issue or suggestion
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
- Critical issues count
- High issues count

## Critical Issues (Must Fix Immediately)

### Security Issues
List critical security vulnerabilities with `file.ext:line` references

### Performance Issues
List critical performance problems with `file.ext:line` references

### Testing Issues
List critical testing gaps with `file.ext:line` references

## High Priority Issues

### Security Improvements
### Performance Optimizations
### Testing Enhancements

## Medium Priority Issues

### Code Quality Improvements

## Action Items

### Immediate (Critical)
Numbered list of critical fixes

### Follow-up (High Priority)
Numbered list of high priority improvements

## Recommendation
Final recommendation: APPROVED / REQUIRES FIXES / DO NOT MERGE

Be specific with file names and line numbers. Use format: `filename.ext:123` for references.
"""
    
    print("🧠 Analyzing code with Claude Sonnet 4...")
    
    try:
        # Call Claude API
        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=max_tokens,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        
        # Record LLM metrics
        metrics.record_llm_call(
            message.usage.input_tokens,
            message.usage.output_tokens
        )
        
        report = message.content[0].text
        
        # Save markdown report
        report_dir = Path(repo_path) / '.agent-os/reviews'
        report_dir.mkdir(parents=True, exist_ok=True)
        
        report_file = report_dir / f'{review_type}-report.md'
        with open(report_file, 'w') as f:
            f.write(report)
        
        print(f"✅ Audit complete! Report saved to: {report_file}")
        
        # Parse findings
        findings = parse_findings_from_report(report)
        
        # Record finding metrics
        for finding in findings:
            metrics.record_finding(finding['severity'], finding['category'])
        
        # Generate SARIF
        sarif = generate_sarif(findings, repo_path)
        sarif_file = report_dir / 'results.sarif'
        with open(sarif_file, 'w') as f:
            json.dump(sarif, f, indent=2)
        print(f"📄 SARIF saved to: {sarif_file}")
        
        # Generate structured JSON
        json_output = {
            "version": "1.0.14",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "repository": os.environ.get('GITHUB_REPOSITORY', 'unknown'),
            "commit": os.environ.get('GITHUB_SHA', 'unknown'),
            "summary": metrics.metrics,
            "findings": findings
        }
        
        json_file = report_dir / 'results.json'
        with open(json_file, 'w') as f:
            json.dump(json_output, f, indent=2)
        print(f"📊 JSON saved to: {json_file}")
        
        # Save metrics
        metrics_file = report_dir / 'metrics.json'
        metrics.finalize()
        metrics.save(metrics_file)
        
        # Count blockers and suggestions
        blocker_count = report.count('[CRITICAL]') + report.count('[BLOCKER]')
        suggestion_count = report.count('[HIGH]') + report.count('[MEDIUM]') + report.count('[SUGGESTION]')
        
        print(f"\n📊 Results:")
        print(f"   Critical: {metrics.metrics['findings']['critical']}")
        print(f"   High: {metrics.metrics['findings']['high']}")
        print(f"   Medium: {metrics.metrics['findings']['medium']}")
        print(f"   Low: {metrics.metrics['findings']['low']}")
        print(f"\n💰 Cost: ${metrics.metrics['cost_usd']:.2f}")
        print(f"⏱️  Duration: {metrics.metrics['duration_seconds']}s")
        
        # Output for GitHub Actions
        print(f"\n::set-output name=blockers::{blocker_count}")
        print(f"::set-output name=suggestions::{suggestion_count}")
        print(f"::set-output name=report-path::{report_file}")
        print(f"::set-output name=sarif-path::{sarif_file}")
        print(f"::set-output name=json-path::{json_file}")
        print(f"::set-output name=cost-estimate::{metrics.metrics['cost_usd']:.2f}")
        print(f"::set-output name=files-analyzed::{metrics.metrics['files_reviewed']}")
        print(f"::set-output name=duration-seconds::{metrics.metrics['duration_seconds']}")
        
        return blocker_count, suggestion_count, metrics
        
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
    
    # Get configuration from environment
    config = {
        'only_changed': os.environ.get('INPUT_ONLY_CHANGED', 'false').lower() == 'true',
        'include_paths': os.environ.get('INPUT_INCLUDE_PATHS', ''),
        'exclude_paths': os.environ.get('INPUT_EXCLUDE_PATHS', ''),
        'max_file_size': os.environ.get('INPUT_MAX_FILE_SIZE', '50000'),
        'max_files': os.environ.get('INPUT_MAX_FILES', '50'),
        'max_tokens': os.environ.get('INPUT_MAX_TOKENS', '8000'),
        'cost_limit': os.environ.get('INPUT_COST_LIMIT', '1.0'),
    }
    
    run_audit(repo_path, api_key, config, review_type)
