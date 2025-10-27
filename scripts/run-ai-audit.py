#!/usr/bin/env python3
"""
Agent OS AI-Powered Code Audit Script
Supports multiple LLM providers: Anthropic, OpenAI, Ollama
With cost guardrails, SARIF/JSON output, and observability
"""

import os
import sys
import json
import time
import glob
import subprocess
from pathlib import Path
from datetime import datetime, timezone

class ReviewMetrics:
    """Track observability metrics for the review"""
    def __init__(self):
        self.start_time = time.time()
        self.metrics = {
            "version": "1.0.15",
            "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "repository": os.environ.get('GITHUB_REPOSITORY', 'unknown'),
            "commit": os.environ.get('GITHUB_SHA', 'unknown'),
            "files_reviewed": 0,
            "lines_analyzed": 0,
            "tokens_input": 0,
            "tokens_output": 0,
            "cost_usd": 0.0,
            "duration_seconds": 0,
            "model": "",
            "provider": "",
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
    
    def record_llm_call(self, input_tokens, output_tokens, provider):
        self.metrics["tokens_input"] += input_tokens
        self.metrics["tokens_output"] += output_tokens
        
        # Calculate cost based on provider
        if provider == 'anthropic':
            # Claude Sonnet 4: $3/1M input, $15/1M output
            input_cost = (input_tokens / 1_000_000) * 3.0
            output_cost = (output_tokens / 1_000_000) * 15.0
        elif provider == 'openai':
            # GPT-4: $10/1M input, $30/1M output
            input_cost = (input_tokens / 1_000_000) * 10.0
            output_cost = (output_tokens / 1_000_000) * 30.0
        else:
            # Ollama: Free (local)
            input_cost = 0.0
            output_cost = 0.0
        
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

def detect_ai_provider(config):
    """Auto-detect which AI provider to use based on available keys"""
    provider = config.get('ai_provider', 'auto')
    
    if provider != 'auto':
        return provider
    
    # Auto-detect based on available API keys
    if config.get('anthropic_api_key'):
        return 'anthropic'
    elif config.get('openai_api_key'):
        return 'openai'
    elif config.get('ollama_endpoint'):
        return 'ollama'
    else:
        print("⚠️  No AI provider configured")
        print("💡 Set one of: ANTHROPIC_API_KEY, OPENAI_API_KEY, or OLLAMA_ENDPOINT")
        return None

def get_ai_client(provider, config):
    """Get AI client for the specified provider"""
    if provider == 'anthropic':
        try:
            from anthropic import Anthropic
            api_key = config.get('anthropic_api_key')
            if not api_key:
                raise ValueError("ANTHROPIC_API_KEY not set")
            
            print("🔑 Using Anthropic API")
            return Anthropic(api_key=api_key), 'anthropic'
        except ImportError:
            print("❌ anthropic package not installed. Run: pip install anthropic")
            sys.exit(2)
    
    elif provider == 'openai':
        try:
            from openai import OpenAI
            api_key = config.get('openai_api_key')
            if not api_key:
                raise ValueError("OPENAI_API_KEY not set")
            
            print("🔑 Using OpenAI API endpoint")
            return OpenAI(api_key=api_key), 'openai'
        except ImportError:
            print("❌ openai package not installed. Run: pip install openai")
            sys.exit(2)
    
    elif provider == 'ollama':
        try:
            from openai import OpenAI
            endpoint = config.get('ollama_endpoint', 'http://localhost:11434')
            print(f"🔑 Using Ollama endpoint: {endpoint}")
            return OpenAI(base_url=f"{endpoint}/v1", api_key="ollama"), 'ollama'
        except ImportError:
            print("❌ openai package not installed. Run: pip install openai")
            sys.exit(2)
    
    else:
        print(f"❌ Unknown AI provider: {provider}")
        sys.exit(2)

def get_model_name(provider, config):
    """Get the appropriate model name for the provider"""
    model = config.get('model', 'auto')
    
    if model != 'auto':
        return model
    
    # Default models for each provider
    defaults = {
        'anthropic': 'claude-sonnet-4-20250514',
        'openai': 'gpt-4-turbo-preview',
        'ollama': 'llama3'
    }
    
    return defaults.get(provider, 'claude-sonnet-4-20250514')

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
    
    # Extended language support for polyglot codebases
    extensions = {
        # Web/Frontend
        '.js', '.jsx', '.ts', '.tsx', '.vue', '.svelte',
        # Backend
        '.py', '.java', '.go', '.rs', '.rb', '.php', '.cs', '.scala', '.kt',
        # Systems
        '.c', '.cpp', '.h', '.hpp', '.swift',
        # Data/Config
        '.sql', '.graphql', '.proto',
        # Infrastructure
        '.tf', '.yaml', '.yml'
    }
    
    # Parse configuration
    only_changed = config.get('only_changed', False)
    include_patterns = [p.strip() for p in config.get('include_paths', '').split(',') if p.strip()]
    exclude_patterns = [p.strip() for p in config.get('exclude_paths', '').split(',') if p.strip()]
    max_file_size = int(config.get('max_file_size', 50000))
    max_files = int(config.get('max_files', 100))  # Increased for large codebases
    
    # Get changed files if in PR mode
    changed_files = []
    if only_changed:
        changed_files = get_changed_files()
        print(f"📝 PR mode: Found {len(changed_files)} changed files")
    
    total_lines = 0
    file_priorities = []  # (priority, file_info)
    
    for root, dirs, files in os.walk(repo_path):
        # Skip common directories
        dirs[:] = [d for d in dirs if d not in {
            '.git', 'node_modules', 'venv', '__pycache__', 'dist', 'build', 
            '.next', 'target', 'vendor', '.gradle', '.idea', '.vscode'
        }]
        
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
                    
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        lines = len(content.split('\n'))
                        
                        # Prioritize files based on criticality
                        priority = 0
                        
                        # High priority: Security-sensitive files
                        if any(keyword in rel_path.lower() for keyword in ['auth', 'security', 'password', 'token', 'secret', 'crypto']):
                            priority += 100
                        
                        # High priority: API/Controllers
                        if any(keyword in rel_path.lower() for keyword in ['controller', 'api', 'route', 'handler', 'endpoint']):
                            priority += 50
                        
                        # Medium priority: Business logic
                        if any(keyword in rel_path.lower() for keyword in ['service', 'model', 'repository', 'dao']):
                            priority += 30
                        
                        # Changed files get highest priority
                        if only_changed:
                            priority += 200
                        
                        file_priorities.append((priority, {
                            'path': rel_path,
                            'content': content[:10000],  # Limit content size
                            'lines': lines,
                            'size': file_size
                        }))
                        
                except Exception as e:
                    print(f"Warning: Could not read {file_path}: {e}")
    
    # Sort by priority and take top N files
    file_priorities.sort(reverse=True, key=lambda x: x[0])
    important_files = [f[1] for f in file_priorities[:max_files]]
    
    total_lines = sum(f['lines'] for f in important_files)
    
    print(f"✅ Selected {len(important_files)} files ({total_lines} lines)")
    if file_priorities and len(file_priorities) > max_files:
        print(f"⚠️  {len(file_priorities) - max_files} files skipped (priority-based selection)")
    
    return important_files

def estimate_cost(files, max_tokens, provider):
    """Estimate cost before running analysis"""
    total_chars = sum(len(f['content']) for f in files)
    # Rough estimate: 4 chars per token
    estimated_input_tokens = total_chars // 4
    estimated_output_tokens = max_tokens
    
    if provider == 'anthropic':
        input_cost = (estimated_input_tokens / 1_000_000) * 3.0
        output_cost = (estimated_output_tokens / 1_000_000) * 15.0
    elif provider == 'openai':
        input_cost = (estimated_input_tokens / 1_000_000) * 10.0
        output_cost = (estimated_output_tokens / 1_000_000) * 30.0
    else:  # ollama
        input_cost = 0.0
        output_cost = 0.0
    
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
                    "version": "1.0.15",
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
    import re
    findings = []
    lines = report_text.split('\n')
    
    # Track current section for categorization
    current_section = None
    current_severity = None
    
    for i, line in enumerate(lines):
        # Detect sections
        if '## Critical Issues' in line or '## Critical' in line:
            current_severity = 'critical'
            continue
        elif '## High Priority' in line or '## High' in line:
            current_severity = 'high'
            continue
        elif '## Medium Priority' in line or '## Medium' in line:
            current_severity = 'medium'
            continue
        elif '## Low Priority' in line or '## Low' in line:
            current_severity = 'low'
            continue
        
        # Detect category subsections
        if '### Security' in line:
            current_section = 'security'
            continue
        elif '### Performance' in line:
            current_section = 'performance'
            continue
        elif '### Testing' in line or '### Test' in line:
            current_section = 'testing'
            continue
        elif '### Code Quality' in line or '### Quality' in line:
            current_section = 'quality'
            continue
        
        # Look for numbered findings (e.g., "1. **Issue Name**" or "14. **Issue Name**")
        numbered_match = re.match(r'^\d+\.\s+\*\*(.+?)\*\*\s*-?\s*`?([^`\n]+\.(?:ts|js|py|java|go|rs|rb|php|cs))?:?(\d+)?', line)
        if numbered_match:
            issue_name = numbered_match.group(1)
            file_path = numbered_match.group(2) if numbered_match.group(2) else 'unknown'
            line_num = int(numbered_match.group(3)) if numbered_match.group(3) else 1
            
            # Get description from next lines
            description_lines = []
            for j in range(i+1, min(i+5, len(lines))):
                if lines[j].strip() and not lines[j].startswith('#') and not re.match(r'^\d+\.', lines[j]):
                    description_lines.append(lines[j].strip())
                elif lines[j].startswith('#') or re.match(r'^\d+\.', lines[j]):
                    break
            
            description = ' '.join(description_lines[:2]) if description_lines else issue_name
            
            # Determine category and severity
            category = current_section or 'quality'
            severity = current_severity or 'medium'
            
            # Override category based on keywords
            lower_text = (issue_name + ' ' + description).lower()
            if any(kw in lower_text for kw in ['security', 'sql', 'xss', 'csrf', 'auth', 'jwt', 'secret', 'injection']):
                category = 'security'
            elif any(kw in lower_text for kw in ['performance', 'n+1', 'memory', 'leak', 'slow', 'inefficient']):
                category = 'performance'
            elif any(kw in lower_text for kw in ['test', 'coverage', 'testing']):
                category = 'testing'
            
            findings.append({
                'severity': severity,
                'category': category,
                'message': f"{issue_name}: {description[:200]}",
                'file_path': file_path,
                'line_number': line_num,
                'rule_id': f'{category.upper()}-{len([f for f in findings if f["category"] == category]) + 1:03d}'
            })
    
    return findings

def call_llm_api(client, provider, model, prompt, max_tokens):
    """Call LLM API with provider-specific handling"""
    if provider == 'anthropic':
        message = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}]
        )
        return message.content[0].text, message.usage.input_tokens, message.usage.output_tokens
    
    elif provider in ['openai', 'ollama']:
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens
        )
        input_tokens = response.usage.prompt_tokens
        output_tokens = response.usage.completion_tokens
        return response.choices[0].message.content, input_tokens, output_tokens
    
    else:
        raise ValueError(f"Unknown provider: {provider}")

def run_audit(repo_path, config, review_type='audit'):
    """Run AI-powered code audit with multi-LLM support"""
    
    metrics = ReviewMetrics()
    
    print(f"🤖 Starting AI-powered {review_type} analysis...")
    print(f"📁 Repository: {repo_path}")
    
    # Detect AI provider
    provider = detect_ai_provider(config)
    if not provider:
        print("❌ No AI provider available")
        print("\n💡 Available options:")
        print("   1. Anthropic Claude (Best quality)")
        print("      Get key: https://console.anthropic.com/")
        print("      Set: ANTHROPIC_API_KEY")
        print("\n   2. OpenAI GPT-4 (Good quality)")
        print("      Get key: https://platform.openai.com/api-keys")
        print("      Set: OPENAI_API_KEY")
        print("\n   3. Ollama (Free, local)")
        print("      Install: https://ollama.ai/")
        print("      Set: OLLAMA_ENDPOINT=http://localhost:11434")
        sys.exit(2)
    
    print(f"🔧 Provider: {provider}")
    metrics.metrics["provider"] = provider
    
    # Get AI client
    client, actual_provider = get_ai_client(provider, config)
    
    # Get model name
    model = get_model_name(provider, config)
    print(f"🧠 Model: {model}")
    metrics.metrics["model"] = model
    
    # Check cost limit
    cost_limit = float(config.get('cost_limit', 1.0))
    max_tokens = int(config.get('max_tokens', 8000))
    
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
    estimated_cost, est_input, est_output = estimate_cost(files, max_tokens, provider)
    if provider == 'ollama':
        print(f"💰 Estimated cost: $0.00 (local Ollama)")
    else:
        print(f"💰 Estimated cost: ${estimated_cost:.2f}")
    
    if estimated_cost > cost_limit and provider != 'ollama':
        print(f"⚠️  Estimated cost ${estimated_cost:.2f} exceeds limit ${cost_limit:.2f}")
        print(f"💡 Reduce max-files, use path filters, or increase cost-limit")
        sys.exit(2)
    
    # Build context for LLM
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

⚠️ IMPORTANT: This is AI-assisted code review. While AI can identify many issues,
human oversight is essential for:
- Architectural decisions and trade-offs
- Business logic correctness
- Context-specific security considerations
- Code maintainability and team conventions

Use this as a starting point for human review, not a replacement.
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

## Human Review Required
Note any areas where human judgment is essential (architecture, business logic, etc.)

Be specific with file names and line numbers. Use format: `filename.ext:123` for references.
"""
    
    print(f"🧠 Analyzing code with {provider} ({model})...")
    
    try:
        # Call LLM API
        report, input_tokens, output_tokens = call_llm_api(client, provider, model, prompt, max_tokens)
        
        # Record LLM metrics
        metrics.record_llm_call(input_tokens, output_tokens, provider)
        
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
            "version": "1.0.15",
            "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "repository": os.environ.get('GITHUB_REPOSITORY', 'unknown'),
            "commit": os.environ.get('GITHUB_SHA', 'unknown'),
            "provider": provider,
            "model": model,
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
        blocker_count = metrics.metrics['findings']['critical'] + metrics.metrics['findings']['high']
        suggestion_count = metrics.metrics['findings']['medium'] + metrics.metrics['findings']['low']
        
        print(f"\n📊 Results:")
        print(f"   Critical: {metrics.metrics['findings']['critical']}")
        print(f"   High: {metrics.metrics['findings']['high']}")
        print(f"   Medium: {metrics.metrics['findings']['medium']}")
        print(f"   Low: {metrics.metrics['findings']['low']}")
        print(f"\n💰 Cost: ${metrics.metrics['cost_usd']:.2f}")
        print(f"⏱️  Duration: {metrics.metrics['duration_seconds']}s")
        print(f"🔧 Provider: {provider} ({model})")
        
        # Check fail-on conditions
        fail_on = config.get('fail_on', '')
        should_fail = False
        
        if fail_on:
            print(f"\n🚦 Checking fail conditions: {fail_on}")
            conditions = [c.strip() for c in fail_on.split(',') if c.strip()]
            
            for condition in conditions:
                if ':' in condition:
                    category, severity = condition.split(':', 1)
                    category = category.strip().lower()
                    severity = severity.strip().lower()
                    
                    # Check if condition is met
                    if category == 'any':
                        # any:critical means any category with critical severity
                        if severity in metrics.metrics['findings'] and metrics.metrics['findings'][severity] > 0:
                            print(f"   ❌ FAIL: Found {metrics.metrics['findings'][severity]} {severity} issues")
                            should_fail = True
                    else:
                        # Check specific category:severity combination
                        matching_findings = [f for f in findings 
                                           if f['category'] == category and f['severity'] == severity]
                        if matching_findings:
                            print(f"   ❌ FAIL: Found {len(matching_findings)} {category}:{severity} issues")
                            should_fail = True
        
        # Output for GitHub Actions (using GITHUB_OUTPUT)
        github_output = os.environ.get('GITHUB_OUTPUT')
        if github_output:
            with open(github_output, 'a') as f:
                f.write(f"blockers={blocker_count}\n")
                f.write(f"suggestions={suggestion_count}\n")
                f.write(f"report-path={report_file}\n")
                f.write(f"sarif-path={sarif_file}\n")
                f.write(f"json-path={json_file}\n")
                f.write(f"cost-estimate={metrics.metrics['cost_usd']:.2f}\n")
                f.write(f"files-analyzed={metrics.metrics['files_reviewed']}\n")
                f.write(f"duration-seconds={metrics.metrics['duration_seconds']}\n")
        else:
            # Fallback for local testing
            print(f"\nblockers={blocker_count}")
            print(f"suggestions={suggestion_count}")
            print(f"report-path={report_file}")
            print(f"sarif-path={sarif_file}")
            print(f"json-path={json_file}")
            print(f"cost-estimate={metrics.metrics['cost_usd']:.2f}")
            print(f"files-analyzed={metrics.metrics['files_reviewed']}")
            print(f"duration-seconds={metrics.metrics['duration_seconds']}")
        
        # Exit with appropriate code
        if should_fail:
            print(f"\n❌ Failing due to fail-on conditions")
            sys.exit(1)
        
        return blocker_count, suggestion_count, metrics
        
    except Exception as e:
        print(f"❌ Error during AI analysis: {e}")
        print(f"Error type: {type(e).__name__}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    repo_path = sys.argv[1] if len(sys.argv) > 1 else '.'
    review_type = sys.argv[2] if len(sys.argv) > 2 else 'audit'
    
    # Get configuration from environment
    config = {
        'ai_provider': os.environ.get('INPUT_AI_PROVIDER', 'auto'),
        'anthropic_api_key': os.environ.get('ANTHROPIC_API_KEY', ''),
        'openai_api_key': os.environ.get('OPENAI_API_KEY', ''),
        'ollama_endpoint': os.environ.get('OLLAMA_ENDPOINT', ''),
        'model': os.environ.get('INPUT_MODEL', 'auto'),
        'only_changed': os.environ.get('INPUT_ONLY_CHANGED', 'false').lower() == 'true',
        'include_paths': os.environ.get('INPUT_INCLUDE_PATHS', ''),
        'exclude_paths': os.environ.get('INPUT_EXCLUDE_PATHS', ''),
        'max_file_size': os.environ.get('INPUT_MAX_FILE_SIZE', '50000'),
        'max_files': os.environ.get('INPUT_MAX_FILES', '100'),
        'max_tokens': os.environ.get('INPUT_MAX_TOKENS', '8000'),
        'cost_limit': os.environ.get('INPUT_COST_LIMIT', '1.0'),
        'fail_on': os.environ.get('INPUT_FAIL_ON', ''),
    }
    
    run_audit(repo_path, config, review_type)
