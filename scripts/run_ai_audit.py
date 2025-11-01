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
import logging
from pathlib import Path
from datetime import datetime, timezone
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ReviewMetrics:
    """Track observability metrics for the review"""
    def __init__(self):
        self.start_time = time.time()
        self.metrics = {
            "version": "1.0.16",
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
            },
            # NEW: Exploit analysis metrics
            "exploitability": {
                "trivial": 0,
                "moderate": 0,
                "complex": 0,
                "theoretical": 0
            },
            "exploit_chains_found": 0,
            "tests_generated": 0,
            # NEW: Agent execution tracking
            "agents_executed": [],
            "agent_execution_times": {}
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

    def record_exploitability(self, exploitability_level):
        """Record exploitability classification

        Args:
            exploitability_level: One of 'trivial', 'moderate', 'complex', 'theoretical'
        """
        level = exploitability_level.lower()
        if level in self.metrics["exploitability"]:
            self.metrics["exploitability"][level] += 1

    def record_exploit_chain(self):
        """Record that an exploit chain was identified"""
        self.metrics["exploit_chains_found"] += 1

    def record_test_generated(self, count=1):
        """Record number of security tests generated

        Args:
            count: Number of test files generated (default: 1)
        """
        self.metrics["tests_generated"] += count

    def record_agent_execution(self, agent_name, duration_seconds):
        """Record agent execution for observability

        Args:
            agent_name: Name of the agent (e.g., 'exploit-analyst')
            duration_seconds: Time taken to execute the agent
        """
        if agent_name not in self.metrics["agents_executed"]:
            self.metrics["agents_executed"].append(agent_name)
        self.metrics["agent_execution_times"][agent_name] = duration_seconds

    def finalize(self):
        self.metrics["duration_seconds"] = int(time.time() - self.start_time)
        return self.metrics

    def save(self, path):
        with open(path, 'w') as f:
            json.dump(self.metrics, f, indent=2)
        print(f"📊 Metrics saved to: {path}")


class CostLimitExceeded(Exception):
    """Raised when cost limit would be exceeded by an operation"""
    pass


class CostCircuitBreaker:
    """Runtime cost enforcement to prevent budget overruns

    This class provides real-time cost tracking and enforcement:
    - Checks before each LLM call if limit would be exceeded
    - Maintains 10% safety buffer to prevent overage
    - Logs warnings at 50%, 75%, 90% thresholds
    - Raises CostLimitExceeded when limit reached

    Example:
        breaker = CostCircuitBreaker(cost_limit_usd=1.0)
        breaker.check_before_call(estimated_cost=0.15, provider='anthropic')
        # ... make LLM call ...
        breaker.record_actual_cost(0.14)
    """

    def __init__(self, cost_limit_usd: float, safety_buffer_percent: float = 10.0):
        """Initialize cost circuit breaker

        Args:
            cost_limit_usd: Maximum cost allowed in USD
            safety_buffer_percent: Safety buffer percentage (default: 10%)
        """
        self.cost_limit = cost_limit_usd
        self.safety_buffer = safety_buffer_percent / 100.0
        self.effective_limit = cost_limit_usd * (1.0 - self.safety_buffer)
        self.current_cost = 0.0
        self.warned_thresholds = set()

        logger.info(f"💰 Cost Circuit Breaker initialized: ${cost_limit_usd:.2f} limit "
                   f"(${self.effective_limit:.2f} effective with {safety_buffer_percent}% buffer)")

    def check_before_call(self, estimated_cost: float, provider: str, operation: str = "LLM call"):
        """Check if estimated cost would exceed limit

        Args:
            estimated_cost: Estimated cost of the operation in USD
            provider: AI provider name (for logging)
            operation: Description of operation (for logging)

        Raises:
            CostLimitExceeded: If operation would exceed cost limit
        """
        projected_cost = self.current_cost + estimated_cost
        utilization = (self.current_cost / self.effective_limit) * 100 if self.effective_limit > 0 else 0

        # Check threshold warnings (50%, 75%, 90%)
        for threshold in [50, 75, 90]:
            if utilization >= threshold and threshold not in self.warned_thresholds:
                self.warned_thresholds.add(threshold)
                logger.warning(f"⚠️  Cost at {utilization:.1f}% of limit "
                             f"(${self.current_cost:.3f} / ${self.effective_limit:.2f})")

        # Check if we would exceed the limit
        if projected_cost > self.effective_limit:
            remaining = self.effective_limit - self.current_cost
            message = (
                f"Cost limit exceeded! "
                f"Operation would cost ${estimated_cost:.3f}, "
                f"but only ${remaining:.3f} remaining of ${self.cost_limit:.2f} limit. "
                f"Current cost: ${self.current_cost:.3f}"
            )
            logger.error(f"🚨 {message}")
            raise CostLimitExceeded(message)

        # Log the check
        logger.debug(f"✓ Cost check passed: ${estimated_cost:.3f} {operation} ({provider}), "
                    f"projected: ${projected_cost:.3f} / ${self.effective_limit:.2f}")

    def record_actual_cost(self, actual_cost: float):
        """Record actual cost after operation completes

        Args:
            actual_cost: Actual cost incurred in USD
        """
        self.current_cost += actual_cost
        logger.debug(f"💵 Cost updated: +${actual_cost:.3f} → ${self.current_cost:.3f}")

    def get_remaining_budget(self) -> float:
        """Get remaining budget in USD

        Returns:
            Remaining budget considering safety buffer
        """
        return max(0.0, self.effective_limit - self.current_cost)

    def get_utilization_percent(self) -> float:
        """Get current cost utilization as percentage

        Returns:
            Utilization percentage (0-100+)
        """
        if self.effective_limit == 0:
            return 0.0
        return (self.current_cost / self.effective_limit) * 100

    def get_summary(self) -> dict:
        """Get cost summary for reporting

        Returns:
            Dictionary with cost details
        """
        return {
            "cost_limit_usd": self.cost_limit,
            "effective_limit_usd": self.effective_limit,
            "safety_buffer_percent": self.safety_buffer * 100,
            "current_cost_usd": self.current_cost,
            "remaining_budget_usd": self.get_remaining_budget(),
            "utilization_percent": self.get_utilization_percent(),
            "limit_exceeded": self.current_cost > self.effective_limit
        }


# Available agents for multi-agent mode
AVAILABLE_AGENTS = [
    'security-reviewer',
    'exploit-analyst',
    'security-test-generator',
    'performance-reviewer',
    'test-coverage-reviewer',
    'code-quality-reviewer',
    'review-orchestrator'
]

# Agent execution order for security workflow
SECURITY_WORKFLOW_AGENTS = [
    'security-reviewer',
    'exploit-analyst',
    'security-test-generator'
]

# Agents that can run in parallel (quality analysis)
PARALLEL_QUALITY_AGENTS = [
    'performance-reviewer',
    'test-coverage-reviewer',
    'code-quality-reviewer'
]

# Cost estimates (approximate, based on Claude Sonnet 4)
COST_ESTIMATES = {
    'single_agent': 0.20,
    'multi_agent_sequential': 1.00,
    'per_agent': {
        'security-reviewer': 0.10,
        'exploit-analyst': 0.05,
        'security-test-generator': 0.05,
        'performance-reviewer': 0.08,
        'test-coverage-reviewer': 0.08,
        'code-quality-reviewer': 0.08,
        'review-orchestrator': 0.06
    }
}

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
        'anthropic': 'claude-sonnet-4-5-20250929',
        'openai': 'gpt-4-turbo-preview',
        'ollama': 'llama3'
    }

    return defaults.get(provider, 'claude-sonnet-4-5-20250929')

def get_working_model_with_fallback(client, provider, initial_model):
    """Try to find a working model using fallback chain for Anthropic"""
    if provider != 'anthropic':
        return initial_model

    # Model fallback chain for Anthropic (most universally available first)
    MODEL_FALLBACK_CHAIN = [
        initial_model,  # Try user's requested model first
        'claude-3-haiku-20240307',  # Most lightweight and universally available
        'claude-3-sonnet-20240229',  # Balanced
        'claude-sonnet-4-5-20250929',  # Latest Claude Sonnet 4.5
        'claude-3-5-sonnet-20241022',  # Claude 3.5 Sonnet
        'claude-3-5-sonnet-20240620',  # Stable
        'claude-3-opus-20240229',  # Most powerful
    ]

    # Remove duplicates while preserving order
    seen = set()
    unique_models = []
    for model in MODEL_FALLBACK_CHAIN:
        if model not in seen:
            seen.add(model)
            unique_models.append(model)

    logger.info(f"Testing model accessibility for provider: {provider}")

    for model_id in unique_models:
        try:
            # Quick test with minimal tokens
            logger.debug(f"Testing model: {model_id}")
            message = client.messages.create(
                model=model_id,
                max_tokens=10,
                messages=[{"role": "user", "content": "test"}]
            )
            logger.info(f"✅ Found working model: {model_id}")
            return model_id
        except Exception as e:
            error_type = type(e).__name__
            logger.debug(f"Model {model_id} not accessible: {error_type}")

            # If authentication fails, stop trying
            if 'Authentication' in error_type or 'auth' in str(e).lower():
                logger.error(f"Authentication failed with API key")
                raise

            continue

    # If no model works, raise error with helpful message
    logger.error("No accessible Claude models found with this API key")
    raise RuntimeError(
        "❌ No Claude models are accessible with your API key.\n"
        "Tried models: " + ", ".join(unique_models) + "\n"
        "Please check:\n"
        "1. API key has correct permissions at https://console.anthropic.com/\n"
        "2. Account has billing enabled\n"
        "3. API key is from correct workspace/organization\n"
        "4. Contact support@anthropic.com if issue persists"
    )

def get_changed_files():
    """Get list of changed files in PR with improved error handling"""
    try:
        result = subprocess.run(
            ['git', 'diff', '--name-only', 'HEAD^', 'HEAD'],
            capture_output=True,
            text=True,
            check=True,
            timeout=30
        )
        changed_files = [f.strip() for f in result.stdout.split('\n') if f.strip()]
        logger.info(f"Found {len(changed_files)} changed files")
        return changed_files
    except subprocess.TimeoutExpired:
        logger.warning("Git diff timed out after 30 seconds")
        return []
    except subprocess.CalledProcessError as e:
        # Not necessarily an error - might not be in a PR context
        logger.debug(f"Git diff failed (stderr: {e.stderr}). This is normal if not in a PR context.")
        return []
    except FileNotFoundError:
        logger.warning("Git not found in PATH. Ensure git is installed.")
        return []
    except Exception as e:
        logger.error(f"Unexpected error getting changed files: {type(e).__name__}: {e}")
        return []

def matches_glob_patterns(file_path, patterns):
    """Check if file matches any glob pattern"""
    if not patterns:
        return False
    from pathlib import Path
    for pattern in patterns:
        # Use pathlib's match for better glob support including **
        if Path(file_path).match(pattern):
            return True
        # Fallback to fnmatch for simple patterns
        elif glob.fnmatch.fnmatch(file_path, pattern):
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

def estimate_review_cost(mode='single', num_files=50):
    """Estimate cost of review based on mode and file count

    Args:
        mode: 'single' or 'multi'
        num_files: Number of files to review

    Returns:
        Estimated cost in USD
    """
    if mode == 'single':
        base_cost = COST_ESTIMATES['single_agent']
    else:
        base_cost = COST_ESTIMATES['multi_agent_sequential']

    # Adjust for file count
    file_factor = num_files / 50.0  # 50 files is baseline
    estimated_cost = base_cost * file_factor

    return round(estimated_cost, 2)

def map_exploitability_to_score(exploitability):
    """Map exploitability level to numeric score for SARIF

    Args:
        exploitability: String like 'trivial', 'moderate', 'complex', 'theoretical'

    Returns:
        Numeric score (0-10)
    """
    mapping = {
        'trivial': 10,      # Highest exploitability
        'moderate': 7,
        'complex': 4,
        'theoretical': 1    # Lowest exploitability
    }
    return mapping.get(exploitability.lower(), 5)

def map_severity_to_sarif(severity):
    """Map severity to SARIF level

    Args:
        severity: String like 'critical', 'high', 'medium', 'low', 'info'

    Returns:
        SARIF level string
    """
    mapping = {
        'critical': 'error',
        'high': 'error',
        'medium': 'warning',
        'low': 'note',
        'info': 'note'
    }
    return mapping.get(severity.lower(), 'warning')

def generate_sarif(findings, repo_path, metrics=None):
    """Generate SARIF 2.1.0 format for GitHub Code Scanning with exploitability data

    Args:
        findings: List of vulnerability findings
        repo_path: Path to repository
        metrics: Optional ReviewMetrics instance

    Returns:
        SARIF dictionary
    """
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Agent OS Code Reviewer",
                    "version": "1.0.16",
                    "informationUri": "https://github.com/securedotcom/agent-os-action",
                    "rules": []
                }
            },
            "results": []
        }]
    }

    for finding in findings:
        result = {
            "ruleId": finding.get('rule_id', 'AGENT-OS-001'),
            "level": map_severity_to_sarif(finding.get('severity', 'medium')),
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

        # Add properties
        properties = {}

        if 'cwe' in finding:
            properties['cwe'] = finding['cwe']

        # NEW: Add exploitability as a property
        if 'exploitability' in finding:
            properties['exploitability'] = finding['exploitability']
            properties['exploitabilityScore'] = map_exploitability_to_score(
                finding['exploitability']
            )

        # NEW: Add exploit chain reference if part of a chain
        if 'part_of_chain' in finding:
            properties['exploitChain'] = finding['part_of_chain']

        # NEW: Add generated tests reference
        if 'tests_generated' in finding:
            properties['testsGenerated'] = finding['tests_generated']

        if properties:
            result['properties'] = properties

        sarif['runs'][0]['results'].append(result)

    # Add run properties with metrics
    if metrics:
        sarif['runs'][0]['properties'] = {
            'exploitability': metrics.metrics['exploitability'],
            'exploitChainsFound': metrics.metrics['exploit_chains_found'],
            'testsGenerated': metrics.metrics['tests_generated'],
            'agentsExecuted': metrics.metrics['agents_executed']
        }

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

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=4, max=10),
    retry=retry_if_exception_type((ConnectionError, TimeoutError)),
    before_sleep=before_sleep_log(logger, logging.WARNING),
    reraise=True
)
def estimate_call_cost(prompt_length: int, max_output_tokens: int, provider: str) -> float:
    """Estimate cost of a single LLM API call before making it (for circuit breaker)

    Args:
        prompt_length: Character length of prompt (rough proxy for tokens)
        max_output_tokens: Maximum output tokens requested
        provider: AI provider name

    Returns:
        Estimated cost in USD
    """
    # Rough estimation: 1 token ≈ 4 characters
    estimated_input_tokens = prompt_length / 4
    estimated_output_tokens = max_output_tokens * 0.7  # Assume 70% of max is used

    if provider == 'anthropic':
        # Claude Sonnet 4.5: $3/1M input, $15/1M output
        input_cost = (estimated_input_tokens / 1_000_000) * 3.0
        output_cost = (estimated_output_tokens / 1_000_000) * 15.0
    elif provider == 'openai':
        # GPT-4: $10/1M input, $30/1M output
        input_cost = (estimated_input_tokens / 1_000_000) * 10.0
        output_cost = (estimated_output_tokens / 1_000_000) * 30.0
    else:
        # Ollama: Free (local)
        input_cost = 0.0
        output_cost = 0.0

    return input_cost + output_cost


def call_llm_api(client, provider, model, prompt, max_tokens, circuit_breaker=None, operation="LLM call"):
    """Call LLM API with retry logic and cost enforcement

    Args:
        client: AI client instance
        provider: AI provider name
        model: Model name
        prompt: Prompt text
        max_tokens: Maximum output tokens
        circuit_breaker: Optional CostCircuitBreaker for cost enforcement
        operation: Description of operation for logging

    Returns:
        Tuple of (response_text, input_tokens, output_tokens)

    Raises:
        CostLimitExceeded: If cost limit would be exceeded
    """
    # Estimate cost and check circuit breaker before making call
    if circuit_breaker:
        estimated_cost = estimate_call_cost(len(prompt), max_tokens, provider)
        circuit_breaker.check_before_call(estimated_cost, provider, operation)

    try:
        if provider == 'anthropic':
            message = client.messages.create(
                model=model,
                max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}],
                timeout=300.0  # 5 minute timeout
            )
            response_text = message.content[0].text
            input_tokens = message.usage.input_tokens
            output_tokens = message.usage.output_tokens

        elif provider in ['openai', 'ollama']:
            response = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=max_tokens,
                timeout=300.0  # 5 minute timeout
            )
            response_text = response.choices[0].message.content
            input_tokens = response.usage.prompt_tokens
            output_tokens = response.usage.completion_tokens

        else:
            raise ValueError(f"Unknown provider: {provider}")

        # Record actual cost after successful call
        if circuit_breaker:
            actual_cost = calculate_actual_cost(input_tokens, output_tokens, provider)
            circuit_breaker.record_actual_cost(actual_cost)

        return response_text, input_tokens, output_tokens

    except Exception as e:
        logger.error(f"LLM API call failed: {type(e).__name__}: {e}")
        raise


def calculate_actual_cost(input_tokens: int, output_tokens: int, provider: str) -> float:
    """Calculate actual cost after LLM call completes

    Args:
        input_tokens: Actual input tokens used
        output_tokens: Actual output tokens used
        provider: AI provider name

    Returns:
        Actual cost in USD
    """
    if provider == 'anthropic':
        input_cost = (input_tokens / 1_000_000) * 3.0
        output_cost = (output_tokens / 1_000_000) * 15.0
    elif provider == 'openai':
        input_cost = (input_tokens / 1_000_000) * 10.0
        output_cost = (output_tokens / 1_000_000) * 30.0
    else:
        input_cost = 0.0
        output_cost = 0.0

    return input_cost + output_cost

def load_agent_prompt(agent_name):
    """Load specialized agent prompt from profiles"""
    agent_prompts = {
        'security': 'security-agent-prompt.md',
        'security-reviewer': 'security-reviewer.md',
        'exploit-analyst': 'exploit-analyst.md',
        'security-test-generator': 'security-test-generator.md',
        'performance': 'performance-agent-prompt.md',
        'performance-reviewer': 'performance-reviewer.md',
        'testing': 'testing-agent-prompt.md',
        'test-coverage-reviewer': 'test-coverage-reviewer.md',
        'quality': 'quality-agent-prompt.md',
        'code-quality-reviewer': 'code-quality-reviewer.md',
        'orchestrator': 'orchestrator-agent-prompt.md',
        'review-orchestrator': 'review-orchestrator.md'
    }

    prompt_file = agent_prompts.get(agent_name)
    if not prompt_file:
        # Fallback: try to find prompt file by agent name
        prompt_file = f'{agent_name}.md'

    # Try multiple locations
    possible_paths = [
        Path.home() / f'.agent-os/profiles/default/agents/{prompt_file}',
        Path.home() / f'.agent-os/profiles/default/agents/{agent_name}.md',
        Path('.agent-os') / f'profiles/default/agents/{prompt_file}',
        Path('.agent-os') / f'profiles/default/agents/{agent_name}.md'
    ]

    for prompt_path in possible_paths:
        if prompt_path.exists():
            with open(prompt_path, 'r') as f:
                return f.read()

    print(f"⚠️  Agent prompt not found for: {agent_name}")
    return f"You are a {agent_name} code reviewer. Analyze the code for {agent_name}-related issues."

def run_multi_agent_sequential(repo_path, config, review_type, client, provider, model, max_tokens, files, metrics, circuit_breaker):
    """Run multi-agent sequential review with specialized agents and cost enforcement"""

    print("\n" + "="*80)
    print("🤖 MULTI-AGENT SEQUENTIAL MODE")
    print("="*80)
    print("Running 7 specialized agents in sequence:")
    print("  1️⃣  Security Reviewer")
    print("  2️⃣  Exploit Analyst")
    print("  3️⃣  Security Test Generator")
    print("  4️⃣  Performance Reviewer")
    print("  5️⃣  Testing Reviewer")
    print("  6️⃣  Code Quality Reviewer")
    print("  7️⃣  Review Orchestrator")
    print("="*80 + "\n")

    # Build codebase context once
    codebase_context = "\n\n".join([
        f"File: {f['path']}\n```\n{f['content']}\n```"
        for f in files
    ])

    # Store agent findings
    agent_reports = {}
    agent_metrics = {}

    # Define agents in execution order (security workflow first)
    agents = ['security', 'exploit-analyst', 'security-test-generator', 'performance', 'testing', 'quality']
    
    # Run each specialized agent
    for i, agent_name in enumerate(agents, 1):
        print(f"\n{'─'*80}")
        print(f"🔍 Agent {i}/7: {agent_name.upper()} REVIEWER")
        print(f"{'─'*80}")

        agent_start = time.time()

        # Load agent-specific prompt
        agent_prompt_template = load_agent_prompt(agent_name)

        # For exploit-analyst and security-test-generator, pass security findings
        if agent_name in ['exploit-analyst', 'security-test-generator']:
            # Use security findings as context
            security_context = agent_reports.get('security', '')
            agent_prompt = f"""{agent_prompt_template}

## Previous Agent Findings

The Security Reviewer has identified the following vulnerabilities:

{security_context}

## Codebase to Analyze

{codebase_context}

## Your Task

{'Analyze the exploitability of the vulnerabilities identified above.' if agent_name == 'exploit-analyst' else 'Generate security tests for the vulnerabilities identified above.'}

Provide detailed analysis in your specialized format.
"""
        else:
            # Create agent-specific prompt
            agent_prompt = f"""{agent_prompt_template}

## Codebase to Analyze

{codebase_context}

## Your Task

Analyze the above codebase from your specialized perspective as a {agent_name} reviewer.
Focus ONLY on {agent_name}-related issues. Do not analyze areas outside your responsibility.

Provide your findings in this format:

# {agent_name.title()} Review Report

## Summary
- Total {agent_name} issues found: X
- Critical: X
- High: X
- Medium: X
- Low: X

## Critical Issues

### [CRITICAL] Issue Title - `file.ext:line`
**Category**: [Specific subcategory]
**Impact**: Description of impact
**Evidence**: Code snippet
**Recommendation**: Fix with code example

[Repeat for each critical issue]

## High Priority Issues

[Same format as critical]

## Medium Priority Issues

[Same format]

## Low Priority Issues

[Same format]

Be specific with file paths and line numbers. Focus on actionable, real issues.
"""

        try:
            print(f"   🧠 Analyzing with {model}...")
            report, input_tokens, output_tokens = call_llm_api(
                client, provider, model, agent_prompt, max_tokens,
                circuit_breaker=circuit_breaker,
                operation=f"{agent_name} agent review"
            )

            agent_duration = time.time() - agent_start

            # Record metrics for this agent
            metrics.record_llm_call(input_tokens, output_tokens, provider)
            metrics.record_agent_execution(agent_name, agent_duration)

            agent_metrics[agent_name] = {
                'duration_seconds': round(agent_duration, 2),
                'input_tokens': input_tokens,
                'output_tokens': output_tokens,
                'cost_usd': round((input_tokens / 1_000_000) * 3.0 + (output_tokens / 1_000_000) * 15.0, 4) if provider == 'anthropic' else 0
            }

            # Store report
            agent_reports[agent_name] = report

            # Parse findings for metrics
            findings = parse_findings_from_report(report)
            finding_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            for finding in findings:
                if finding['severity'] in finding_counts:
                    finding_counts[finding['severity']] += 1
                    metrics.record_finding(finding['severity'], agent_name)

                # Extract exploitability if present (from exploit-analyst)
                if agent_name == 'exploit-analyst' and 'exploitability' in finding:
                    metrics.record_exploitability(finding['exploitability'])

            # Extract exploit chains from report text (simple heuristic)
            if agent_name == 'exploit-analyst':
                exploit_chain_count = report.lower().count('exploit chain')
                for _ in range(exploit_chain_count):
                    metrics.record_exploit_chain()

            # Extract test generation count from report
            if agent_name == 'security-test-generator':
                test_count = report.lower().count('test file:') + report.lower().count('test case:')
                if test_count > 0:
                    metrics.record_test_generated(test_count)

            print(f"   ✅ Complete: {finding_counts['critical']} critical, {finding_counts['high']} high, {finding_counts['medium']} medium, {finding_counts['low']} low")
            print(f"   ⏱️  Duration: {agent_duration:.1f}s | 💰 Cost: ${agent_metrics[agent_name]['cost_usd']:.4f}")

        except CostLimitExceeded as e:
            # Cost limit reached - stop immediately
            print(f"   🚨 Cost limit exceeded: {e}")
            print(f"   💰 Review stopped at ${circuit_breaker.current_cost:.3f} to stay within ${circuit_breaker.cost_limit:.2f} budget")
            print(f"   ✅ {i-1}/{len(agents)} agents completed before limit reached")

            # Generate partial report with agents completed so far
            agent_reports[agent_name] = f"# {agent_name.title()} Review Skipped\n\n**Reason**: Cost limit reached (${circuit_breaker.cost_limit:.2f})\n"
            raise  # Re-raise to stop the entire review

        except Exception as e:
            print(f"   ❌ Error: {e}")
            agent_reports[agent_name] = f"# {agent_name.title()} Review Failed\n\nError: {str(e)}"
            agent_metrics[agent_name] = {'error': str(e)}
    
    # Run orchestrator agent
    print(f"\n{'─'*80}")
    print(f"🎯 Agent 7/7: ORCHESTRATOR")
    print(f"{'─'*80}")
    print("   🔄 Aggregating findings from all agents...")

    orchestrator_start = time.time()

    # Load orchestrator prompt
    orchestrator_prompt_template = load_agent_prompt('orchestrator')

    # Combine all agent reports
    combined_reports = "\n\n" + "="*80 + "\n\n".join([
        f"# {name.upper()} AGENT FINDINGS\n\n{report}"
        for name, report in agent_reports.items()
    ])

    # Create orchestrator prompt
    orchestrator_prompt = f"""{orchestrator_prompt_template}

## Agent Reports to Synthesize

You have received findings from 6 specialized agents:

{combined_reports}

## Your Task

Synthesize these findings into a comprehensive, actionable audit report.

1. **Deduplicate**: Remove identical issues reported by multiple agents
2. **Prioritize**: Order by exploitability and business impact
3. **Aggregate**: Combine related findings
4. **Decide**: Make clear APPROVED / REQUIRES FIXES / DO NOT MERGE recommendation
5. **Action Plan**: Create sequenced, logical action items prioritized by exploitability

Pay special attention to:
- Exploitability analysis from the Exploit Analyst
- Security tests generated by the Security Test Generator
- Exploit chains that link multiple vulnerabilities

Generate the complete audit report as specified in your instructions.
"""

    try:
        print(f"   🧠 Synthesizing with {model}...")
        final_report, input_tokens, output_tokens = call_llm_api(
            client, provider, model, orchestrator_prompt, max_tokens,
            circuit_breaker=circuit_breaker,
            operation="orchestrator synthesis"
        )

        orchestrator_duration = time.time() - orchestrator_start

        # Record orchestrator metrics
        metrics.record_llm_call(input_tokens, output_tokens, provider)
        metrics.record_agent_execution('orchestrator', orchestrator_duration)

        agent_metrics['orchestrator'] = {
            'duration_seconds': round(orchestrator_duration, 2),
            'input_tokens': input_tokens,
            'output_tokens': output_tokens,
            'cost_usd': round((input_tokens / 1_000_000) * 3.0 + (output_tokens / 1_000_000) * 15.0, 4) if provider == 'anthropic' else 0
        }

        print(f"   ✅ Synthesis complete")
        print(f"   ⏱️  Duration: {orchestrator_duration:.1f}s | 💰 Cost: ${agent_metrics['orchestrator']['cost_usd']:.4f}")

    except CostLimitExceeded as e:
        # Cost limit reached during orchestration
        print(f"   🚨 Cost limit exceeded during synthesis: {e}")
        print(f"   📊 Generating report from {len(agent_reports)} completed agents")
        # Fall through to generate partial report

    except Exception as e:
        print(f"   ❌ Error: {e}")

    # Fallback: concatenate all reports (used if orchestrator fails OR cost limit reached)
    if 'final_report' not in locals():
        final_report = f"""# Codebase Audit Report (Multi-Agent Sequential)

## Note
Orchestrator synthesis failed. Below are individual agent reports.

{combined_reports}
"""
        agent_metrics['orchestrator'] = {'error': str(e)}
    
    # Add multi-agent metadata to final report
    total_cost = sum(m.get('cost_usd', 0) for m in agent_metrics.values())
    total_duration = sum(m.get('duration_seconds', 0) for m in agent_metrics.values())
    
    multi_agent_summary = f"""
---

## Multi-Agent Review Metrics

**Mode**: Sequential (7 agents)
**Total Duration**: {total_duration:.1f}s
**Total Cost**: ${total_cost:.4f}

### Agent Performance
| Agent | Duration | Cost | Status |
|-------|----------|------|--------|
| Security | {agent_metrics.get('security', {}).get('duration_seconds', 'N/A')}s | ${agent_metrics.get('security', {}).get('cost_usd', 0):.4f} | {'✅' if 'error' not in agent_metrics.get('security', {}) else '❌'} |
| Exploit Analyst | {agent_metrics.get('exploit-analyst', {}).get('duration_seconds', 'N/A')}s | ${agent_metrics.get('exploit-analyst', {}).get('cost_usd', 0):.4f} | {'✅' if 'error' not in agent_metrics.get('exploit-analyst', {}) else '❌'} |
| Security Test Generator | {agent_metrics.get('security-test-generator', {}).get('duration_seconds', 'N/A')}s | ${agent_metrics.get('security-test-generator', {}).get('cost_usd', 0):.4f} | {'✅' if 'error' not in agent_metrics.get('security-test-generator', {}) else '❌'} |
| Performance | {agent_metrics.get('performance', {}).get('duration_seconds', 'N/A')}s | ${agent_metrics.get('performance', {}).get('cost_usd', 0):.4f} | {'✅' if 'error' not in agent_metrics.get('performance', {}) else '❌'} |
| Testing | {agent_metrics.get('testing', {}).get('duration_seconds', 'N/A')}s | ${agent_metrics.get('testing', {}).get('cost_usd', 0):.4f} | {'✅' if 'error' not in agent_metrics.get('testing', {}) else '❌'} |
| Quality | {agent_metrics.get('quality', {}).get('duration_seconds', 'N/A')}s | ${agent_metrics.get('quality', {}).get('cost_usd', 0):.4f} | {'✅' if 'error' not in agent_metrics.get('quality', {}) else '❌'} |
| Orchestrator | {agent_metrics.get('orchestrator', {}).get('duration_seconds', 'N/A')}s | ${agent_metrics.get('orchestrator', {}).get('cost_usd', 0):.4f} | {'✅' if 'error' not in agent_metrics.get('orchestrator', {}) else '❌'} |

### Exploitability Metrics
- **Trivial**: {metrics.metrics['exploitability']['trivial']} (fix within 24-48 hours)
- **Moderate**: {metrics.metrics['exploitability']['moderate']} (fix within 1 week)
- **Complex**: {metrics.metrics['exploitability']['complex']} (fix within 1 month)
- **Theoretical**: {metrics.metrics['exploitability']['theoretical']} (fix in next release)

### Security Testing
- **Exploit Chains Found**: {metrics.metrics['exploit_chains_found']}
- **Security Tests Generated**: {metrics.metrics['tests_generated']}

---

*This report was generated by Agent OS Multi-Agent Sequential Review System*
"""
    
    final_report += multi_agent_summary
    
    # Save individual agent reports
    report_dir = Path(repo_path) / '.agent-os/reviews'
    report_dir.mkdir(parents=True, exist_ok=True)
    
    agents_dir = report_dir / 'agents'
    agents_dir.mkdir(exist_ok=True)
    
    for agent_name, report in agent_reports.items():
        agent_file = agents_dir / f'{agent_name}-report.md'
        with open(agent_file, 'w') as f:
            f.write(report)
        print(f"   📄 Saved: {agent_file}")
    
    # Save agent metrics
    agent_metrics_file = agents_dir / 'metrics.json'
    with open(agent_metrics_file, 'w') as f:
        json.dump(agent_metrics, f, indent=2)
    
    print(f"\n{'='*80}")
    print(f"✅ MULTI-AGENT REVIEW COMPLETE")
    print(f"{'='*80}")
    print(f"📊 Total Cost: ${total_cost:.4f}")
    print(f"⏱️  Total Duration: {total_duration:.1f}s")
    print(f"🤖 Agents: 7 (Security, Exploit Analyst, Security Test Generator, Performance, Testing, Quality, Orchestrator)")

    # Display exploitability summary
    if any(metrics.metrics['exploitability'].values()):
        print(f"\n⚠️  Exploitability Breakdown:")
        print(f"   Trivial: {metrics.metrics['exploitability']['trivial']}")
        print(f"   Moderate: {metrics.metrics['exploitability']['moderate']}")
        print(f"   Complex: {metrics.metrics['exploitability']['complex']}")
        print(f"   Theoretical: {metrics.metrics['exploitability']['theoretical']}")

    if metrics.metrics['exploit_chains_found'] > 0:
        print(f"\n⛓️  Exploit Chains: {metrics.metrics['exploit_chains_found']}")

    if metrics.metrics['tests_generated'] > 0:
        print(f"🧪 Tests Generated: {metrics.metrics['tests_generated']}")

    print(f"{'='*80}\n")

    return final_report

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

    # Verify model accessibility and fallback if needed (Anthropic only)
    if provider == 'anthropic':
        try:
            print(f"🔍 Verifying model accessibility: {model}")
            working_model = get_working_model_with_fallback(client, provider, model)
            if working_model != model:
                print(f"⚠️  Requested model '{model}' not accessible")
                print(f"✅ Using fallback model: {working_model}")
                model = working_model
            else:
                print(f"✅ Model verified: {model}")
        except Exception as e:
            logger.error(f"Model verification failed: {e}")
            print(f"\n❌ {e}")
            sys.exit(2)

    print(f"🧠 Model: {model}")
    metrics.metrics["model"] = model

    # Check cost limit
    cost_limit = float(config.get('cost_limit', 1.0))
    max_tokens = int(config.get('max_tokens', 8000))

    # Initialize cost circuit breaker for runtime enforcement
    circuit_breaker = CostCircuitBreaker(cost_limit_usd=cost_limit)

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
    
    # Check multi-agent mode
    multi_agent_mode = config.get('multi_agent_mode', 'single')
    
    if multi_agent_mode == 'sequential':
        # Run multi-agent sequential review
        report = run_multi_agent_sequential(
            repo_path, config, review_type,
            client, provider, model, max_tokens,
            files, metrics, circuit_breaker
        )
        
        # Skip to saving reports (multi-agent handles its own analysis)
        report_dir = Path(repo_path) / '.agent-os/reviews'
        report_dir.mkdir(parents=True, exist_ok=True)
        
        report_file = report_dir / f'{review_type}-report.md'
        with open(report_file, 'w') as f:
            f.write(report)
        
        print(f"✅ Multi-agent audit complete! Report saved to: {report_file}")
        
        # Parse findings from final orchestrated report
        findings = parse_findings_from_report(report)

        # Generate SARIF with metrics
        sarif = generate_sarif(findings, repo_path, metrics)
        sarif_file = report_dir / 'results.sarif'
        with open(sarif_file, 'w') as f:
            json.dump(sarif, f, indent=2)
        print(f"📄 SARIF saved to: {sarif_file}")
        
        # Generate structured JSON
        json_output = {
            "version": "2.1.0",
            "mode": "multi-agent-sequential",
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
        
        print(f"\n📊 Final Results:")
        print(f"   Critical: {metrics.metrics['findings']['critical']}")
        print(f"   High: {metrics.metrics['findings']['high']}")
        print(f"   Medium: {metrics.metrics['findings']['medium']}")
        print(f"   Low: {metrics.metrics['findings']['low']}")
        print(f"\n💰 Total Cost: ${metrics.metrics['cost_usd']:.2f}")
        print(f"⏱️  Total Duration: {metrics.metrics['duration_seconds']}s")
        print(f"🤖 Mode: Multi-Agent Sequential (7 agents)")

        # Display exploitability metrics
        if any(metrics.metrics['exploitability'].values()):
            print(f"\n⚠️  Exploitability:")
            if metrics.metrics['exploitability']['trivial'] > 0:
                print(f"   ⚠️  Trivial: {metrics.metrics['exploitability']['trivial']}")
            if metrics.metrics['exploitability']['moderate'] > 0:
                print(f"   🟨 Moderate: {metrics.metrics['exploitability']['moderate']}")
            if metrics.metrics['exploitability']['complex'] > 0:
                print(f"   🟦 Complex: {metrics.metrics['exploitability']['complex']}")
            if metrics.metrics['exploitability']['theoretical'] > 0:
                print(f"   ⬜ Theoretical: {metrics.metrics['exploitability']['theoretical']}")

        if metrics.metrics['exploit_chains_found'] > 0:
            print(f"   ⛓️  Exploit Chains: {metrics.metrics['exploit_chains_found']}")

        if metrics.metrics['tests_generated'] > 0:
            print(f"   🧪 Tests Generated: {metrics.metrics['tests_generated']}")
        
        # Output for GitHub Actions
        print(f"completed=true")
        print(f"blockers={blocker_count}")
        print(f"suggestions={suggestion_count}")
        print(f"report-path={report_file}")
        print(f"sarif-path={sarif_file}")
        print(f"json-path={json_file}")
        print(f"cost-estimate={metrics.metrics['cost_usd']:.4f}")
        print(f"files-analyzed={metrics.metrics['files_reviewed']}")
        print(f"duration-seconds={metrics.metrics['duration_seconds']}")
        
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
                    
                    if category == 'any':
                        if severity in metrics.metrics['findings'] and metrics.metrics['findings'][severity] > 0:
                            print(f"   ❌ FAIL: Found {metrics.metrics['findings'][severity]} {severity} issues")
                            should_fail = True
                    else:
                        matching_findings = [f for f in findings 
                                           if f['category'] == category and f['severity'] == severity]
                        if matching_findings:
                            print(f"   ❌ FAIL: Found {len(matching_findings)} {category}:{severity} issues")
                            should_fail = True
        
        if should_fail:
            print(f"\n❌ Failing due to fail-on conditions")
            sys.exit(1)
        
        return blocker_count, suggestion_count, metrics
    
    # Single-agent mode (original logic)
    print(f"🤖 Mode: Single-Agent")
    
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
        # Call LLM API with cost enforcement
        report, input_tokens, output_tokens = call_llm_api(
            client, provider, model, prompt, max_tokens,
            circuit_breaker=circuit_breaker,
            operation="single-agent review"
        )
        
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

        # Generate SARIF with metrics
        sarif = generate_sarif(findings, repo_path, metrics)
        sarif_file = report_dir / 'results.sarif'
        with open(sarif_file, 'w') as f:
            json.dump(sarif, f, indent=2)
        print(f"📄 SARIF saved to: {sarif_file}")
        
        # Generate structured JSON
        json_output = {
            "version": "1.0.16",
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
        'multi_agent_mode': os.environ.get('INPUT_MULTI_AGENT_MODE', 'single'),
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
