#!/usr/bin/env python3
"""
Real Multi-Agent Consensus Code Review
Uses actual API calls to multiple AI models available in Cursor

Models:
1. Claude Sonnet 4 (Anthropic API)
2. GPT-4 or another model (configurable)
"""

import os
import json
import asyncio
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime
import anthropic
from pathlib import Path

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SUGGESTION = "suggestion"

@dataclass
class Finding:
    """A single code review finding from one agent"""
    agent: str
    file: str
    line: int
    issue_type: str
    severity: str
    description: str
    recommendation: str
    confidence: float
    is_production: bool
    context: str
    raw_response: str = ""

@dataclass
class ConsensusResult:
    """Aggregated finding with consensus information"""
    file: str
    line: int
    issue_type: str
    severity: str
    votes: int
    total_agents: int
    confidence: float
    descriptions: List[str]
    recommendations: List[str]
    agents_agree: List[str]
    agents_disagree: List[str]
    consensus_level: str
    is_production: bool
    final_classification: str

class RealMultiAgentReview:
    """Real multi-agent review using actual API calls"""
    
    def __init__(self, anthropic_api_key: str, openai_api_key: Optional[str] = None):
        self.anthropic_api_key = anthropic_api_key
        self.openai_api_key = openai_api_key
        
        # Initialize agents
        self.agents = []
        self.claude_client = None
        
        if anthropic_api_key:
            self.claude_client = anthropic.Anthropic(api_key=anthropic_api_key)
            # Register two Anthropic agents to enable fully-automated consensus without OpenAI
            self.agents.append("Claude-Sonnet-4")
            self.agents.append("Claude-Haiku-3.5")
        
        # Add OpenAI if available
        if openai_api_key:
            try:
                import openai
                openai.api_key = openai_api_key
                self.agents.append("GPT-4-Turbo")
            except ImportError:
                print("⚠️  OpenAI library not installed. Install with: pip install openai")
        
        print(f"✅ Initialized {len(self.agents)} agent(s): {', '.join(self.agents)}")
    
    def is_production_code(self, file_path: str) -> bool:
        """Determine if this is production code or dev infrastructure"""
        dev_indicators = [
            'docker/',
            'docker-compose',
            '.env.example',
            'test/',
            'tests/',
            '.github/workflows',
            'Dockerfile',
            '.dockerignore'
        ]
        return not any(indicator in file_path for indicator in dev_indicators)
    
    def build_review_prompt(self, file_path: str, code_content: str, context: Dict[str, Any]) -> str:
        """Build a comprehensive review prompt with context"""
        
        is_prod = self.is_production_code(file_path)
        
        prompt = f"""You are an expert code reviewer. Review this code for security, performance, and quality issues.

**FILE**: {file_path}
**TYPE**: {context.get('file_type', 'unknown')}
**PRODUCTION CODE**: {"Yes" if is_prod else "No (dev infrastructure)"}

**CRITICAL CONTEXT RULES**:
1. If file is in docker/, docker-compose.yml, etc. → LOCAL DEV ONLY (not production)
2. If this is a test file → Different security standards apply  
3. If this is static SQL DDL (CREATE TABLE, etc.) → NOT SQL injection risk
4. If this is data extraction/pipeline → Not creating new vulnerabilities
5. Distinguish between development tooling and production code

**CODE TO REVIEW**:
```
{code_content[:3000]}
```

**YOUR TASK**:
Identify real production issues. For each finding, provide:

1. **issue_type**: Short identifier (e.g., "sql-injection", "missing-validation")
2. **severity**: critical, high, medium, low, or suggestion
3. **line**: Approximate line number where issue occurs
4. **description**: What's wrong (1-2 sentences)
5. **recommendation**: How to fix it (1-2 sentences)
6. **confidence**: 0.0-1.0 (how sure are you this is a real issue?)
7. **is_production**: true if this affects production, false if dev-only

**IMPORTANT**: 
- Be context-aware: dev infrastructure ≠ production security issues
- Static DDL files are not SQL injection vulnerabilities
- Focus on high-confidence, actionable findings
- If uncertain, lower the confidence score

**RESPONSE FORMAT** (JSON array):
[
  {{
    "issue_type": "example-issue",
    "severity": "high",
    "line": 42,
    "description": "Brief description of the issue",
    "recommendation": "How to fix it",
    "confidence": 0.85,
    "is_production": true
  }}
]

Return ONLY the JSON array, no other text.
"""
        return prompt
    
    async def review_with_claude(self, file_path: str, code_content: str, context: Dict[str, Any]) -> List[Finding]:
        """Review code using Claude Sonnet 4"""
        if not self.claude_client:
            return []
        
        print(f"  🔵 Claude Sonnet 4: Reviewing {file_path}...")
        
        prompt = self.build_review_prompt(file_path, code_content, context)
        
        try:
            response = await asyncio.to_thread(
                self.claude_client.messages.create,
                model="claude-3-5-sonnet-20241022",
                max_tokens=2048,
                temperature=0.3,  # Lower temp for consistency
                messages=[{
                    "role": "user",
                    "content": prompt
                }]
            )
            
            response_text = response.content[0].text
            print(f"    Response length: {len(response_text)} chars")
            
            # Parse JSON response
            findings = self._parse_json_response(response_text, "Claude-Sonnet-4", file_path)
            print(f"    Found: {len(findings)} issue(s)")
            
            return findings
            
        except Exception as e:
            print(f"    ❌ Error: {e}")
            return []

    async def review_with_claude_haiku(self, file_path: str, code_content: str, context: Dict[str, Any]) -> List[Finding]:
        """Review code using Claude 3.5 Haiku"""
        if not self.claude_client:
            return []
        
        print(f"  🔵 Claude 3.5 Haiku: Reviewing {file_path}...")
        
        prompt = self.build_review_prompt(file_path, code_content, context)
        
        try:
            response = await asyncio.to_thread(
                self.claude_client.messages.create,
                model="claude-3-5-haiku-20241022",
                max_tokens=2048,
                temperature=0.2,
                messages=[{
                    "role": "user",
                    "content": prompt
                }]
            )
            
            response_text = response.content[0].text
            print(f"    Response length: {len(response_text)} chars")
            
            findings = self._parse_json_response(response_text, "Claude-Haiku-3.5", file_path)
            print(f"    Found: {len(findings)} issue(s)")
            
            return findings
            
        except Exception as e:
            print(f"    ❌ Error: {e}")
            return []
    
    async def review_with_gpt4(self, file_path: str, code_content: str, context: Dict[str, Any]) -> List[Finding]:
        """Review code using GPT-4"""
        if "GPT-4-Turbo" not in self.agents:
            return []
        
        print(f"  🟢 GPT-4 Turbo: Reviewing {file_path}...")
        
        try:
            import openai
            
            prompt = self.build_review_prompt(file_path, code_content, context)
            
            response = await asyncio.to_thread(
                openai.ChatCompletion.create,
                model="gpt-4-turbo-preview",
                messages=[
                    {"role": "system", "content": "You are an expert code reviewer. Respond with JSON only."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3
            )
            
            response_text = response.choices[0].message.content
            print(f"    Response length: {len(response_text)} chars")
            
            findings = self._parse_json_response(response_text, "GPT-4-Turbo", file_path)
            print(f"    Found: {len(findings)} issue(s)")
            
            return findings
            
        except Exception as e:
            print(f"    ❌ Error: {e}")
            return []
    
    def _safe_int(self, value, default=0):
        """Safely convert value to int, handling strings, nulls, and invalid values"""
        try:
            if value in (None, '', 'null', 'None'):
                return default
            return int(value)
        except (ValueError, TypeError):
            return default
    
    def _parse_json_response(self, response_text: str, agent_name: str, file_path: str) -> List[Finding]:
        """Parse JSON response from AI model"""
        try:
            # Try to extract JSON from response
            # Sometimes models wrap JSON in markdown code blocks
            if "```json" in response_text:
                start = response_text.find("```json") + 7
                end = response_text.find("```", start)
                response_text = response_text[start:end].strip()
            elif "```" in response_text:
                start = response_text.find("```") + 3
                end = response_text.find("```", start)
                response_text = response_text[start:end].strip()
            
            # Parse JSON
            json_data = json.loads(response_text)
            
            if not isinstance(json_data, list):
                json_data = [json_data]
            
            findings = []
            for item in json_data:
                finding = Finding(
                    agent=agent_name,
                    file=file_path,
                    line=self._safe_int(item.get('line'), 0),
                    issue_type=item.get('issue_type', 'unknown'),
                    severity=item.get('severity', 'medium'),
                    description=item.get('description', ''),
                    recommendation=item.get('recommendation', ''),
                    confidence=float(item.get('confidence', 0.5)),
                    is_production=item.get('is_production', True),
                    context=f"Agent: {agent_name}",
                    raw_response=response_text[:500]
                )
                findings.append(finding)
            
            return findings
            
        except json.JSONDecodeError as e:
            print(f"    ⚠️  Failed to parse JSON: {e}")
            print(f"    Response: {response_text[:200]}")
            return []
        except Exception as e:
            print(f"    ⚠️  Error parsing response: {e}")
            return []
    
    async def review_file(self, file_path: str, repo_path: str) -> List[Finding]:
        """Review a single file with all available agents"""
        full_path = Path(repo_path) / file_path
        
        if not full_path.exists():
            print(f"  ⚠️  File not found: {full_path}")
            return []
        
        # Read file content
        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                code_content = f.read()
        except Exception as e:
            print(f"  ⚠️  Error reading file: {e}")
            return []
        
        # Build context
        context = {
            'file_path': file_path,
            'file_type': full_path.suffix,
            'is_test': 'test' in file_path.lower(),
            'is_production': self.is_production_code(file_path)
        }
        
        # Run all agents in parallel
        tasks = []
        
        if "Claude-Sonnet-4" in self.agents:
            tasks.append(self.review_with_claude(file_path, code_content, context))
        if "Claude-Haiku-3.5" in self.agents:
            tasks.append(self.review_with_claude_haiku(file_path, code_content, context))
        
        if "GPT-4-Turbo" in self.agents:
            tasks.append(self.review_with_gpt4(file_path, code_content, context))
        
        results = await asyncio.gather(*tasks)
        
        # Flatten results
        all_findings = []
        for findings in results:
            all_findings.extend(findings)
        
        return all_findings
    
    def build_consensus(self, all_findings: List[Finding]) -> List[ConsensusResult]:
        """Build consensus from findings"""
        if not all_findings:
            return []
        
        # Group by file + issue_type + line range (similar issues at similar locations)
        grouped = {}
        
        for finding in all_findings:
            # Create a location-sensitive key to avoid collapsing distinct bugs
            # Group issues within ~10 lines as the same issue
            line_bucket = (finding.line // 10) * 10
            key = f"{finding.file}:{finding.issue_type}:L{line_bucket}"
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(finding)
        
        consensus_results = []
        
        for key, group in grouped.items():
            votes = len(group)
            total_agents = len(self.agents)
            avg_confidence = sum(f.confidence for f in group) / len(group)
            
            is_prod = any(f.is_production for f in group)
            
            # Classify based on votes and production status
            if votes == total_agents and is_prod and avg_confidence >= 0.7:
                final_classification = "critical_fix"
            elif votes >= total_agents // 2 + 1 and is_prod:
                final_classification = "high_priority"
            elif votes >= total_agents // 2 + 1 and not is_prod:
                final_classification = "dev_issue"  # Dev infrastructure issues, not false positives
            elif votes == 1:
                final_classification = "suggestion"
            else:
                final_classification = "needs_investigation"
            
            # Consensus level
            if votes == total_agents:
                consensus_level = "unanimous"
            elif votes > total_agents / 2:
                consensus_level = "majority"
            else:
                consensus_level = "minority"
            
            # Get average line number
            avg_line = int(sum(f.line for f in group) / len(group))
            
            result = ConsensusResult(
                file=group[0].file,
                line=avg_line,
                issue_type=group[0].issue_type,
                severity=group[0].severity,
                votes=votes,
                total_agents=total_agents,
                confidence=avg_confidence,
                descriptions=[f.description for f in group],
                recommendations=[f.recommendation for f in group],
                agents_agree=[f.agent for f in group],
                agents_disagree=[a for a in self.agents if a not in [f.agent for f in group]],
                consensus_level=consensus_level,
                is_production=is_prod,
                final_classification=final_classification
            )
            
            consensus_results.append(result)
        
        # Sort by votes and confidence
        consensus_results.sort(key=lambda x: (x.votes, x.confidence), reverse=True)
        
        return consensus_results
    
    def generate_report(self, consensus_results: List[ConsensusResult], repo_name: str) -> str:
        """Generate markdown report"""
        
        critical = [r for r in consensus_results if r.final_classification == "critical_fix"]
        high = [r for r in consensus_results if r.final_classification == "high_priority"]
        suggestions = [r for r in consensus_results if r.final_classification == "suggestion"]
        dev_issues = [r for r in consensus_results if r.final_classification == "dev_issue"]
        
        report = f"""# 🤖 Real Multi-Agent Consensus Code Review

**Repository**: {repo_name}  
**Agents**: {', '.join(self.agents)} (REAL API CALLS)  
**Review Date**: {datetime.utcnow().isoformat()}Z  

---

## 📊 Executive Summary

| Metric | Count |
|--------|-------|
| **Total Agents** | {len(self.agents)} |
| **Consensus Findings** | {len(consensus_results)} |
| **Critical Fixes (Unanimous/High Conf)** | {len(critical)} 🔴 |
| **High Priority (Majority)** | {len(high)} 🟠 |
| **Suggestions (Minority)** | {len(suggestions)} 🟡 |
| **Dev Infrastructure Issues** | {len(dev_issues)} 🔧 |

---

## 🔴 Critical Fixes ({len(critical)})

"""
        
        for result in critical:
            report += f"""
### {result.issue_type.replace('-', ' ').title()}

**File**: `{result.file}:{result.line}`  
**Votes**: {result.votes}/{result.total_agents} ({result.consensus_level.upper()})  
**Confidence**: {result.confidence:.0%}  

**Findings from agents**:
"""
            for i, (agent, desc) in enumerate(zip(result.agents_agree, result.descriptions), 1):
                report += f"{i}. **{agent}**: {desc}\n"
            
            report += "\n**Recommendations**:\n"
            for i, rec in enumerate(result.recommendations, 1):
                report += f"{i}. {rec}\n"
            
            report += "\n---\n"
        
        report += f"""

## 🟠 High Priority ({len(high)})

"""
        
        for result in high:
            report += f"""
### {result.issue_type.replace('-', ' ').title()}

**File**: `{result.file}:{result.line}`  
**Votes**: {result.votes}/{result.total_agents}  
**Agents**: {', '.join(result.agents_agree)}  

{result.descriptions[0]}

---
"""
        
        report += f"""

## 🟡 Suggestions ({len(suggestions)})

"""
        for result in suggestions:
            report += f"- {result.issue_type} in `{result.file}` (1 agent)\n"
        
        report += f"""

## 🔧 Dev Infrastructure Issues ({len(dev_issues)})

"""
        for result in dev_issues:
            report += f"- {result.issue_type} in `{result.file}:{result.line}` (dev infrastructure, not production-critical)\n"
        
        report += """

---

**💡 This report was generated using REAL API calls to multiple AI models.**  
**Each finding represents actual consensus between independent AI agents.**

"""
        
        return report


async def main():
    """Main entry point"""
    print("🤖 Real Multi-Agent Consensus Review")
    print("=" * 70)
    print()
    
    # Get API keys from environment
    anthropic_key = os.getenv('ANTHROPIC_API_KEY')
    openai_key = os.getenv('OPENAI_API_KEY')
    
    if not anthropic_key:
        print("❌ ANTHROPIC_API_KEY not found in environment")
        print("   Set it with: export ANTHROPIC_API_KEY='your-key-here'")
        return
    
    # Initialize review system
    reviewer = RealMultiAgentReview(
        anthropic_api_key=anthropic_key,
        openai_api_key=openai_key
    )
    
    print()
    
    # Repository to review
    repo_path = "/tmp/Spring-Steampipe-Data-Pipeline"
    repo_name = "Spring-Steampipe-Data-Pipeline"
    
    if not Path(repo_path).exists():
        print(f"❌ Repository not found: {repo_path}")
        print("   Clone it first with:")
        print(f"   gh repo clone securedotcom/{repo_name} {repo_path}")
        return
    
    # Files to review (key files from human feedback)
    files_to_review = [
        "docker/hive/postgres-init/02-configure-auth.sql",
        "pipeline/src/urr/aws/services/rds/create_rds_urr.sql"
    ]
    
    print(f"📂 Repository: {repo_name}")
    print(f"📄 Files to review: {len(files_to_review)}")
    print()
    
    # Review all files
    all_findings = []
    
    for file_path in files_to_review:
        print(f"📄 Reviewing: {file_path}")
        findings = await reviewer.review_file(file_path, repo_path)
        all_findings.extend(findings)
        print()
    
    print(f"✅ Total findings: {len(all_findings)}")
    print()
    
    # Build consensus
    print("🔄 Building consensus...")
    consensus_results = reviewer.build_consensus(all_findings)
    print(f"✅ Consensus results: {len(consensus_results)}")
    print()
    
    # Generate report
    print("📝 Generating report...")
    report = reviewer.generate_report(consensus_results, repo_name)
    
    # Save report
    output_file = "/tmp/real_multi_agent_report.md"
    with open(output_file, 'w') as f:
        f.write(report)
    
    print(f"✅ Report saved: {output_file}")
    print()
    
    # Summary
    print("📊 Summary:")
    critical = len([r for r in consensus_results if r.final_classification == "critical_fix"])
    high = len([r for r in consensus_results if r.final_classification == "high_priority"])
    suggestions = len([r for r in consensus_results if r.final_classification == "suggestion"])
    
    print(f"  🔴 Critical Fixes: {critical}")
    print(f"  🟠 High Priority: {high}")
    print(f"  🟡 Suggestions: {suggestions}")
    print()
    
    print("🎉 Real multi-agent consensus review complete!")
    print(f"📄 View report: {output_file}")


if __name__ == "__main__":
    asyncio.run(main())

