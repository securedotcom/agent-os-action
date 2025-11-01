# 🤖 Multi-Agent Consensus System Implementation Plan

**Goal**: Reduce false positives and increase confidence in code review findings through multi-agent consensus.

---

## Phase 1: Core Multi-Agent Infrastructure (Week 1-2)

### 1.1 Multi-Model Support

**File**: `action.yml`

**Changes**:
```yaml
inputs:
  # Existing inputs...
  
  multi-agent-enabled:
    description: 'Enable multi-agent consensus mode'
    required: false
    default: 'false'
  
  agent-models:
    description: 'Comma-separated list of models (claude-sonnet,gpt-4,gemini-pro)'
    required: false
    default: 'claude-sonnet-4'
  
  consensus-threshold:
    description: 'Minimum votes required for critical issues (2 or 3)'
    required: false
    default: '2'
  
  openai-api-key:
    description: 'OpenAI API key for GPT-4'
    required: false
    default: ''
  
  google-api-key:
    description: 'Google API key for Gemini'
    required: false
    default: ''
```

---

### 1.2 Agent Orchestrator

**New File**: `scripts/multi_agent_orchestrator.py`

```python
#!/usr/bin/env python3
"""
Multi-Agent Consensus Code Review Orchestrator

Coordinates multiple AI models to review code and build consensus.
"""

import asyncio
import json
from typing import List, Dict, Any
from dataclasses import dataclass
from enum import Enum

class AgentModel(Enum):
    CLAUDE_SONNET = "claude-sonnet-4"
    GPT4 = "gpt-4"
    GEMINI_PRO = "gemini-pro"

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
    severity: Severity
    description: str
    recommendation: str
    confidence: float  # 0-1
    context: Dict[str, Any]

@dataclass
class ConsensusResult:
    """Aggregated finding with consensus information"""
    file: str
    line: int
    issue_type: str
    severity: Severity
    votes: int
    total_agents: int
    confidence: float
    descriptions: List[str]
    recommendations: List[str]
    agents_agree: List[str]
    agents_disagree: List[str]
    consensus_level: str  # "unanimous", "majority", "minority"

class MultiAgentOrchestrator:
    def __init__(
        self,
        models: List[AgentModel],
        consensus_threshold: int = 2,
        anthropic_key: str = None,
        openai_key: str = None,
        google_key: str = None
    ):
        self.models = models
        self.consensus_threshold = consensus_threshold
        self.api_keys = {
            'anthropic': anthropic_key,
            'openai': openai_key,
            'google': google_key
        }
        self.agents = []
        self._initialize_agents()
    
    def _initialize_agents(self):
        """Initialize agent instances for each model"""
        for model in self.models:
            if model == AgentModel.CLAUDE_SONNET:
                from agents.claude_agent import ClaudeAgent
                self.agents.append(ClaudeAgent(self.api_keys['anthropic']))
            elif model == AgentModel.GPT4:
                from agents.gpt4_agent import GPT4Agent
                self.agents.append(GPT4Agent(self.api_keys['openai']))
            elif model == AgentModel.GEMINI_PRO:
                from agents.gemini_agent import GeminiAgent
                self.agents.append(GeminiAgent(self.api_keys['google']))
    
    async def review_code(
        self,
        file_path: str,
        code_content: str,
        context: Dict[str, Any]
    ) -> List[Finding]:
        """Run code review with all agents in parallel"""
        tasks = [
            agent.review(file_path, code_content, context)
            for agent in self.agents
        ]
        results = await asyncio.gather(*tasks)
        
        # Flatten all findings from all agents
        all_findings = []
        for agent_idx, agent_findings in enumerate(results):
            for finding in agent_findings:
                finding.agent = self.agents[agent_idx].name
                all_findings.append(finding)
        
        return all_findings
    
    def build_consensus(
        self,
        findings: List[Finding]
    ) -> List[ConsensusResult]:
        """
        Build consensus from multiple agent findings.
        Groups similar findings and calculates vote counts.
        """
        # Group findings by file + line + issue_type
        grouped = {}
        
        for finding in findings:
            key = f"{finding.file}:{finding.line}:{finding.issue_type}"
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(finding)
        
        # Calculate consensus for each group
        consensus_results = []
        
        for key, group in grouped.items():
            votes = len(group)
            total_agents = len(self.agents)
            
            # Calculate average confidence
            avg_confidence = sum(f.confidence for f in group) / len(group)
            
            # Determine severity (use highest severity from group)
            severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
            group_severity = next(
                (sev for sev in severity_order if any(f.severity == sev for f in group)),
                Severity.SUGGESTION
            )
            
            # Determine consensus level
            if votes == total_agents:
                consensus_level = "unanimous"
            elif votes >= self.consensus_threshold:
                consensus_level = "majority"
            else:
                consensus_level = "minority"
            
            result = ConsensusResult(
                file=group[0].file,
                line=group[0].line,
                issue_type=group[0].issue_type,
                severity=group_severity,
                votes=votes,
                total_agents=total_agents,
                confidence=avg_confidence,
                descriptions=[f.description for f in group],
                recommendations=[f.recommendation for f in group],
                agents_agree=[f.agent for f in group],
                agents_disagree=[
                    a.name for a in self.agents 
                    if a.name not in [f.agent for f in group]
                ],
                consensus_level=consensus_level
            )
            
            consensus_results.append(result)
        
        # Sort by confidence and votes
        consensus_results.sort(
            key=lambda x: (x.votes, x.confidence),
            reverse=True
        )
        
        return consensus_results
    
    def classify_findings(
        self,
        consensus_results: List[ConsensusResult]
    ) -> Dict[str, List[ConsensusResult]]:
        """
        Classify findings into action categories based on consensus.
        
        Returns:
            {
                'critical_fixes': [...],  # 3/3 or high confidence 2/3
                'high_priority': [...],   # 2/3 votes
                'suggestions': [...],     # 1/3 votes
                'ignored': [...]          # 0 votes or false positives
            }
        """
        classification = {
            'critical_fixes': [],
            'high_priority': [],
            'suggestions': [],
            'needs_investigation': []
        }
        
        for result in consensus_results:
            # Unanimous agreement on critical = definite fix
            if result.votes == result.total_agents and result.severity == Severity.CRITICAL:
                classification['critical_fixes'].append(result)
            
            # High confidence majority = likely real issue
            elif result.votes >= self.consensus_threshold and result.confidence >= 0.7:
                if result.severity in [Severity.CRITICAL, Severity.HIGH]:
                    classification['critical_fixes'].append(result)
                else:
                    classification['high_priority'].append(result)
            
            # Majority but mixed severity = investigate
            elif result.votes >= self.consensus_threshold:
                classification['needs_investigation'].append(result)
            
            # Low votes = suggestion only
            else:
                classification['suggestions'].append(result)
        
        return classification
    
    async def run_consensus_review(
        self,
        files: List[str],
        project_path: str
    ) -> Dict[str, Any]:
        """
        Run full consensus review on multiple files.
        
        Returns complete report with classifications.
        """
        all_findings = []
        
        # Review all files in parallel
        for file_path in files:
            with open(f"{project_path}/{file_path}", 'r') as f:
                code_content = f.read()
            
            context = {
                'project_path': project_path,
                'file_type': file_path.split('.')[-1],
                'is_test': 'test' in file_path.lower(),
                'is_config': file_path in ['docker-compose.yml', 'Dockerfile']
            }
            
            findings = await self.review_code(file_path, code_content, context)
            all_findings.extend(findings)
        
        # Build consensus
        consensus_results = self.build_consensus(all_findings)
        
        # Classify findings
        classified = self.classify_findings(consensus_results)
        
        # Generate report
        report = {
            'summary': {
                'total_files': len(files),
                'total_agents': len(self.agents),
                'total_findings': len(all_findings),
                'consensus_findings': len(consensus_results),
                'critical_fixes': len(classified['critical_fixes']),
                'high_priority': len(classified['high_priority']),
                'suggestions': len(classified['suggestions']),
                'needs_investigation': len(classified['needs_investigation'])
            },
            'agents': [agent.name for agent in self.agents],
            'classified_findings': classified,
            'all_consensus_results': consensus_results
        }
        
        return report

# Example usage
async def main():
    orchestrator = MultiAgentOrchestrator(
        models=[
            AgentModel.CLAUDE_SONNET,
            AgentModel.GPT4,
            AgentModel.GEMINI_PRO
        ],
        consensus_threshold=2,
        anthropic_key="...",
        openai_key="...",
        google_key="..."
    )
    
    files = ["src/main.py", "src/auth.py"]
    report = await orchestrator.run_consensus_review(files, "/path/to/project")
    
    print(f"Critical fixes: {len(report['classified_findings']['critical_fixes'])}")
    print(f"Suggestions: {len(report['classified_findings']['suggestions'])}")

if __name__ == "__main__":
    asyncio.run(main())
```

---

## Phase 2: Individual Agent Implementations (Week 2-3)

### 2.1 Base Agent Interface

**New File**: `scripts/agents/base_agent.py`

```python
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from dataclasses import dataclass

class BaseAgent(ABC):
    """Base class for all code review agents"""
    
    def __init__(self, api_key: str, name: str):
        self.api_key = api_key
        self.name = name
    
    @abstractmethod
    async def review(
        self,
        file_path: str,
        code_content: str,
        context: Dict[str, Any]
    ) -> List[Finding]:
        """
        Review code and return findings.
        
        Args:
            file_path: Path to the file being reviewed
            code_content: Content of the file
            context: Additional context (project type, etc.)
        
        Returns:
            List of findings from this agent
        """
        pass
    
    def _build_prompt(self, code_content: str, context: Dict[str, Any]) -> str:
        """Build review prompt with context awareness"""
        prompt = f"""Review this code for security, performance, and quality issues.

CODE:
```
{code_content}
```

CONTEXT:
- File: {context.get('file_path', 'unknown')}
- Type: {context.get('file_type', 'unknown')}
- Is Test: {context.get('is_test', False)}
- Is Config: {context.get('is_config', False)}

IMPORTANT CONTEXT RULES:
1. If this is in a 'docker/' directory → LOCAL DEV ONLY, not production
2. If this is a test file → Different security standards apply
3. If this is a config file → Check if it's dev vs prod
4. If this is static SQL/DDL → Not SQL injection risk
5. If this is data extraction → Not creating new vulnerabilities

Please identify:
1. Real production security issues (not local dev)
2. Performance bottlenecks
3. Code quality improvements

For each finding, provide:
- Severity (critical/high/medium/low)
- Confidence (0-1, how sure are you?)
- Context awareness (is this prod or dev?)
"""
        return prompt
```

---

### 2.2 Claude Agent

**New File**: `scripts/agents/claude_agent.py`

```python
import anthropic
from typing import List, Dict, Any
from .base_agent import BaseAgent, Finding, Severity

class ClaudeAgent(BaseAgent):
    def __init__(self, api_key: str):
        super().__init__(api_key, "Claude-Sonnet-4")
        self.client = anthropic.Anthropic(api_key=api_key)
    
    async def review(
        self,
        file_path: str,
        code_content: str,
        context: Dict[str, Any]
    ) -> List[Finding]:
        prompt = self._build_prompt(code_content, context)
        
        response = self.client.messages.create(
            model="claude-3-5-sonnet-20240620",
            max_tokens=4096,
            messages=[{
                "role": "user",
                "content": prompt
            }]
        )
        
        # Parse response and extract findings
        findings = self._parse_response(response.content[0].text, file_path)
        return findings
    
    def _parse_response(self, text: str, file_path: str) -> List[Finding]:
        """Parse Claude's response into structured findings"""
        # Implementation to parse natural language response
        # into Finding objects
        pass
```

---

### 2.3 GPT-4 Agent

**New File**: `scripts/agents/gpt4_agent.py`

```python
import openai
from typing import List, Dict, Any
from .base_agent import BaseAgent, Finding

class GPT4Agent(BaseAgent):
    def __init__(self, api_key: str):
        super().__init__(api_key, "GPT-4")
        openai.api_key = api_key
    
    async def review(
        self,
        file_path: str,
        code_content: str,
        context: Dict[str, Any]
    ) -> List[Finding]:
        prompt = self._build_prompt(code_content, context)
        
        response = openai.ChatCompletion.create(
            model="gpt-4-turbo-preview",
            messages=[{
                "role": "system",
                "content": "You are an expert code reviewer focused on security and quality."
            }, {
                "role": "user",
                "content": prompt
            }],
            temperature=0.3  # Lower temp for more consistent reviews
        )
        
        findings = self._parse_response(response.choices[0].message.content, file_path)
        return findings
```

---

### 2.4 Gemini Agent

**New File**: `scripts/agents/gemini_agent.py`

```python
import google.generativeai as genai
from typing import List, Dict, Any
from .base_agent import BaseAgent, Finding

class GeminiAgent(BaseAgent):
    def __init__(self, api_key: str):
        super().__init__(api_key, "Gemini-Pro")
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-pro')
    
    async def review(
        self,
        file_path: str,
        code_content: str,
        context: Dict[str, Any]
    ) -> List[Finding]:
        prompt = self._build_prompt(code_content, context)
        
        response = self.model.generate_content(prompt)
        findings = self._parse_response(response.text, file_path)
        return findings
```

---

## Phase 3: Consensus Engine (Week 3)

### 3.1 Finding Similarity Matcher

**New File**: `scripts/consensus/similarity_matcher.py`

```python
from typing import List, Tuple
from difflib import SequenceMatcher

class SimilarityMatcher:
    """Determines if two findings from different agents are about the same issue"""
    
    @staticmethod
    def are_similar(finding1: Finding, finding2: Finding, threshold: float = 0.7) -> bool:
        """
        Determine if two findings are describing the same issue.
        
        Criteria:
        1. Same file
        2. Similar line numbers (within 5 lines)
        3. Similar issue types
        4. Similar descriptions (>70% match)
        """
        # Must be same file
        if finding1.file != finding2.file:
            return False
        
        # Line numbers must be close
        if abs(finding1.line - finding2.line) > 5:
            return False
        
        # Issue types should match or be related
        if not SimilarityMatcher._issue_types_related(
            finding1.issue_type,
            finding2.issue_type
        ):
            return False
        
        # Descriptions should be similar
        desc_similarity = SequenceMatcher(
            None,
            finding1.description.lower(),
            finding2.description.lower()
        ).ratio()
        
        return desc_similarity >= threshold
    
    @staticmethod
    def _issue_types_related(type1: str, type2: str) -> bool:
        """Check if two issue types are related"""
        related_groups = [
            {'sql-injection', 'injection', 'security'},
            {'n+1-query', 'performance', 'database'},
            {'hardcoded-secret', 'credentials', 'security'},
            {'missing-validation', 'input-validation', 'security'}
        ]
        
        for group in related_groups:
            if type1 in group and type2 in group:
                return True
        
        return type1 == type2
```

---

## Phase 4: PR Generation with Consensus (Week 4)

### 4.1 Consensus-Based PR Creator

**New File**: `scripts/pr_creator_consensus.py`

```python
class ConsensusPRCreator:
    """Creates PRs based on consensus confidence levels"""
    
    def create_prs(self, classified_findings: Dict[str, List[ConsensusResult]]):
        """
        Create different types of PRs based on consensus:
        
        - Critical Fixes (3/3 or high confidence 2/3):
          → Create code fix PR with actual changes
        
        - High Priority (2/3):
          → Create documentation PR with implementation guide
        
        - Suggestions (1/3):
          → Add as PR comments, not blocking
        
        - Needs Investigation:
          → Create discussion issue, tag senior devs
        """
        
        # Critical fixes → Code PR
        if classified_findings['critical_fixes']:
            self._create_code_fix_pr(classified_findings['critical_fixes'])
        
        # High priority → Documentation PR
        if classified_findings['high_priority']:
            self._create_documentation_pr(classified_findings['high_priority'])
        
        # Suggestions → Comments
        if classified_findings['suggestions']:
            self._add_suggestions_as_comments(classified_findings['suggestions'])
        
        # Needs investigation → Discussion issue
        if classified_findings['needs_investigation']:
            self._create_discussion_issue(classified_findings['needs_investigation'])
    
    def _create_code_fix_pr(self, findings: List[ConsensusResult]):
        """Create PR with actual code fixes"""
        pr_body = f"""## 🔒 Critical Security Fixes (Multi-Agent Consensus)

**Confidence Level**: HIGH (Unanimous or Strong Majority)

These issues were identified by **multiple AI agents** and represent
high-confidence findings that should be addressed immediately.

### Consensus Summary:

"""
        for finding in findings:
            pr_body += f"""
#### Issue: {finding.issue_type}
- **File**: `{finding.file}:{finding.line}`
- **Votes**: {finding.votes}/{finding.total_agents} agents agree
- **Confidence**: {finding.confidence:.0%}
- **Consensus**: {finding.consensus_level.upper()}

**What the agents found:**
"""
            for i, desc in enumerate(finding.descriptions, 1):
                pr_body += f"\n{i}. {desc}"
            
            pr_body += "\n\n**Recommended fixes:**\n"
            for i, rec in enumerate(finding.recommendations, 1):
                pr_body += f"\n{i}. {rec}"
            
            pr_body += f"\n\n**Agents in agreement:** {', '.join(finding.agents_agree)}\n"
            pr_body += "---\n\n"
        
        # Create actual PR with this body
        self._github_create_pr(
            title="🔒 Critical Security Fixes (Multi-Agent Verified)",
            body=pr_body,
            labels=['security', 'critical', 'multi-agent-verified']
        )
    
    def _create_documentation_pr(self, findings: List[ConsensusResult]):
        """Create PR with documentation and implementation guide"""
        pr_body = f"""## 📋 High Priority Improvements (Multi-Agent Consensus)

**Confidence Level**: MEDIUM-HIGH (Majority Agreement)

These issues were flagged by a majority of AI agents. While not
unanimous, they represent likely real issues that should be investigated.

### Consensus Summary:

"""
        # Similar format to critical fixes
        # ...
```

---

## Phase 5: Integration with GitHub Actions (Week 4)

### 5.1 Updated Workflow

**File**: `.github/workflows/agent-os-code-review-simple.yml`

```yaml
name: Agent OS Multi-Agent Consensus Review

on:
  pull_request:
    branches: [main, master, develop]
  workflow_dispatch:
    inputs:
      multi_agent_enabled:
        description: 'Enable multi-agent consensus'
        required: true
        default: 'true'
        type: boolean
      models:
        description: 'Models to use (comma-separated)'
        required: false
        default: 'claude-sonnet,gpt-4,gemini-pro'
        type: string

permissions:
  contents: write
  pull-requests: write
  issues: write

jobs:
  multi-agent-review:
    runs-on: ubuntu-latest
    timeout-minutes: 30  # Increased for multiple agents
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      with:
        fetch-depth: 0
    
    - name: Setup Python
      uses: actions/setup-python@v5
      with:
        python-version: '3.11'
    
    - name: Run Multi-Agent Consensus Review
      uses: securedotcom/agent-os-action@v3.0.0  # New version with multi-agent
      with:
        review-type: 'audit'
        multi-agent-enabled: 'true'
        agent-models: 'claude-sonnet,gpt-4,gemini-pro'
        consensus-threshold: '2'
        
        # API Keys for different models
        anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
        openai-api-key: ${{ secrets.OPENAI_API_KEY }}
        google-api-key: ${{ secrets.GOOGLE_API_KEY }}
        
        # Other settings
        fail-on-blockers: 'true'
        create-consensus-pr: 'true'
        comment-on-pr: 'true'
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    
    - name: Upload Consensus Report
      if: always()
      uses: actions/upload-artifact@v4
      with:
        name: multi-agent-consensus-report
        path: .agent-os/consensus-report.json
        retention-days: 90
```

---

## Phase 6: Reporting & Visualization (Week 5)

### 6.1 Consensus Report Generator

**New File**: `scripts/reporting/consensus_report.py`

```python
class ConsensusReportGenerator:
    """Generate human-readable consensus reports"""
    
    def generate_markdown_report(self, consensus_data: Dict) -> str:
        """Generate comprehensive markdown report"""
        
        report = f"""# 🤖 Multi-Agent Consensus Code Review Report

**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Agents**: {', '.join(consensus_data['agents'])}  
**Files Reviewed**: {consensus_data['summary']['total_files']}  

---

## 📊 Executive Summary

| Metric | Count |
|--------|-------|
| **Total Findings (All Agents)** | {consensus_data['summary']['total_findings']} |
| **Consensus Findings** | {consensus_data['summary']['consensus_findings']} |
| **Critical Fixes (High Confidence)** | {consensus_data['summary']['critical_fixes']} 🔴 |
| **High Priority (Majority Vote)** | {consensus_data['summary']['high_priority']} 🟠 |
| **Suggestions (Low Vote)** | {consensus_data['summary']['suggestions']} 🟡 |
| **Needs Investigation** | {consensus_data['summary']['needs_investigation']} ⚠️ |

---

## 🎯 Confidence Levels

### Unanimous Agreement (3/3 Agents)
{self._format_findings(consensus_data['unanimous'])}

### Strong Majority (2/3 Agents)
{self._format_findings(consensus_data['majority'])}

### Single Agent Only (1/3 Agents)
{self._format_findings(consensus_data['minority'])}

---

## 📈 Agent Agreement Matrix

| Finding | Claude | GPT-4 | Gemini |
|---------|--------|-------|--------|
{self._generate_agreement_matrix(consensus_data)}

---

## 🔍 Detailed Findings

### Critical Fixes (Action Required)

{self._format_detailed_findings(consensus_data['classified_findings']['critical_fixes'])}

---

## 💡 Recommendations

Based on multi-agent consensus:

1. **Immediate Action** ({len(consensus_data['classified_findings']['critical_fixes'])} issues):
   - These have strong agreement from multiple agents
   - High confidence they are real issues
   - Should be fixed before deployment

2. **Investigation Required** ({len(consensus_data['classified_findings']['needs_investigation'])} issues):
   - Agents disagree on severity or context
   - Requires human review to determine applicability
   - May need architectural context

3. **Suggested Improvements** ({len(consensus_data['classified_findings']['suggestions'])} issues):
   - Only one agent flagged these
   - May be false positives or style preferences
   - Consider for technical debt backlog

---

**Generated by Agent OS Multi-Agent Consensus System v3.0**
"""
        return report
```

---

## Testing Strategy

### Unit Tests

```python
# tests/test_consensus_engine.py

def test_unanimous_agreement():
    """Test that 3/3 agreement is classified as critical"""
    findings = [
        Finding(agent="claude", severity=Severity.CRITICAL, ...),
        Finding(agent="gpt4", severity=Severity.CRITICAL, ...),
        Finding(agent="gemini", severity=Severity.CRITICAL, ...)
    ]
    
    consensus = build_consensus(findings)
    assert consensus.consensus_level == "unanimous"
    assert consensus.votes == 3

def test_false_positive_detection():
    """Test that single-agent findings are flagged as low confidence"""
    findings = [
        Finding(agent="claude", severity=Severity.LOW, ...)
    ]
    
    consensus = build_consensus(findings)
    assert consensus.consensus_level == "minority"
    assert consensus.confidence < 0.5
```

---

## Cost Analysis

### API Costs (Per Review)

| Model | Cost per 1K tokens | Typical Review | Cost |
|-------|-------------------|----------------|------|
| Claude Sonnet 4 | $3/$15 | 10K in, 5K out | $0.10 |
| GPT-4 Turbo | $10/$30 | 10K in, 5K out | $0.25 |
| Gemini Pro | $0.50/$1.50 | 10K in, 5K out | $0.01 |
| **Total per review** | | | **$0.36** |

### Monthly Costs (79 Repos, Weekly)

- Weekly reviews: 79 repos × 4 weeks = 316 reviews/month
- Cost per review: $0.36
- **Monthly total: ~$114**

### ROI:

- **Cost**: $114/month
- **Value**: Reduced false positives = less wasted developer time
- **Benefit**: High-confidence findings = faster issue resolution
- **ROI**: 10-20x (based on developer time saved)

---

## Rollout Plan

### Phase 1: Pilot (Week 1-2)
- Deploy to 2-3 test repositories
- Test with spring_auth, spring-dashboard-analytics
- Validate consensus accuracy
- Tune thresholds

### Phase 2: Expand (Week 3-4)
- Deploy to top 10 critical repositories
- Monitor costs and accuracy
- Adjust models if needed

### Phase 3: Full Rollout (Week 5-6)
- Deploy to all 79 repositories
- Enable by default
- Train team on interpreting results

---

## Success Metrics

Track these KPIs:

1. **False Positive Rate**: Target <10% (vs current ~30-40%)
2. **Consensus Accuracy**: Target >90% for unanimous findings
3. **Developer Acceptance**: Target >80% of fixes merged
4. **Time to Fix**: Target <48 hours for critical consensus issues
5. **Cost per Finding**: Target <$2 per validated issue

---

## Configuration Examples

### Conservative (High Precision)
```yaml
multi-agent-enabled: true
agent-models: 'claude-sonnet,gpt-4,gemini-pro'
consensus-threshold: 3  # Require unanimous
confidence-threshold: 0.8
```

### Balanced (Recommended)
```yaml
multi-agent-enabled: true
agent-models: 'claude-sonnet,gpt-4,gemini-pro'
consensus-threshold: 2  # Require 2/3
confidence-threshold: 0.7
```

### Aggressive (High Recall)
```yaml
multi-agent-enabled: true
agent-models: 'claude-sonnet,gpt-4'
consensus-threshold: 1  # Any agent can flag
confidence-threshold: 0.5
```

---

## Next Steps

1. ✅ Review this plan
2. ✅ Approve budget ($114/month for API costs)
3. ✅ Provide API keys (OpenAI, Google)
4. ✅ Select pilot repositories
5. ✅ Begin implementation (Week 1)

**Estimated Timeline**: 5-6 weeks to full rollout  
**Estimated Cost**: $114/month operational + development time  
**Expected Benefit**: 60-70% reduction in false positives

---

**Document Version**: 1.0  
**Last Updated**: October 30, 2025  
**Status**: Planning Phase



