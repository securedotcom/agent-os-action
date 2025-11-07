#!/usr/bin/env python3
"""
Correlation Engine - Phase 2.1
Groups related findings across attack surfaces using Foundation-Sec-8B
"""

import json
import sys
import hashlib
from pathlib import Path
from typing import List, Dict, Set, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from normalizer.base import Finding
from providers.sagemaker_foundation_sec import SageMakerFoundationSecProvider


@dataclass
class CorrelationGroup:
    """Group of related findings"""
    id: str
    findings: List[str]  # Finding IDs
    relationship_type: str  # exploit_chain, same_attack_surface, related_vulnerability
    risk_multiplier: float  # How much this correlation increases risk
    description: str
    confidence: float


class Correlator:
    """
    Correlates findings to identify:
    1. Exploit chains (multiple vulns that can be chained)
    2. Same attack surface (vulns in related code/endpoints)
    3. Related vulnerabilities (similar root causes)
    
    Uses Foundation-Sec-8B for intelligent correlation
    """
    
    def __init__(self):
        self.foundation_sec = None
        
        # Initialize Foundation-Sec if available
            try:
                self.foundation_sec = SageMakerFoundationSecProvider()
                print("✅ Foundation-Sec-8B initialized for correlation analysis")
            except Exception as e:
            print(f"⚠️  Foundation-Sec not available, using heuristics only: {e}")
    
    def correlate_findings(self, findings: List[Finding]) -> Tuple[List[Finding], List[CorrelationGroup]]:
        """
        Correlate findings and assign correlation_group_id
            
        Returns:
            Tuple of (updated findings, correlation groups)
        """
        print(f"\n🔗 Correlating {len(findings)} findings...")
        
        groups: List[CorrelationGroup] = []
        
        # 1. Find exploit chains
        exploit_chains = self._find_exploit_chains(findings)
        groups.extend(exploit_chains)
        
        # 2. Find same attack surface
        attack_surfaces = self._find_same_attack_surface(findings)
        groups.extend(attack_surfaces)
        
        # 3. Find related vulnerabilities
        related_vulns = self._find_related_vulnerabilities(findings)
        groups.extend(related_vulns)
        
        # 4. Use Foundation-Sec for intelligent correlation
        if self.foundation_sec and len(findings) > 1:
            ai_correlations = self._ai_correlate(findings)
            groups.extend(ai_correlations)
        
        # 5. Assign correlation_group_id to findings
        findings = self._assign_correlation_ids(findings, groups)
        
        # 6. Update risk scores based on correlations
        findings = self._update_risk_scores(findings, groups)
        
        print(f"✅ Found {len(groups)} correlation groups")
        for group in groups:
            print(f"   - {group.relationship_type}: {len(group.findings)} findings (risk ×{group.risk_multiplier})")
        
        return findings, groups
    
    def _find_exploit_chains(self, findings: List[Finding]) -> List[CorrelationGroup]:
        """
        Find exploit chains: multiple vulnerabilities that can be chained together
        
        Examples:
        - XSS + CSRF in same endpoint
        - SQL injection + weak auth
        - Path traversal + arbitrary file write
        """
        chains = []
        
        # Group by path/endpoint
        by_path = defaultdict(list)
        for f in findings:
            by_path[f.path].append(f)
        
        # Look for dangerous combinations
        for path, path_findings in by_path.items():
            if len(path_findings) < 2:
                continue
            
            categories = {f.category for f in path_findings}
            cwes = {f.cwe for f in path_findings if f.cwe}
            
            # XSS + CSRF
            if 'SAST' in categories and any('79' in str(cwe) for cwe in cwes):  # CWE-79 = XSS
                csrf_findings = [f for f in path_findings if '352' in str(f.cwe or '')]  # CWE-352 = CSRF
                if csrf_findings:
                    chain_id = self._generate_group_id('exploit_chain', path)
                    chains.append(CorrelationGroup(
                        id=chain_id,
                        findings=[f.id for f in path_findings],
                        relationship_type='exploit_chain',
                        risk_multiplier=1.5,
                        description=f'XSS + CSRF exploit chain in {path}',
                        confidence=0.9
                    ))
            
            # SQL injection + weak auth
            if any('89' in str(f.cwe or '') for f in path_findings):  # CWE-89 = SQLi
                auth_findings = [f for f in path_findings if 'auth' in f.rule_name.lower()]
                if auth_findings:
                    chain_id = self._generate_group_id('exploit_chain', path)
                    chains.append(CorrelationGroup(
                        id=chain_id,
                        findings=[f.id for f in path_findings],
                        relationship_type='exploit_chain',
                        risk_multiplier=2.0,
                        description=f'SQL injection + weak auth in {path}',
                        confidence=0.85
                    ))
        
        return chains
    
    def _find_same_attack_surface(self, findings: List[Finding]) -> List[CorrelationGroup]:
        """
        Find findings on the same attack surface
        
        Same module, package, or service
        """
        surfaces = []
        
        # Group by module/package
        by_module = defaultdict(list)
        for f in findings:
            # Extract module from path (e.g., src/auth/login.py -> auth)
            parts = Path(f.path).parts
            module = parts[1] if len(parts) > 1 else parts[0]
            by_module[module].append(f)
        
        # Create groups for modules with multiple high-severity findings
        for module, module_findings in by_module.items():
            high_sev = [f for f in module_findings if f.severity in ['high', 'critical']]
            if len(high_sev) >= 2:
                surface_id = self._generate_group_id('attack_surface', module)
                surfaces.append(CorrelationGroup(
                    id=surface_id,
                    findings=[f.id for f in high_sev],
                    relationship_type='same_attack_surface',
                    risk_multiplier=1.3,
                    description=f'Multiple high-severity findings in {module} module',
                    confidence=0.8
                ))
        
        return surfaces
    
    def _find_related_vulnerabilities(self, findings: List[Finding]) -> List[CorrelationGroup]:
        """
        Find related vulnerabilities (similar root causes)
        
        Same CWE, same rule category, etc.
        """
        related = []
        
        # Group by CWE
        by_cwe = defaultdict(list)
        for f in findings:
            if f.cwe:
                by_cwe[f.cwe].append(f)
        
        # Create groups for CWEs with multiple instances
        for cwe, cwe_findings in by_cwe.items():
            if len(cwe_findings) >= 3:  # At least 3 instances
                related_id = self._generate_group_id('related_vuln', cwe)
                related.append(CorrelationGroup(
                    id=related_id,
                    findings=[f.id for f in cwe_findings],
                    relationship_type='related_vulnerability',
                    risk_multiplier=1.2,
                    description=f'Multiple instances of {cwe} across codebase',
                    confidence=0.9
                ))
        
        return related
    
    def _ai_correlate(self, findings: List[Finding]) -> List[CorrelationGroup]:
        """
        Use Foundation-Sec-8B to find intelligent correlations
        
        AI can identify non-obvious relationships that heuristics miss
        """
        correlations = []
        
        try:
            # Prepare findings summary for AI
            findings_summary = self._prepare_findings_summary(findings)
            
            # Ask Foundation-Sec to find correlations
            prompt = f"""Analyze these security findings and identify correlations that could indicate exploit chains or related attack vectors.

**Findings:**
{findings_summary}

**Task:** Identify groups of findings that are related and could be exploited together. For each group, provide:
1. Finding IDs (from the list above)
2. Relationship type (exploit_chain, same_attack_surface, or related_vulnerability)
3. Risk multiplier (1.0-3.0, how much more dangerous when combined)
4. Brief description

Respond with ONLY a JSON array:
[
  {{
    "finding_ids": ["id1", "id2"],
    "relationship_type": "exploit_chain",
    "risk_multiplier": 1.8,
    "description": "XSS and open redirect can be chained",
    "confidence": 0.85
  }}
]
"""
            
            response = self.foundation_sec.analyze_code(
                code="",  # No specific code, analyzing findings
                context=prompt,
                focus="correlation_analysis"
            )
            
            # Parse AI response
            ai_groups = self._parse_ai_correlations(response, findings)
            correlations.extend(ai_groups)
        
        except Exception as e:
            print(f"⚠️  Foundation-Sec correlation failed: {e}")
        
        return correlations
    
    def _prepare_findings_summary(self, findings: List[Finding]) -> str:
        """Prepare concise summary of findings for AI analysis"""
        summary_lines = []
        for i, f in enumerate(findings[:20], 1):  # Limit to 20 for token efficiency
            summary_lines.append(
                f"{i}. ID:{f.id[:8]} | {f.category} | {f.severity} | {f.rule_name} | {f.path}:{f.line}"
            )
        
        if len(findings) > 20:
            summary_lines.append(f"... and {len(findings) - 20} more findings")
        
        return '\n'.join(summary_lines)
    
    def _parse_ai_correlations(self, response: str, findings: List[Finding]) -> List[CorrelationGroup]:
        """Parse Foundation-Sec correlation response"""
        groups = []
        
        try:
            # Extract JSON from response
            if '[' in response and ']' in response:
                start = response.index('[')
                end = response.rindex(']') + 1
                json_str = response[start:end]
                correlations_data = json.loads(json_str)
                
                # Create CorrelationGroup objects
                for corr in correlations_data:
                    group_id = self._generate_group_id('ai_correlation', str(corr.get('finding_ids', [])))
                    groups.append(CorrelationGroup(
                        id=group_id,
                        findings=corr.get('finding_ids', []),
                        relationship_type=corr.get('relationship_type', 'related_vulnerability'),
                        risk_multiplier=float(corr.get('risk_multiplier', 1.2)),
                        description=corr.get('description', 'AI-identified correlation'),
                        confidence=float(corr.get('confidence', 0.7))
                    ))
        except Exception as e:
            print(f"⚠️  Failed to parse AI correlations: {e}")
        
        return groups
    
    def _assign_correlation_ids(self, findings: List[Finding], groups: List[CorrelationGroup]) -> List[Finding]:
        """Assign correlation_group_id to findings"""
        # Build finding_id -> group_id mapping
        finding_to_group = {}
        for group in groups:
            for finding_id in group.findings:
                if finding_id not in finding_to_group:
                    finding_to_group[finding_id] = []
                finding_to_group[finding_id].append(group.id)
        
        # Assign to findings
        for finding in findings:
            if finding.id in finding_to_group:
                # Join multiple group IDs with comma
                finding.correlation_group_id = ','.join(finding_to_group[finding.id])
        
        return findings
    
    def _update_risk_scores(self, findings: List[Finding], groups: List[CorrelationGroup]) -> List[Finding]:
        """Update risk scores based on correlations"""
        # Build finding_id -> max_risk_multiplier mapping
        risk_multipliers = {}
        for group in groups:
            for finding_id in group.findings:
                current_mult = risk_multipliers.get(finding_id, 1.0)
                risk_multipliers[finding_id] = max(current_mult, group.risk_multiplier)
        
        # Apply multipliers
        for finding in findings:
            if finding.id in risk_multipliers:
                multiplier = risk_multipliers[finding.id]
                finding.risk_score = min(finding.risk_score * multiplier, 10.0)
        
        return findings
    
    def _generate_group_id(self, group_type: str, identifier: str) -> str:
        """Generate unique group ID"""
        key = f"{group_type}:{identifier}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]


def main():
    """CLI interface for correlation"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Correlate security findings')
    parser.add_argument('--input', '-i', required=True, help='Input findings JSON file')
    parser.add_argument('--output', '-o', required=True, help='Output correlated findings JSON file')
    parser.add_argument('--groups-output', help='Output correlation groups JSON file')
    
    args = parser.parse_args()
    
    # Load findings
    with open(args.input, 'r') as f:
        findings_data = json.load(f)
    
    findings = [Finding.from_dict(f) for f in findings_data]
    
    # Correlate findings
    correlator = Correlator()
    correlated_findings, groups = correlator.correlate_findings(findings)
    
    # Save correlated findings
    with open(args.output, 'w') as f:
        json.dump([f.to_dict() for f in correlated_findings], f, indent=2)
    
    print(f"\n✅ Correlated findings saved to {args.output}")
    
    # Save groups if requested
    if args.groups_output:
        with open(args.groups_output, 'w') as f:
            json.dump([asdict(g) for g in groups], f, indent=2)
        print(f"✅ Correlation groups saved to {args.groups_output}")


if __name__ == '__main__':
    main()
