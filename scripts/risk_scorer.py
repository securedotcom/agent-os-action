#!/usr/bin/env python3
"""
Risk Scoring Engine
Calculates risk scores based on PRD formula:
Risk Score = CVSS × Exploitability × Reachability × Business Impact
"""

import json
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum


class Exploitability(str, Enum):
    """Exploitability levels from Aardvark"""
    CRITICAL = "critical"  # 1.0 - Active exploitation in wild
    HIGH = "high"          # 0.8 - PoC exists, easy to exploit
    MEDIUM = "medium"      # 0.5 - Requires specific conditions
    LOW = "low"            # 0.2 - Theoretical/very difficult
    NONE = "none"          # 0.0 - Not exploitable


class Reachability(str, Enum):
    """Reachability levels"""
    DIRECT = "direct"      # 1.0 - Direct code path
    INDIRECT = "indirect"  # 0.6 - Through dependencies
    UNUSED = "unused"      # 0.1 - Code not imported/used


class BusinessImpact(str, Enum):
    """Business impact levels"""
    CRITICAL = "critical"  # 1.0 - Production, customer data
    HIGH = "high"          # 0.8 - Core functionality
    MEDIUM = "medium"      # 0.5 - Non-critical features
    LOW = "low"            # 0.2 - Dev/test environments


@dataclass
class RiskScore:
    """Risk score result"""
    finding_id: str
    raw_score: float      # 0-10 scale
    normalized_score: int # 0-100 scale
    severity: str         # critical, high, medium, low
    factors: Dict[str, float]
    priority: int         # 1 (highest) to 4 (lowest)


class RiskScorer:
    """Calculate risk scores for security findings"""
    
    # Multipliers for each factor
    EXPLOITABILITY_MULTIPLIERS = {
        Exploitability.CRITICAL: 1.0,
        Exploitability.HIGH: 0.8,
        Exploitability.MEDIUM: 0.5,
        Exploitability.LOW: 0.2,
        Exploitability.NONE: 0.0,
    }
    
    REACHABILITY_MULTIPLIERS = {
        Reachability.DIRECT: 1.0,
        Reachability.INDIRECT: 0.6,
        Reachability.UNUSED: 0.1,
    }
    
    BUSINESS_IMPACT_MULTIPLIERS = {
        BusinessImpact.CRITICAL: 1.0,
        BusinessImpact.HIGH: 0.8,
        BusinessImpact.MEDIUM: 0.5,
        BusinessImpact.LOW: 0.2,
    }
    
    # Risk score thresholds
    SEVERITY_THRESHOLDS = {
        'critical': 80,  # 80-100
        'high': 60,      # 60-79
        'medium': 40,    # 40-59
        'low': 0,        # 0-39
    }
    
    def __init__(self, default_business_impact: str = 'high'):
        """
        Initialize risk scorer
        
        Args:
            default_business_impact: Default business impact if not specified
        """
        self.default_business_impact = BusinessImpact(default_business_impact)
    
    def score_finding(self, finding: Dict) -> RiskScore:
        """
        Calculate risk score for a single finding
        
        Args:
            finding: Normalized finding with metadata
            
        Returns:
            RiskScore: Calculated risk score
        """
        # Extract factors
        cvss = self._get_cvss(finding)
        exploitability = self._get_exploitability(finding)
        reachability = self._get_reachability(finding)
        business_impact = self._get_business_impact(finding)
        
        # Get multipliers
        exploit_mult = self.EXPLOITABILITY_MULTIPLIERS.get(exploitability, 0.5)
        reach_mult = self.REACHABILITY_MULTIPLIERS.get(reachability, 0.6)
        impact_mult = self.BUSINESS_IMPACT_MULTIPLIERS.get(business_impact, 0.8)
        
        # Calculate raw score (0-10 scale)
        # Formula: CVSS × Exploitability × Reachability × Business Impact
        raw_score = cvss * exploit_mult * reach_mult * impact_mult
        
        # Normalize to 0-100 scale
        normalized_score = int(raw_score * 10)
        normalized_score = max(0, min(100, normalized_score))  # Clamp to 0-100
        
        # Determine severity
        severity = self._score_to_severity(normalized_score)
        
        # Determine priority (1=highest, 4=lowest)
        priority = self._score_to_priority(normalized_score)
        
        return RiskScore(
            finding_id=finding.get('id'),
            raw_score=round(raw_score, 2),
            normalized_score=normalized_score,
            severity=severity,
            factors={
                'cvss': cvss,
                'exploitability': exploit_mult,
                'reachability': reach_mult,
                'business_impact': impact_mult
            },
            priority=priority
        )
    
    def score_findings(self, findings: List[Dict]) -> List[RiskScore]:
        """Score multiple findings and sort by risk"""
        scores = [self.score_finding(f) for f in findings]
        
        # Sort by normalized score (descending)
        scores.sort(key=lambda x: x.normalized_score, reverse=True)
        
        # Print summary
        self._print_summary(scores)
        
        return scores
    
    def enrich_findings(self, findings: List[Dict]) -> List[Dict]:
        """
        Enrich findings with risk scores
        
        Args:
            findings: List of normalized findings
            
        Returns:
            List[Dict]: Findings with risk_score added
        """
        scores = self.score_findings(findings)
        score_map = {s.finding_id: s for s in scores}
        
        enriched = []
        for finding in findings:
            finding_id = finding.get('id')
            
            if finding_id in score_map:
                score = score_map[finding_id]
                finding['risk_score'] = score.normalized_score
                finding['risk_severity'] = score.severity
                finding['risk_priority'] = score.priority
                finding['risk_factors'] = score.factors
            
            enriched.append(finding)
        
        # Sort by risk score
        enriched.sort(key=lambda x: x.get('risk_score', 0), reverse=True)
        
        return enriched
    
    def _get_cvss(self, finding: Dict) -> float:
        """Extract CVSS score (0-10)"""
        # Try various fields where CVSS might be
        cvss = finding.get('cvss_score', 0.0)
        
        if cvss == 0.0:
            # Try parsing from metadata
            metadata = finding.get('metadata', {})
            cvss = metadata.get('cvss', 0.0)
        
        if cvss == 0.0:
            # Fallback: estimate from severity
            severity_map = {
                'critical': 9.0,
                'high': 7.0,
                'medium': 5.0,
                'low': 3.0,
                'info': 0.0
            }
            severity = finding.get('severity', 'medium').lower()
            cvss = severity_map.get(severity, 5.0)
        
        return float(cvss)
    
    def _get_exploitability(self, finding: Dict) -> Exploitability:
        """Extract exploitability level"""
        exploit = finding.get('exploitability', '').lower()
        
        if exploit in ['critical', 'active', 'in-the-wild']:
            return Exploitability.CRITICAL
        elif exploit in ['high', 'poc-exists', 'easy']:
            return Exploitability.HIGH
        elif exploit in ['medium', 'moderate']:
            return Exploitability.MEDIUM
        elif exploit in ['low', 'difficult', 'theoretical']:
            return Exploitability.LOW
        else:
            # Default to medium for vulns, low for other findings
            if finding.get('category') == 'VULN':
                return Exploitability.MEDIUM
            else:
                return Exploitability.LOW
    
    def _get_reachability(self, finding: Dict) -> Reachability:
        """Extract reachability level"""
        # Check if reachability analysis was done
        if 'reachable' in finding:
            is_reachable = finding.get('reachable', False)
            confidence = finding.get('reachability_confidence', 'medium')
            
            if is_reachable and confidence == 'high':
                return Reachability.DIRECT
            elif is_reachable:
                return Reachability.INDIRECT
            else:
                return Reachability.UNUSED
        else:
            # Default: assume indirect reachability for vulns
            if finding.get('category') == 'VULN':
                return Reachability.INDIRECT
            else:
                return Reachability.DIRECT
    
    def _get_business_impact(self, finding: Dict) -> BusinessImpact:
        """Extract business impact level"""
        impact = finding.get('business_impact', '').lower()
        
        if impact in ['critical', 'production']:
            return BusinessImpact.CRITICAL
        elif impact in ['high', 'core']:
            return BusinessImpact.HIGH
        elif impact in ['medium', 'standard']:
            return BusinessImpact.MEDIUM
        elif impact in ['low', 'dev', 'test']:
            return BusinessImpact.LOW
        else:
            return self.default_business_impact
    
    def _score_to_severity(self, score: int) -> str:
        """Convert numeric score to severity"""
        if score >= self.SEVERITY_THRESHOLDS['critical']:
            return 'critical'
        elif score >= self.SEVERITY_THRESHOLDS['high']:
            return 'high'
        elif score >= self.SEVERITY_THRESHOLDS['medium']:
            return 'medium'
        else:
            return 'low'
    
    def _score_to_priority(self, score: int) -> int:
        """Convert numeric score to priority (1-4)"""
        if score >= 80:
            return 1  # P1 - Critical
        elif score >= 60:
            return 2  # P2 - High
        elif score >= 40:
            return 3  # P3 - Medium
        else:
            return 4  # P4 - Low
    
    def _print_summary(self, scores: List[RiskScore]):
        """Print risk score summary"""
        if not scores:
            return
        
        by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for score in scores:
            by_severity[score.severity] += 1
        
        print(f"\n📊 Risk Score Summary:")
        print(f"   Total Findings: {len(scores)}")
        print(f"   Critical (P1): {by_severity['critical']}")
        print(f"   High (P2): {by_severity['high']}")
        print(f"   Medium (P3): {by_severity['medium']}")
        print(f"   Low (P4): {by_severity['low']}")
        
        # Show top 5 riskiest findings
        if scores:
            print(f"\n🔥 Top 5 Riskiest Findings:")
            for i, score in enumerate(scores[:5], 1):
                print(f"   {i}. Score: {score.normalized_score}/100 ({score.severity}) - ID: {score.finding_id[:16]}...")


def main():
    """CLI entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Calculate risk scores for security findings'
    )
    parser.add_argument(
        'findings',
        help='Path to findings JSON file'
    )
    parser.add_argument(
        '--business-impact',
        default='high',
        choices=['critical', 'high', 'medium', 'low'],
        help='Default business impact level'
    )
    parser.add_argument(
        '-o', '--output',
        help='Output file for enriched findings'
    )
    
    args = parser.parse_args()
    
    # Load findings
    with open(args.findings) as f:
        findings = json.load(f)
    
    # Calculate risk scores
    scorer = RiskScorer(default_business_impact=args.business_impact)
    enriched = scorer.enrich_findings(findings)
    
    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(enriched, f, indent=2)
        print(f"\n✅ Risk-scored findings written to {args.output}")
    else:
        print(json.dumps(enriched, indent=2))


if __name__ == '__main__':
    main()

