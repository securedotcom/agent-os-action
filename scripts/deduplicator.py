#!/usr/bin/env python3
"""
Finding Deduplicator
Identifies and merges duplicate findings across multiple repositories
Uses content-based hashing and fuzzy matching
"""

import json
import hashlib
from typing import Dict, List, Set, Tuple
from pathlib import Path
from dataclasses import dataclass
from collections import defaultdict


@dataclass
class DuplicateGroup:
    """Group of duplicate findings"""
    canonical_id: str
    finding_ids: List[str]
    repos: List[str]
    count: int
    severity: str
    rule_id: str


class FindingDeduplicator:
    """Deduplicate findings across repositories"""
    
    def __init__(self, fuzzy_threshold: float = 0.9):
        """
        Initialize deduplicator
        
        Args:
            fuzzy_threshold: Similarity threshold for fuzzy matching (0.0-1.0)
        """
        self.fuzzy_threshold = fuzzy_threshold
        self.duplicate_groups: List[DuplicateGroup] = []
    
    def deduplicate_findings(
        self,
        findings_by_repo: Dict[str, List[Dict]]
    ) -> Tuple[List[Dict], List[DuplicateGroup]]:
        """
        Deduplicate findings across multiple repositories
        
        Args:
            findings_by_repo: Dict mapping repo name to list of findings
            
        Returns:
            Tuple of (deduplicated_findings, duplicate_groups)
        """
        print(f"🔍 Deduplicating findings across {len(findings_by_repo)} repositories...")
        
        # Step 1: Create content hashes for all findings
        all_findings = []
        finding_to_repo = {}
        
        for repo, findings in findings_by_repo.items():
            for finding in findings:
                finding['repo'] = repo  # Ensure repo is set
                all_findings.append(finding)
                finding_to_repo[finding.get('id')] = repo
        
        print(f"   Total findings before dedup: {len(all_findings)}")
        
        # Step 2: Group by content hash (exact duplicates)
        hash_groups = defaultdict(list)
        
        for finding in all_findings:
            content_hash = self._compute_content_hash(finding)
            hash_groups[content_hash].append(finding)
        
        # Step 3: Merge exact duplicates
        deduplicated = []
        duplicate_groups = []
        
        for content_hash, group in hash_groups.items():
            if len(group) == 1:
                # Not a duplicate
                deduplicated.append(group[0])
            else:
                # Duplicate group - merge into canonical finding
                canonical = self._merge_findings(group)
                deduplicated.append(canonical)
                
                # Track duplicate group
                repos = list(set(f.get('repo', 'unknown') for f in group))
                duplicate_groups.append(DuplicateGroup(
                    canonical_id=canonical.get('id'),
                    finding_ids=[f.get('id') for f in group],
                    repos=repos,
                    count=len(group),
                    severity=canonical.get('severity'),
                    rule_id=canonical.get('rule_id')
                ))
        
        # Step 4: Fuzzy matching for near-duplicates (optional)
        if self.fuzzy_threshold < 1.0:
            deduplicated, fuzzy_groups = self._fuzzy_deduplicate(deduplicated)
            duplicate_groups.extend(fuzzy_groups)
        
        self.duplicate_groups = duplicate_groups
        
        # Print summary
        self._print_summary(len(all_findings), len(deduplicated), duplicate_groups)
        
        return deduplicated, duplicate_groups
    
    def _compute_content_hash(self, finding: Dict) -> str:
        """
        Compute content-based hash for a finding
        Uses: rule_id + severity + category + normalized path
        """
        # Extract key fields
        rule_id = finding.get('rule_id', '')
        severity = finding.get('severity', '')
        category = finding.get('category', '')
        
        # Normalize path (remove repo-specific prefix)
        path = finding.get('path', '')
        normalized_path = Path(path).name  # Just filename
        
        # For code findings, include line range
        line_start = finding.get('line_start', 0)
        line_end = finding.get('line_end', 0)
        
        # For secrets, include detector type
        detector = finding.get('metadata', {}).get('detector', '')
        
        # Combine into hash key
        hash_input = f"{rule_id}|{severity}|{category}|{normalized_path}|{line_start}|{line_end}|{detector}"
        
        return hashlib.sha256(hash_input.encode()).hexdigest()[:16]
    
    def _merge_findings(self, findings: List[Dict]) -> Dict:
        """
        Merge duplicate findings into canonical finding
        
        Strategy:
        - Use first finding as base
        - Add 'duplicate_of' references
        - Merge repos list
        - Keep earliest timestamp
        """
        # Sort by timestamp (oldest first)
        sorted_findings = sorted(
            findings,
            key=lambda f: f.get('timestamp', '9999-99-99')
        )
        
        canonical = sorted_findings[0].copy()
        
        # Add duplicate metadata
        canonical['is_canonical'] = True
        canonical['duplicate_count'] = len(findings) - 1
        canonical['duplicate_ids'] = [f.get('id') for f in sorted_findings[1:]]
        
        # Merge repos
        repos = list(set(f.get('repo', 'unknown') for f in findings))
        canonical['affected_repos'] = repos
        canonical['repo_count'] = len(repos)
        
        # Keep highest severity if different
        severities = [f.get('severity') for f in findings]
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        canonical['severity'] = min(severities, key=lambda s: severity_order.get(s, 99))
        
        return canonical
    
    def _fuzzy_deduplicate(
        self,
        findings: List[Dict]
    ) -> Tuple[List[Dict], List[DuplicateGroup]]:
        """
        Fuzzy matching for near-duplicates
        Groups findings with similar characteristics but not exact matches
        """
        # For now, group by rule_id + severity (simple fuzzy match)
        fuzzy_groups = defaultdict(list)
        
        for finding in findings:
            if finding.get('is_canonical'):
                continue  # Skip already merged findings
            
            key = f"{finding.get('rule_id')}|{finding.get('severity')}"
            fuzzy_groups[key].append(finding)
        
        deduplicated = []
        duplicate_groups = []
        
        for key, group in fuzzy_groups.items():
            if len(group) <= 1:
                deduplicated.extend(group)
            else:
                # Group by repo to avoid merging same-repo findings
                by_repo = defaultdict(list)
                for finding in group:
                    repo = finding.get('repo', 'unknown')
                    by_repo[repo].append(finding)
                
                # If same issue across multiple repos, merge
                if len(by_repo) > 1:
                    canonical = self._merge_findings(group)
                    deduplicated.append(canonical)
                    
                    repos = list(by_repo.keys())
                    duplicate_groups.append(DuplicateGroup(
                        canonical_id=canonical.get('id'),
                        finding_ids=[f.get('id') for f in group],
                        repos=repos,
                        count=len(group),
                        severity=canonical.get('severity'),
                        rule_id=canonical.get('rule_id')
                    ))
                else:
                    # Same repo, keep separate
                    deduplicated.extend(group)
        
        return deduplicated, duplicate_groups
    
    def _print_summary(
        self,
        original_count: int,
        deduplicated_count: int,
        duplicate_groups: List[DuplicateGroup]
    ):
        """Print deduplication summary"""
        reduction = original_count - deduplicated_count
        reduction_pct = (reduction / original_count * 100) if original_count > 0 else 0
        
        print(f"\n📊 Deduplication Summary:")
        print(f"   Original findings: {original_count}")
        print(f"   After dedup: {deduplicated_count}")
        print(f"   Removed: {reduction} ({reduction_pct:.1f}% reduction)")
        print(f"   Duplicate groups: {len(duplicate_groups)}")
        
        # Show top duplicate groups
        if duplicate_groups:
            sorted_groups = sorted(duplicate_groups, key=lambda g: g.count, reverse=True)
            print(f"\n🔄 Top 5 Most Common Duplicates:")
            for i, group in enumerate(sorted_groups[:5], 1):
                print(f"   {i}. {group.rule_id} ({group.severity})")
                print(f"      - Found in {len(group.repos)} repos: {', '.join(group.repos[:3])}")
                print(f"      - {group.count} occurrences")
    
    def save_duplicate_report(self, output_file: str):
        """Save duplicate groups report"""
        report = {
            'duplicate_groups': [
                {
                    'canonical_id': g.canonical_id,
                    'rule_id': g.rule_id,
                    'severity': g.severity,
                    'count': g.count,
                    'repos': g.repos,
                    'finding_ids': g.finding_ids
                }
                for g in self.duplicate_groups
            ],
            'total_groups': len(self.duplicate_groups),
            'total_duplicates': sum(g.count - 1 for g in self.duplicate_groups)
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"✅ Duplicate report saved to {output_file}")


def main():
    """CLI entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Deduplicate findings across multiple repositories'
    )
    parser.add_argument(
        'findings_dir',
        help='Directory containing per-repo findings JSON files'
    )
    parser.add_argument(
        '-o', '--output',
        default='deduplicated_findings.json',
        help='Output file for deduplicated findings'
    )
    parser.add_argument(
        '--duplicate-report',
        default='duplicate_report.json',
        help='Output file for duplicate groups report'
    )
    parser.add_argument(
        '--fuzzy-threshold',
        type=float,
        default=0.9,
        help='Similarity threshold for fuzzy matching (0.0-1.0)'
    )
    
    args = parser.parse_args()
    
    # Load findings from directory
    findings_dir = Path(args.findings_dir)
    findings_by_repo = {}
    
    for findings_file in findings_dir.glob('*_findings.json'):
        repo_name = findings_file.stem.replace('_findings', '').replace('_', '/')
        
        with open(findings_file) as f:
            findings = json.load(f)
        
        findings_by_repo[repo_name] = findings
    
    if not findings_by_repo:
        print(f"❌ No findings files found in {findings_dir}")
        exit(1)
    
    # Deduplicate
    deduplicator = FindingDeduplicator(fuzzy_threshold=args.fuzzy_threshold)
    deduplicated, duplicate_groups = deduplicator.deduplicate_findings(findings_by_repo)
    
    # Save results
    with open(args.output, 'w') as f:
        json.dump(deduplicated, f, indent=2)
    
    print(f"\n✅ Deduplicated findings saved to {args.output}")
    
    # Save duplicate report
    deduplicator.save_duplicate_report(args.duplicate_report)


if __name__ == '__main__':
    main()

