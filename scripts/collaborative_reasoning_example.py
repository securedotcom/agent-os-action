#!/usr/bin/env python3
"""
Example usage of Collaborative Reasoning System

This script demonstrates how to use the collaborative reasoning system
for multi-agent security finding analysis.
"""

import json
import sys
from pathlib import Path

# Ensure scripts directory is in path
SCRIPT_DIR = Path(__file__).parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from collaborative_reasoning import (
    CollaborativeReasoning,
    create_comprehensive_agent_team,
    create_default_agent_team,
)


# Mock LLM Provider for testing (replace with real provider in production)
class MockLLMProvider:
    """Mock LLM provider for testing without API calls"""

    def __init__(self):
        self.call_count = 0

    def generate(self, prompt: str, system_prompt: str = None) -> str:
        """Generate mock responses based on agent type and finding"""
        self.call_count += 1

        # Detect agent type from system prompt
        if system_prompt and "SecretHunter" in system_prompt:
            if "test" in prompt.lower() or "fixture" in prompt.lower():
                return json.dumps(
                    {
                        "decision": "false_positive",
                        "confidence": 0.85,
                        "reasoning": "This appears to be in test fixtures. Test files often contain mock secrets for testing authentication flows.",
                        "severity_assessment": "low",
                        "key_evidence": ["File path contains 'tests/'", "Mock data pattern detected"],
                        "concerns": [],
                        "questions_for_others": ["Can someone verify this is actually a test file?"],
                    }
                )
            else:
                return json.dumps(
                    {
                        "decision": "confirmed",
                        "confidence": 0.9,
                        "reasoning": "High-entropy string matching API key pattern. This appears to be a valid hardcoded secret.",
                        "severity_assessment": "critical",
                        "key_evidence": ["High entropy (7.2 bits)", "Matches AWS access key format"],
                        "concerns": ["Could be a test key but no indication in file path"],
                        "questions_for_others": [],
                    }
                )

        elif system_prompt and "FalsePositiveFilter" in system_prompt:
            if "test" in prompt.lower() or "fixture" in prompt.lower():
                return json.dumps(
                    {
                        "decision": "false_positive",
                        "confidence": 0.95,
                        "reasoning": "File path tests/fixtures/config.py clearly indicates test fixture. Not production code.",
                        "severity_assessment": "info",
                        "key_evidence": ["tests/ directory", "fixtures/ subdirectory", "Mock data patterns"],
                        "concerns": [],
                        "questions_for_others": [],
                    }
                )
            else:
                return json.dumps(
                    {
                        "decision": "uncertain",
                        "confidence": 0.6,
                        "reasoning": "Need more context to determine if this is production code or test/example.",
                        "severity_assessment": "medium",
                        "key_evidence": [],
                        "concerns": ["File path doesn't clearly indicate test or production"],
                        "questions_for_others": ["What is the purpose of this file?"],
                    }
                )

        elif system_prompt and "ExploitAssessor" in system_prompt:
            return json.dumps(
                {
                    "decision": "confirmed",
                    "confidence": 0.8,
                    "reasoning": "If this is production code, hardcoded secrets are trivially exploitable. However, severity depends on whether this is actually deployed.",
                    "severity_assessment": "high",
                    "key_evidence": ["Hardcoded secrets allow unauthorized access"],
                    "concerns": ["Need to confirm if this is deployed code"],
                    "questions_for_others": ["Is this file deployed to production?"],
                }
            )

        # Default response for discussion rounds
        return "I agree with the consensus. The evidence supports this conclusion."


def example_1_test_fixture_secret():
    """
    Example 1: Hardcoded secret in test fixture
    Expected: FALSE POSITIVE (consensus reached)
    """
    print("=" * 80)
    print("Example 1: Hardcoded Secret in Test Fixture")
    print("=" * 80)

    # Initialize mock LLM and agents
    llm = MockLLMProvider()
    agents = create_default_agent_team(llm)

    # Initialize collaborative reasoning
    collab = CollaborativeReasoning(agents, min_consensus_threshold=0.6)

    # Sample finding - secret in test file
    finding = {
        "id": "finding-001",
        "origin": "gitleaks",
        "path": "tests/fixtures/config.py",
        "line": 42,
        "severity": "high",
        "rule_id": "hardcoded-password",
        "rule_name": "Hardcoded Password",
        "category": "SECRETS",
        "evidence": {
            "matched_string": "password = 'test123'",
            "entropy": 3.2,
        },
    }

    print("\nFinding Details:")
    print(json.dumps(finding, indent=2))

    # Run collaborative analysis
    print("\n" + "-" * 80)
    print("Running Collaborative Analysis (Discussion Mode)...")
    print("-" * 80 + "\n")

    verdict = collab.analyze_collaboratively(finding, mode="discussion", max_rounds=2)

    # Display results
    print("\n" + "=" * 80)
    print("VERDICT")
    print("=" * 80)
    print(f"Final Decision: {verdict.final_decision}")
    print(f"Confidence: {verdict.confidence:.2%}")
    print(f"Consensus Reached: {verdict.consensus_reached}")
    print(f"Discussion Rounds: {verdict.discussion_rounds}")
    print(f"Final Severity: {verdict.final_severity}")
    print(f"\nDecision Breakdown: {verdict.decision_breakdown}")
    print(f"\nResolution Method: {verdict.conflict_resolution_method}")

    print("\n" + "-" * 80)
    print("Agent Opinions:")
    print("-" * 80)
    for opinion in verdict.agent_opinions:
        print(f"\n{opinion.agent_name} ({opinion.persona_type}):")
        print(f"  Decision: {opinion.analysis.decision} (confidence: {opinion.analysis.confidence:.2%})")
        print(f"  Reasoning: {opinion.analysis.reasoning[:200]}...")
        if opinion.discussion_notes:
            print(f"  Discussion: {len(opinion.discussion_notes)} rounds")

    print("\n" + "-" * 80)
    print("Combined Reasoning:")
    print("-" * 80)
    print(verdict.reasoning)
    print("\n")

    return verdict


def example_2_production_secret():
    """
    Example 2: Hardcoded secret in production code
    Expected: CONFIRMED (consensus reached)
    """
    print("\n" + "=" * 80)
    print("Example 2: Hardcoded Secret in Production Code")
    print("=" * 80)

    llm = MockLLMProvider()
    agents = create_default_agent_team(llm)
    collab = CollaborativeReasoning(agents, min_consensus_threshold=0.6)

    # Sample finding - secret in production file
    finding = {
        "id": "finding-002",
        "origin": "trufflehog",
        "path": "app/config/production.py",
        "line": 15,
        "severity": "critical",
        "rule_id": "aws-access-key",
        "rule_name": "AWS Access Key",
        "category": "SECRETS",
        "evidence": {
            "matched_string": "AKIAIOSFODNN7EXAMPLE",
            "detector_type": "AWS",
            "verified": True,
            "entropy": 7.2,
        },
    }

    print("\nFinding Details:")
    print(json.dumps(finding, indent=2))

    print("\n" + "-" * 80)
    print("Running Collaborative Analysis (Independent Mode)...")
    print("-" * 80 + "\n")

    verdict = collab.analyze_collaboratively(finding, mode="independent")

    # Display results
    print("\n" + "=" * 80)
    print("VERDICT")
    print("=" * 80)
    print(f"Final Decision: {verdict.final_decision}")
    print(f"Confidence: {verdict.confidence:.2%}")
    print(f"Consensus Reached: {verdict.consensus_reached}")
    print(f"Final Severity: {verdict.final_severity}")
    print(f"\nDecision Breakdown: {verdict.decision_breakdown}")

    print("\n" + "-" * 80)
    print("Agent Summary:")
    print("-" * 80)
    for opinion in verdict.agent_opinions:
        print(f"  {opinion.agent_name}: {opinion.analysis.decision} ({opinion.analysis.confidence:.2%})")

    print("\n")
    return verdict


def example_3_conflicting_opinions():
    """
    Example 3: Finding with conflicting agent opinions
    Expected: NEEDS_REVIEW (escalated for manual review)
    """
    print("\n" + "=" * 80)
    print("Example 3: Conflicting Agent Opinions")
    print("=" * 80)

    # Use comprehensive team for more diverse opinions
    llm = MockLLMProvider()
    agents = create_comprehensive_agent_team(llm)
    collab = CollaborativeReasoning(agents, min_consensus_threshold=0.6)

    finding = {
        "id": "finding-003",
        "origin": "semgrep",
        "path": "app/utils/helpers.py",
        "line": 78,
        "severity": "medium",
        "rule_id": "sql-injection",
        "rule_name": "SQL Injection Risk",
        "category": "SAST",
        "evidence": {
            "code_snippet": 'query = f"SELECT * FROM users WHERE id = {user_id}"',
        },
    }

    print("\nFinding Details:")
    print(json.dumps(finding, indent=2))

    print("\n" + "-" * 80)
    print("Running Collaborative Analysis (Discussion Mode with 5 agents)...")
    print("-" * 80 + "\n")

    verdict = collab.analyze_collaboratively(finding, mode="discussion", max_rounds=2)

    # Display results
    print("\n" + "=" * 80)
    print("VERDICT")
    print("=" * 80)
    print(f"Final Decision: {verdict.final_decision}")
    print(f"Confidence: {verdict.confidence:.2%}")
    print(f"Consensus Reached: {verdict.consensus_reached}")

    if verdict.escalation_reason:
        print(f"\nEscalation Reason: {verdict.escalation_reason}")

    print(f"\nDecision Breakdown: {verdict.decision_breakdown}")
    print(f"Resolution Method: {verdict.conflict_resolution_method}")

    print("\n" + "-" * 80)
    print("All Agent Opinions:")
    print("-" * 80)
    for opinion in verdict.agent_opinions:
        print(f"\n{opinion.agent_name}:")
        print(f"  Decision: {opinion.analysis.decision}")
        print(f"  Confidence: {opinion.analysis.confidence:.2%}")
        if opinion.opinion_changes:
            print(f"  Opinion Changes: {len(opinion.opinion_changes)}")

    print("\n")
    return verdict


def save_verdict_to_file(verdict, filename):
    """Save verdict to JSON file for inspection"""
    output_path = Path("./collaborative_reasoning_output") / filename
    output_path.parent.mkdir(exist_ok=True)

    with open(output_path, "w") as f:
        json.dump(verdict.to_dict(), f, indent=2)

    print(f"Verdict saved to: {output_path}")


def main():
    """Run all examples"""
    print("\n" + "=" * 80)
    print("COLLABORATIVE REASONING SYSTEM - EXAMPLES")
    print("=" * 80 + "\n")

    # Run examples
    try:
        verdict1 = example_1_test_fixture_secret()
        verdict2 = example_2_production_secret()
        verdict3 = example_3_conflicting_opinions()

        # Summary
        print("\n" + "=" * 80)
        print("SUMMARY OF ALL EXAMPLES")
        print("=" * 80)
        print(f"\nExample 1 (Test Fixture): {verdict1.final_decision} (confidence: {verdict1.confidence:.2%})")
        print(f"Example 2 (Production Secret): {verdict2.final_decision} (confidence: {verdict2.confidence:.2%})")
        print(f"Example 3 (Conflicting): {verdict3.final_decision} (confidence: {verdict3.confidence:.2%})")

        print("\n" + "=" * 80)
        print("Key Insights:")
        print("=" * 80)
        print("1. Multi-agent collaboration improves accuracy by combining specialized expertise")
        print("2. Discussion mode allows agents to reconsider opinions based on peer feedback")
        print("3. Conflicting opinions trigger escalation for human review")
        print("4. Full reasoning chain provides transparency and audit trail")
        print("\nCollaborative reasoning is ready for production use!")

    except Exception as e:
        print(f"\nError running examples: {e}")
        import traceback

        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
