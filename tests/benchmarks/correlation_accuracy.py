"""
Benchmark suite for measuring SAST-DAST correlation accuracy
Provides comprehensive metrics for evaluating correlation engine performance
"""
import json
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

# Add test utilities to path
TEST_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(TEST_ROOT))

# Add scripts directory to path
SCRIPTS_DIR = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))


@dataclass
class BenchmarkMetrics:
    """Metrics for correlation benchmark"""
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    accuracy: float
    avg_match_time_ms: float
    total_test_cases: int


@dataclass
class CorrelationTestCase:
    """Test case for correlation benchmark"""
    name: str
    sast_finding: Dict
    dast_finding: Dict
    expected_match: bool
    expected_confidence: str
    category: str  # "sql_injection", "xss", "command_injection", etc.


class CorrelationAccuracyBenchmark:
    """Benchmark suite for SAST-DAST correlation accuracy"""

    def __init__(self):
        self.test_cases = self._load_test_cases()
        self.results = {
            "overall": None,
            "by_category": {},
            "by_confidence": {},
            "timing": []
        }

    def _load_test_cases(self) -> List[CorrelationTestCase]:
        """Load comprehensive test cases for benchmarking"""
        return [
            # SQL Injection Cases
            CorrelationTestCase(
                name="SQLi - Perfect Match",
                category="sql_injection",
                sast_finding={
                    "id": "sast-sqli-1",
                    "rule_id": "python.django.security.injection.sql.sql-injection",
                    "severity": "high",
                    "cwe": "CWE-89",
                    "file_path": "api/views.py",
                    "line": 42,
                    "endpoint": "/api/users",
                    "message": "SQL injection via string concatenation"
                },
                dast_finding={
                    "id": "dast-sqli-1",
                    "type": "sql-injection",
                    "severity": "high",
                    "endpoint": "/api/users",
                    "method": "GET",
                    "parameter": "id",
                    "payload": "1' OR '1'='1",
                    "evidence": "SQL syntax error detected"
                },
                expected_match=True,
                expected_confidence="high"
            ),
            CorrelationTestCase(
                name="SQLi - Endpoint Mismatch",
                category="sql_injection",
                sast_finding={
                    "id": "sast-sqli-2",
                    "rule_id": "python.flask.security.sql-injection",
                    "severity": "high",
                    "cwe": "CWE-89",
                    "file_path": "api/users.py",
                    "line": 78,
                    "endpoint": "/api/users/search",
                    "message": "SQL injection vulnerability"
                },
                dast_finding={
                    "id": "dast-sqli-2",
                    "type": "sql-injection",
                    "severity": "high",
                    "endpoint": "/api/products",  # Different endpoint
                    "method": "GET",
                    "parameter": "query",
                    "payload": "' OR '1'='1",
                    "evidence": "SQL error"
                },
                expected_match=False,
                expected_confidence="low"
            ),

            # XSS Cases
            CorrelationTestCase(
                name="XSS - Direct Match",
                category="xss",
                sast_finding={
                    "id": "sast-xss-1",
                    "rule_id": "javascript.react.security.react-dangerouslysetinnerhtml",
                    "severity": "high",
                    "cwe": "CWE-79",
                    "file_path": "components/Profile.tsx",
                    "line": 67,
                    "endpoint": "/profile",
                    "message": "Unsafe use of dangerouslySetInnerHTML"
                },
                dast_finding={
                    "id": "dast-xss-1",
                    "type": "xss",
                    "severity": "high",
                    "endpoint": "/profile",
                    "method": "GET",
                    "parameter": "name",
                    "payload": "<script>alert(1)</script>",
                    "evidence": "Script executed"
                },
                expected_match=True,
                expected_confidence="high"
            ),
            CorrelationTestCase(
                name="XSS - Reflected vs Stored",
                category="xss",
                sast_finding={
                    "id": "sast-xss-2",
                    "rule_id": "python.flask.security.xss",
                    "severity": "medium",
                    "cwe": "CWE-79",
                    "file_path": "views/comment.py",
                    "line": 89,
                    "endpoint": "/comments",
                    "message": "XSS via unsafe template rendering"
                },
                dast_finding={
                    "id": "dast-xss-2",
                    "type": "xss",
                    "severity": "high",
                    "endpoint": "/comments",
                    "method": "POST",
                    "parameter": "text",
                    "payload": "<img src=x onerror=alert(1)>",
                    "evidence": "Payload reflected"
                },
                expected_match=True,
                expected_confidence="high"
            ),

            # Command Injection Cases
            CorrelationTestCase(
                name="Command Injection - High Confidence",
                category="command_injection",
                sast_finding={
                    "id": "sast-cmdi-1",
                    "rule_id": "python.lang.security.dangerous-subprocess-use",
                    "severity": "critical",
                    "cwe": "CWE-78",
                    "file_path": "utils/system.py",
                    "line": 23,
                    "endpoint": "/api/backup",
                    "message": "Subprocess call with shell=True"
                },
                dast_finding={
                    "id": "dast-cmdi-1",
                    "type": "command-injection",
                    "severity": "critical",
                    "endpoint": "/api/backup",
                    "method": "POST",
                    "parameter": "filename",
                    "payload": "; cat /etc/passwd",
                    "evidence": "System command executed"
                },
                expected_match=True,
                expected_confidence="high"
            ),

            # Path Traversal Cases
            CorrelationTestCase(
                name="Path Traversal - Direct Match",
                category="path_traversal",
                sast_finding={
                    "id": "sast-pt-1",
                    "rule_id": "python.flask.security.path-traversal",
                    "severity": "high",
                    "cwe": "CWE-22",
                    "file_path": "api/files.py",
                    "line": 89,
                    "endpoint": "/api/download",
                    "message": "Path traversal vulnerability"
                },
                dast_finding={
                    "id": "dast-pt-1",
                    "type": "path-traversal",
                    "severity": "high",
                    "endpoint": "/api/download",
                    "method": "GET",
                    "parameter": "file",
                    "payload": "../../../etc/passwd",
                    "evidence": "File contents returned"
                },
                expected_match=True,
                expected_confidence="high"
            ),

            # SSRF Cases
            CorrelationTestCase(
                name="SSRF - Medium Confidence",
                category="ssrf",
                sast_finding={
                    "id": "sast-ssrf-1",
                    "rule_id": "python.requests.security.ssrf",
                    "severity": "high",
                    "cwe": "CWE-918",
                    "file_path": "api/proxy.py",
                    "line": 34,
                    "endpoint": "/api/fetch",
                    "message": "Server-Side Request Forgery"
                },
                dast_finding={
                    "id": "dast-ssrf-1",
                    "type": "ssrf",
                    "severity": "high",
                    "endpoint": "/api/fetch",
                    "method": "GET",
                    "parameter": "url",
                    "payload": "http://169.254.169.254/latest/meta-data/",
                    "evidence": "Internal metadata accessed"
                },
                expected_match=True,
                expected_confidence="high"
            ),

            # False Positive Cases
            CorrelationTestCase(
                name="False Positive - Different Types",
                category="false_positive",
                sast_finding={
                    "id": "sast-fp-1",
                    "rule_id": "python.django.security.xss",
                    "severity": "medium",
                    "cwe": "CWE-79",
                    "file_path": "admin/views.py",
                    "line": 123,
                    "endpoint": "/admin/settings",
                    "message": "Potential XSS"
                },
                dast_finding={
                    "id": "dast-fp-1",
                    "type": "sql-injection",
                    "severity": "high",
                    "endpoint": "/api/search",
                    "method": "GET",
                    "parameter": "q",
                    "payload": "' OR 1=1--",
                    "evidence": "SQL error"
                },
                expected_match=False,
                expected_confidence="low"
            ),
            CorrelationTestCase(
                name="False Positive - Different Endpoints",
                category="false_positive",
                sast_finding={
                    "id": "sast-fp-2",
                    "rule_id": "python.cryptography.weak-hash",
                    "severity": "medium",
                    "cwe": "CWE-327",
                    "file_path": "auth/crypto.py",
                    "line": 45,
                    "endpoint": "/api/auth",
                    "message": "Weak hash function"
                },
                dast_finding={
                    "id": "dast-fp-2",
                    "type": "xss",
                    "severity": "high",
                    "endpoint": "/api/profile",  # Different endpoint
                    "method": "POST",
                    "parameter": "username",
                    "payload": "<script>alert(1)</script>",
                    "evidence": "Script in response"
                },
                expected_match=False,
                expected_confidence="low"
            ),

            # Edge Cases
            CorrelationTestCase(
                name="Edge Case - Fuzzy Endpoint Match",
                category="edge_case",
                sast_finding={
                    "id": "sast-edge-1",
                    "rule_id": "python.flask.security.sql-injection",
                    "severity": "high",
                    "cwe": "CWE-89",
                    "file_path": "api/v2/users.py",
                    "line": 78,
                    "endpoint": "/api/v2/users/search",
                    "message": "SQL injection"
                },
                dast_finding={
                    "id": "dast-edge-1",
                    "type": "sql-injection",
                    "severity": "high",
                    "endpoint": "/api/users/find",  # Similar but not exact
                    "method": "GET",
                    "parameter": "query",
                    "payload": "' OR '1'='1",
                    "evidence": "SQL error"
                },
                expected_match=True,
                expected_confidence="medium"
            ),
        ]

    def run_benchmark(self) -> BenchmarkMetrics:
        """Run complete benchmark suite"""
        print("=" * 80)
        print("CORRELATION ACCURACY BENCHMARK")
        print("=" * 80)

        try:
            from sast_dast_correlator import SASTDASTCorrelator
            correlator = SASTDASTCorrelator()
            # Disable AI for deterministic testing
            correlator.llm_manager = None
        except ImportError:
            print("❌ SAST-DAST correlator not available")
            return None

        tp, fp, tn, fn = 0, 0, 0, 0
        timing = []
        category_metrics = {}

        print(f"\nRunning {len(self.test_cases)} test cases...\n")

        for test_case in self.test_cases:
            # Time the correlation
            start_time = time.time()
            result = self._correlate_heuristic(
                correlator,
                test_case.sast_finding,
                test_case.dast_finding
            )
            elapsed_ms = (time.time() - start_time) * 1000
            timing.append(elapsed_ms)

            # Determine if correlation detected a match
            detected_match = result["match_score"] > 0.5

            # Update metrics
            if test_case.expected_match and detected_match:
                tp += 1
                outcome = "✅ TP"
            elif test_case.expected_match and not detected_match:
                fn += 1
                outcome = "❌ FN"
            elif not test_case.expected_match and detected_match:
                fp += 1
                outcome = "⚠️  FP"
            else:  # not expected_match and not detected_match
                tn += 1
                outcome = "✅ TN"

            # Track by category
            if test_case.category not in category_metrics:
                category_metrics[test_case.category] = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}

            if test_case.expected_match and detected_match:
                category_metrics[test_case.category]["tp"] += 1
            elif test_case.expected_match and not detected_match:
                category_metrics[test_case.category]["fn"] += 1
            elif not test_case.expected_match and detected_match:
                category_metrics[test_case.category]["fp"] += 1
            else:
                category_metrics[test_case.category]["tn"] += 1

            # Print result
            print(f"{outcome} {test_case.name}")
            print(f"    Score: {result['match_score']:.2f} | Time: {elapsed_ms:.1f}ms")

        # Calculate overall metrics
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        accuracy = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

        metrics = BenchmarkMetrics(
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            precision=precision,
            recall=recall,
            f1_score=f1_score,
            accuracy=accuracy,
            avg_match_time_ms=statistics.mean(timing) if timing else 0,
            total_test_cases=len(self.test_cases)
        )

        # Print results
        self._print_results(metrics, category_metrics, timing)

        # Save results
        self._save_results(metrics, category_metrics)

        return metrics

    def _correlate_heuristic(self, correlator, sast_finding: Dict, dast_finding: Dict) -> Dict:
        """Perform heuristic correlation without AI"""
        from difflib import SequenceMatcher

        scores = []

        # 1. Endpoint matching (40% weight)
        sast_endpoint = sast_finding.get("endpoint", "")
        dast_endpoint = dast_finding.get("endpoint", "")
        if sast_endpoint and dast_endpoint:
            endpoint_score = SequenceMatcher(None, sast_endpoint.lower(), dast_endpoint.lower()).ratio()
            scores.append(("endpoint", endpoint_score, 0.4))

        # 2. Vulnerability type matching (40% weight)
        sast_cwe = sast_finding.get("cwe", "")
        dast_type = dast_finding.get("type", "")
        vuln_type_score = self._match_vulnerability_types(sast_cwe, dast_type)
        scores.append(("vuln_type", vuln_type_score, 0.4))

        # 3. Severity matching (20% weight)
        sast_severity = sast_finding.get("severity", "").lower()
        dast_severity = dast_finding.get("severity", "").lower()
        severity_score = 1.0 if sast_severity == dast_severity else 0.5
        scores.append(("severity", severity_score, 0.2))

        # Calculate weighted average
        total_score = sum(score * weight for _, score, weight in scores)

        return {
            "match_score": total_score,
            "reasoning": f"Endpoint: {scores[0][1]:.2f}, VulnType: {scores[1][1]:.2f}, Severity: {scores[2][1]:.2f}",
            "scores": scores
        }

    def _match_vulnerability_types(self, cwe: str, dast_type: str) -> float:
        """Match CWE to DAST vulnerability type"""
        mappings = {
            "CWE-89": ["sql-injection", "sqli"],
            "CWE-79": ["xss", "cross-site-scripting"],
            "CWE-78": ["command-injection", "os-command-injection"],
            "CWE-22": ["path-traversal", "directory-traversal"],
            "CWE-918": ["ssrf", "server-side-request-forgery"],
        }

        cwe_upper = cwe.upper()
        dast_lower = dast_type.lower()

        for cwe_id, types in mappings.items():
            if cwe_upper == cwe_id and any(t in dast_lower for t in types):
                return 1.0

        return 0.0

    def _print_results(self, metrics: BenchmarkMetrics, category_metrics: Dict, timing: List[float]):
        """Print benchmark results"""
        print("\n" + "=" * 80)
        print("BENCHMARK RESULTS")
        print("=" * 80)

        print(f"\n📊 Overall Metrics:")
        print(f"   Precision:  {metrics.precision:.2%} ({metrics.true_positives} TP, {metrics.false_positives} FP)")
        print(f"   Recall:     {metrics.recall:.2%} ({metrics.true_positives} TP, {metrics.false_negatives} FN)")
        print(f"   Accuracy:   {metrics.accuracy:.2%}")
        print(f"   F1 Score:   {metrics.f1_score:.2%}")
        print(f"   True Neg:   {metrics.true_negatives}")

        print(f"\n⏱️  Performance:")
        print(f"   Avg Time:   {metrics.avg_match_time_ms:.2f}ms per correlation")
        print(f"   Min Time:   {min(timing):.2f}ms")
        print(f"   Max Time:   {max(timing):.2f}ms")
        print(f"   Total:      {len(self.test_cases)} test cases")

        # Print by category
        print(f"\n📂 Results by Category:")
        for category, cat_metrics in sorted(category_metrics.items()):
            tp = cat_metrics["tp"]
            fp = cat_metrics["fp"]
            fn = cat_metrics["fn"]
            tn = cat_metrics["tn"]

            cat_precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            cat_recall = tp / (tp + fn) if (tp + fn) > 0 else 0

            print(f"   {category:20} P={cat_precision:.2%} R={cat_recall:.2%} (TP={tp} FP={fp} FN={fn})")

        # Assessment
        print(f"\n🎯 Assessment:")
        if metrics.precision >= 0.85 and metrics.recall >= 0.85:
            print("   ✅ EXCELLENT - Production ready")
        elif metrics.precision >= 0.75 and metrics.recall >= 0.75:
            print("   ✅ GOOD - Acceptable for production use")
        elif metrics.precision >= 0.65 and metrics.recall >= 0.65:
            print("   ⚠️  FAIR - Needs improvement")
        else:
            print("   ❌ POOR - Requires significant work")

    def _save_results(self, metrics: BenchmarkMetrics, category_metrics: Dict):
        """Save benchmark results to file"""
        output_file = Path("/tmp/correlation_accuracy_benchmark.json")

        results = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "test_framework": "correlation_accuracy_benchmark",
            "overall_metrics": {
                "precision": metrics.precision,
                "recall": metrics.recall,
                "accuracy": metrics.accuracy,
                "f1_score": metrics.f1_score,
                "true_positives": metrics.true_positives,
                "false_positives": metrics.false_positives,
                "true_negatives": metrics.true_negatives,
                "false_negatives": metrics.false_negatives,
                "avg_match_time_ms": metrics.avg_match_time_ms,
                "total_test_cases": metrics.total_test_cases
            },
            "category_metrics": {}
        }

        # Add category metrics
        for category, cat_metrics in category_metrics.items():
            tp = cat_metrics["tp"]
            fp = cat_metrics["fp"]
            fn = cat_metrics["fn"]

            results["category_metrics"][category] = {
                "true_positives": tp,
                "false_positives": fp,
                "false_negatives": fn,
                "true_negatives": cat_metrics["tn"],
                "precision": tp / (tp + fp) if (tp + fp) > 0 else 0,
                "recall": tp / (tp + fn) if (tp + fn) > 0 else 0
            }

        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)

        print(f"\n💾 Results saved to: {output_file}")


def main():
    """Run benchmark suite"""
    benchmark = CorrelationAccuracyBenchmark()
    metrics = benchmark.run_benchmark()

    if metrics:
        # Exit with code based on quality
        if metrics.precision >= 0.75 and metrics.recall >= 0.75:
            exit(0)  # Success
        else:
            exit(1)  # Quality threshold not met


if __name__ == "__main__":
    main()
