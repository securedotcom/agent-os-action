#!/usr/bin/env python3
"""
Progress Tracker Integration Example
Demonstrates how to integrate ProgressTracker with existing Agent OS scanners
"""

from pathlib import Path
from typing import Dict, List, Any
from scripts.progress_tracker import ProgressTracker


# Example 1: Integrating with Semgrep Scanner
def example_semgrep_integration():
    """Show how to integrate ProgressTracker with SemgrepScanner"""
    print("\n" + "="*70)
    print("Example 1: Semgrep Scanner Integration")
    print("="*70 + "\n")

    from scripts.semgrep_scanner import SemgrepScanner

    # Create tracker
    tracker = ProgressTracker()
    tracker.print_header("Semgrep SAST Scan", "Static analysis with 2,000+ security rules")
    tracker.start()

    try:
        # Initialize scanner
        config = {
            "semgrep_rules": "auto",
            "exclude_patterns": [
                "*/test/*", "*/tests/*", "*/.git/*",
                "*/node_modules/*", "*/.venv/*", "*/venv/*"
            ],
        }

        # Count files to scan (approximation)
        repo_path = Path(".")
        files = [
            f for f in repo_path.rglob("*.py")
            if not any(pattern.replace("*", "") in str(f) for pattern in config["exclude_patterns"])
        ]

        # Start tracking
        scan_id = tracker.start_scan("Semgrep", total_files=len(files))

        # Run scanner
        scanner = SemgrepScanner(config)

        # In a real integration, you'd modify SemgrepScanner to call update_progress
        # For now, we'll simulate it
        for i, file in enumerate(files[:10]):  # Limit for demo
            # scanner._scan_file(file)  # Your actual scan logic
            tracker.update_progress(
                scan_id,
                completed=i+1,
                message=f"Scanning {file.name}"
            )

        # Complete scan
        tracker.complete_scan(scan_id, message="Scan complete")

    except Exception as e:
        tracker.log_error(f"Scan failed: {e}")
    finally:
        tracker.stop()


# Example 2: Integrating with Orchestrator
def example_orchestrator_integration():
    """Show how to integrate ProgressTracker with AuditOrchestrator"""
    print("\n" + "="*70)
    print("Example 2: Orchestrator Integration")
    print("="*70 + "\n")

    # Create tracker
    tracker = ProgressTracker()
    tracker.print_header(
        "AI Security Audit",
        "Comprehensive security analysis with multiple scanners"
    )
    tracker.start()

    try:
        # Phase 1: Initialization
        with tracker.operation("Provider Initialization", "Detecting AI provider"):
            # orchestrator.initialize_provider()
            import time
            time.sleep(0.5)
            tracker.log_success("Provider: Anthropic (Claude)")

        # Phase 2: File Selection
        with tracker.operation("File Selection", "Analyzing codebase structure"):
            # orchestrator.select_files()
            time.sleep(0.5)
            tracker.log_info("Selected 50 files for analysis")

        # Phase 3: Cost Estimation
        with tracker.operation("Cost Estimation"):
            # orchestrator.estimate_costs()
            time.sleep(0.3)
            tracker.log_info("Estimated cost: $0.45")

        # Phase 4: Threat Modeling
        with tracker.operation("Threat Modeling", "Generating threat model"):
            # orchestrator.load_threat_model()
            time.sleep(0.5)

        # Phase 5: Heuristic Scan
        with tracker.operation("Heuristic Pre-scan"):
            # orchestrator.run_heuristic_scan()
            time.sleep(0.5)
            tracker.log_info("Flagged 5 files with potential issues")

        # Phase 6: Security Scanners
        scanners = [
            ("Semgrep", 50),
            ("Trivy", 30),
            ("TruffleHog", 25),
            ("Checkov", 20),
        ]

        for scanner_name, file_count in scanners:
            scan_id = tracker.start_scan(scanner_name, total_files=file_count)
            for i in range(file_count):
                # Actual scanning logic would go here
                time.sleep(0.02)  # Simulate work
                tracker.update_progress(scan_id, advance=1)
            tracker.complete_scan(scan_id)

        # Phase 7: LLM Analysis
        with tracker.operation("LLM Analysis", "Analyzing findings with AI"):
            # orchestrator.execute_llm_analysis()
            time.sleep(1)
            tracker.log_info("Analyzed 15 findings")

        # Phase 8: Report Generation
        with tracker.operation("Report Generation", "Generating SARIF and JSON"):
            # orchestrator.generate_reports()
            time.sleep(0.8)
            tracker.log_success("Reports generated successfully")

    except Exception as e:
        tracker.log_error(f"Audit failed: {e}")
    finally:
        tracker.stop()
        stats = tracker.get_stats()
        print(f"\n📊 Final Statistics:")
        print(f"   Files scanned: {stats['files_scanned']}")
        print(f"   Scanners completed: {stats['scanners_completed']}")
        print(f"   LLM calls: {stats['llm_calls']}")
        print(f"   Duration: {stats['duration_seconds']:.1f}s")


# Example 3: Error Handling
def example_error_handling():
    """Show how to handle errors with ProgressTracker"""
    print("\n" + "="*70)
    print("Example 3: Error Handling")
    print("="*70 + "\n")

    tracker = ProgressTracker()
    tracker.start()

    # Successful scan
    scan_id = tracker.start_scan("Semgrep", total_files=20)
    for i in range(20):
        tracker.update_progress(scan_id, advance=1)
    tracker.complete_scan(scan_id, message="Found 3 issues")

    # Failed scan
    scan_id = tracker.start_scan("Trivy", total_files=20)
    try:
        for i in range(10):
            tracker.update_progress(scan_id, advance=1)
        # Simulate an error
        raise ConnectionError("Connection timeout")
    except Exception as e:
        tracker.complete_scan(scan_id, message=str(e), error=True)

    # Operation with error handling
    try:
        with tracker.operation("LLM Analysis"):
            raise ValueError("API key not configured")
    except Exception:
        pass  # Error already logged by context manager

    tracker.stop()


# Example 4: Custom Scanner Integration Template
class CustomScanner:
    """Template for integrating custom scanners with ProgressTracker"""

    def __init__(self, tracker: ProgressTracker = None):
        self.tracker = tracker or ProgressTracker()

    def scan(self, target_path: Path) -> Dict[str, Any]:
        """Run custom scan with progress tracking"""
        # Discover files
        files = list(target_path.rglob("*.py"))

        # Start tracking
        scan_id = self.tracker.start_scan("CustomScanner", total_files=len(files))

        results = []
        try:
            for i, file in enumerate(files):
                # Your scanning logic here
                result = self._scan_file(file)
                results.append(result)

                # Update progress
                self.tracker.update_progress(
                    scan_id,
                    completed=i+1,
                    message=f"Scanning {file.name}"
                )

            # Mark as complete
            self.tracker.complete_scan(
                scan_id,
                message=f"Found {len(results)} issues"
            )

        except Exception as e:
            # Handle errors
            self.tracker.complete_scan(scan_id, message=str(e), error=True)
            raise

        return {"findings": results}

    def _scan_file(self, file: Path) -> Dict[str, Any]:
        """Scan a single file (implement your logic here)"""
        import time
        time.sleep(0.01)  # Simulate work
        return {"file": str(file), "issues": []}


def example_custom_scanner():
    """Show how to create a custom scanner with ProgressTracker"""
    print("\n" + "="*70)
    print("Example 4: Custom Scanner Integration")
    print("="*70 + "\n")

    tracker = ProgressTracker()
    tracker.start()

    scanner = CustomScanner(tracker=tracker)
    results = scanner.scan(Path("."))

    tracker.log_success(f"Custom scan complete: {len(results['findings'])} findings")
    tracker.stop()


# Example 5: CI Environment Behavior
def example_ci_behavior():
    """Show how ProgressTracker behaves in CI environments"""
    print("\n" + "="*70)
    print("Example 5: CI Environment (Simple Logging)")
    print("="*70 + "\n")

    # Force disable rich output (simulates CI)
    tracker = ProgressTracker(enable_rich=False)
    tracker.start()

    scan_id = tracker.start_scan("Semgrep", total_files=20)
    for i in range(20):
        if i % 5 == 0:  # Log every 5 files
            tracker.update_progress(scan_id, completed=i+1)
    tracker.complete_scan(scan_id)

    with tracker.operation("LLM Analysis"):
        import time
        time.sleep(0.5)

    tracker.stop()


# Main execution
if __name__ == "__main__":
    print("\n" + "="*70)
    print(" Progress Tracker Integration Examples")
    print("="*70)

    # Run examples
    examples = [
        # example_semgrep_integration,  # Commented out as it requires files
        example_orchestrator_integration,
        example_error_handling,
        example_custom_scanner,
        example_ci_behavior,
    ]

    for example in examples:
        try:
            example()
        except KeyboardInterrupt:
            print("\n\nInterrupted by user")
            break
        except Exception as e:
            print(f"\nExample failed: {e}")
            import traceback
            traceback.print_exc()

    print("\n" + "="*70)
    print(" Integration Examples Complete")
    print("="*70 + "\n")

    print("Next steps:")
    print("1. Install rich: pip install rich>=13.0.0")
    print("2. Import ProgressTracker in your scanner modules")
    print("3. Pass tracker instance to scanner constructors")
    print("4. Call tracker methods at appropriate integration points")
    print("5. Test in both terminal and CI environments")
    print("\nSee PROGRESS_TRACKER_USAGE.md for detailed documentation")
