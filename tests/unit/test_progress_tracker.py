#!/usr/bin/env python3
"""
Unit tests for Progress Tracker
"""

import os
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, call
from datetime import datetime

import pytest

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from progress_tracker import ProgressTracker, create_progress_tracker


class TestProgressTrackerInitialization:
    """Test ProgressTracker initialization and environment detection"""

    def test_initialization_with_rich_enabled(self):
        """Test initialization with rich explicitly enabled"""
        tracker = ProgressTracker(enable_rich=True)
        assert tracker.use_rich is True
        assert tracker.console is not None
        assert tracker.live is None
        assert tracker.progress is None
        assert tracker.tasks == {}
        assert tracker.operation_spinners == {}
        assert tracker.stats["files_scanned"] == 0
        assert tracker.stats["scanners_completed"] == 0
        assert tracker.stats["llm_calls"] == 0
        assert tracker.stats["errors"] == 0

    def test_initialization_with_rich_disabled(self):
        """Test initialization with rich explicitly disabled"""
        tracker = ProgressTracker(enable_rich=False)
        assert tracker.use_rich is False
        assert tracker.console is None
        assert tracker.live is None
        assert tracker.progress is None

    @patch("sys.stdout.isatty")
    def test_auto_detect_tty_enabled(self, mock_isatty):
        """Test auto-detection when TTY is available and not in CI"""
        mock_isatty.return_value = True

        with patch.dict(os.environ, {}, clear=True):
            tracker = ProgressTracker()
            assert tracker.use_rich is True

    @patch("sys.stdout.isatty")
    def test_auto_detect_tty_disabled(self, mock_isatty):
        """Test auto-detection when TTY is not available"""
        mock_isatty.return_value = False

        with patch.dict(os.environ, {}, clear=True):
            tracker = ProgressTracker()
            assert tracker.use_rich is False

    @patch("sys.stdout.isatty")
    def test_auto_detect_github_actions(self, mock_isatty):
        """Test auto-detection in GitHub Actions environment"""
        mock_isatty.return_value = True

        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}):
            tracker = ProgressTracker()
            assert tracker.use_rich is False

    @patch("sys.stdout.isatty")
    def test_auto_detect_gitlab_ci(self, mock_isatty):
        """Test auto-detection in GitLab CI environment"""
        mock_isatty.return_value = True

        with patch.dict(os.environ, {"GITLAB_CI": "true"}):
            tracker = ProgressTracker()
            assert tracker.use_rich is False

    @patch("sys.stdout.isatty")
    def test_auto_detect_jenkins(self, mock_isatty):
        """Test auto-detection in Jenkins environment"""
        mock_isatty.return_value = True

        with patch.dict(os.environ, {"JENKINS_URL": "https://jenkins.example.com"}):
            tracker = ProgressTracker()
            assert tracker.use_rich is False

    @patch("sys.stdout.isatty")
    def test_auto_detect_circleci(self, mock_isatty):
        """Test auto-detection in CircleCI environment"""
        mock_isatty.return_value = True

        with patch.dict(os.environ, {"CIRCLECI": "true"}):
            tracker = ProgressTracker()
            assert tracker.use_rich is False

    @patch("sys.stdout.isatty")
    def test_auto_detect_generic_ci(self, mock_isatty):
        """Test auto-detection with generic CI environment variable"""
        mock_isatty.return_value = True

        with patch.dict(os.environ, {"CI": "true"}):
            tracker = ProgressTracker()
            assert tracker.use_rich is False

    def test_scanner_colors_defined(self):
        """Test that scanner colors are properly defined"""
        tracker = ProgressTracker(enable_rich=False)

        assert "semgrep" in tracker.scanner_colors
        assert "trivy" in tracker.scanner_colors
        assert "trufflehog" in tracker.scanner_colors
        assert "checkov" in tracker.scanner_colors
        assert "gitleaks" in tracker.scanner_colors
        assert "llm" in tracker.scanner_colors
        assert "report" in tracker.scanner_colors

        assert tracker.scanner_colors["semgrep"] == "cyan"
        assert tracker.scanner_colors["trivy"] == "blue"
        assert tracker.scanner_colors["trufflehog"] == "magenta"


class TestProgressTrackerStartStop:
    """Test start() and stop() methods"""

    def test_start_with_rich_disabled(self):
        """Test start with rich disabled"""
        tracker = ProgressTracker(enable_rich=False)
        tracker.start()

        assert tracker.progress is None
        assert tracker.live is None

    @patch("progress_tracker.Live")
    @patch("progress_tracker.Progress")
    def test_start_with_rich_enabled(self, mock_progress_class, mock_live_class):
        """Test start with rich enabled"""
        mock_progress = MagicMock()
        mock_live = MagicMock()
        mock_progress_class.return_value = mock_progress
        mock_live_class.return_value = mock_live

        tracker = ProgressTracker(enable_rich=True)
        tracker.start()

        assert tracker.progress is not None
        assert tracker.live is not None
        mock_live.start.assert_called_once()

    def test_stop_with_rich_disabled(self):
        """Test stop with rich disabled"""
        tracker = ProgressTracker(enable_rich=False)
        tracker.start()
        tracker.stop()

        # Should not raise any errors

    @patch("progress_tracker.Live")
    @patch("progress_tracker.Progress")
    def test_stop_with_rich_enabled(self, mock_progress_class, mock_live_class):
        """Test stop with rich enabled"""
        mock_progress = MagicMock()
        mock_live = MagicMock()
        mock_progress_class.return_value = mock_progress
        mock_live_class.return_value = mock_live

        tracker = ProgressTracker(enable_rich=True)
        tracker.start()
        tracker.stop()

        mock_live.stop.assert_called_once()
        assert tracker.live is None


class TestProgressTrackerScanOperations:
    """Test scanner progress tracking operations"""

    def test_start_scan_with_rich_disabled(self):
        """Test start_scan with rich disabled"""
        tracker = ProgressTracker(enable_rich=False)

        task_id = tracker.start_scan("Semgrep", total_files=100)

        assert task_id == "semgrep"
        assert task_id in tracker.tasks
        assert tracker.tasks[task_id] == "semgrep"

    @patch("progress_tracker.Live")
    @patch("progress_tracker.Progress")
    def test_start_scan_with_rich_enabled(self, mock_progress_class, mock_live_class):
        """Test start_scan with rich enabled"""
        mock_progress = MagicMock()
        mock_live = MagicMock()
        mock_progress_class.return_value = mock_progress
        mock_live_class.return_value = mock_live

        # Mock add_task to return a task ID
        mock_task_id = MagicMock()
        mock_progress.add_task.return_value = mock_task_id

        tracker = ProgressTracker(enable_rich=True)
        tracker.start()

        task_id = tracker.start_scan("Semgrep", total_files=100)

        assert task_id == "semgrep"
        assert task_id in tracker.tasks
        assert tracker.tasks[task_id] == mock_task_id
        mock_progress.add_task.assert_called_once()

    @patch("progress_tracker.Live")
    @patch("progress_tracker.Progress")
    def test_start_scan_custom_description(self, mock_progress_class, mock_live_class):
        """Test start_scan with custom description"""
        mock_progress = MagicMock()
        mock_live = MagicMock()
        mock_progress_class.return_value = mock_progress
        mock_live_class.return_value = mock_live

        mock_task_id = MagicMock()
        mock_progress.add_task.return_value = mock_task_id

        tracker = ProgressTracker(enable_rich=True)
        tracker.start()

        custom_desc = "[red]Custom Scanner[/red]"
        task_id = tracker.start_scan("CustomScanner", total_files=50, description=custom_desc)

        assert task_id == "customscanner"
        mock_progress.add_task.assert_called_once_with(custom_desc, total=50)

    def test_update_progress_with_rich_disabled(self):
        """Test update_progress with rich disabled"""
        tracker = ProgressTracker(enable_rich=False)
        task_id = tracker.start_scan("Semgrep", total_files=100)

        tracker.update_progress(task_id, completed=50)
        tracker.update_progress(task_id, advance=1, message="Scanning file 51")

        # Should not raise errors

    @patch("progress_tracker.Live")
    @patch("progress_tracker.Progress")
    def test_update_progress_with_completed(self, mock_progress_class, mock_live_class):
        """Test update_progress with completed parameter"""
        mock_progress = MagicMock()
        mock_live = MagicMock()
        mock_progress_class.return_value = mock_progress
        mock_live_class.return_value = mock_live

        mock_task_id = MagicMock()
        mock_progress.add_task.return_value = mock_task_id

        tracker = ProgressTracker(enable_rich=True)
        tracker.start()
        task_id = tracker.start_scan("Semgrep", total_files=100)

        tracker.update_progress(task_id, completed=50)

        mock_progress.update.assert_called_with(mock_task_id, completed=50)
        assert tracker.stats["files_scanned"] == 50

    @patch("progress_tracker.Live")
    @patch("progress_tracker.Progress")
    def test_update_progress_with_advance(self, mock_progress_class, mock_live_class):
        """Test update_progress with advance parameter"""
        mock_progress = MagicMock()
        mock_live = MagicMock()
        mock_progress_class.return_value = mock_progress
        mock_live_class.return_value = mock_live

        mock_task_id = MagicMock()
        mock_progress.add_task.return_value = mock_task_id

        tracker = ProgressTracker(enable_rich=True)
        tracker.start()
        task_id = tracker.start_scan("Semgrep", total_files=100)

        tracker.update_progress(task_id, advance=5)

        mock_progress.advance.assert_called_with(mock_task_id, 5)
        assert tracker.stats["files_scanned"] == 5

    @patch("progress_tracker.Live")
    @patch("progress_tracker.Progress")
    def test_update_progress_with_message(self, mock_progress_class, mock_live_class):
        """Test update_progress with status message"""
        mock_progress = MagicMock()
        mock_live = MagicMock()
        mock_progress_class.return_value = mock_progress
        mock_live_class.return_value = mock_live

        mock_task_id = MagicMock()
        mock_progress.add_task.return_value = mock_task_id

        # Mock the tasks dict access
        mock_task_obj = MagicMock()
        mock_task_obj.description = "[cyan]Semgrep[/cyan]"
        mock_progress.tasks = {mock_task_id: mock_task_obj}

        tracker = ProgressTracker(enable_rich=True)
        tracker.start()
        task_id = tracker.start_scan("Semgrep", total_files=100)

        tracker.update_progress(task_id, completed=10, message="Scanning file 10/100")

        # Should have called update with the message in description
        assert mock_progress.update.call_count >= 1

    def test_update_progress_unknown_task(self):
        """Test update_progress with unknown task ID"""
        tracker = ProgressTracker(enable_rich=True)
        tracker.start()

        # Should not raise error, just log warning
        tracker.update_progress("unknown_task", completed=10)

    def test_complete_scan_with_rich_disabled(self):
        """Test complete_scan with rich disabled"""
        tracker = ProgressTracker(enable_rich=False)
        task_id = tracker.start_scan("Semgrep", total_files=100)

        tracker.complete_scan(task_id)

        assert tracker.stats["scanners_completed"] == 1
        assert tracker.stats["errors"] == 0

    def test_complete_scan_with_error_rich_disabled(self):
        """Test complete_scan with error and rich disabled"""
        tracker = ProgressTracker(enable_rich=False)
        task_id = tracker.start_scan("Semgrep", total_files=100)

        tracker.complete_scan(task_id, message="Connection failed", error=True)

        assert tracker.stats["scanners_completed"] == 0
        assert tracker.stats["errors"] == 1

    @patch("progress_tracker.Live")
    @patch("progress_tracker.Progress")
    def test_complete_scan_success(self, mock_progress_class, mock_live_class):
        """Test complete_scan with success"""
        mock_progress = MagicMock()
        mock_live = MagicMock()
        mock_progress_class.return_value = mock_progress
        mock_live_class.return_value = mock_live

        mock_task_id = MagicMock()
        mock_progress.add_task.return_value = mock_task_id

        # Mock the tasks dict access
        mock_task_obj = MagicMock()
        mock_task_obj.description = "[cyan]Semgrep[/cyan]"
        mock_task_obj.total = 100
        mock_progress.tasks = {mock_task_id: mock_task_obj}

        tracker = ProgressTracker(enable_rich=True)
        tracker.start()
        task_id = tracker.start_scan("Semgrep", total_files=100)

        tracker.complete_scan(task_id, message="All files scanned")

        assert tracker.stats["scanners_completed"] == 1
        assert tracker.stats["errors"] == 0

    @patch("progress_tracker.Live")
    @patch("progress_tracker.Progress")
    def test_complete_scan_error(self, mock_progress_class, mock_live_class):
        """Test complete_scan with error"""
        mock_progress = MagicMock()
        mock_live = MagicMock()
        mock_progress_class.return_value = mock_progress
        mock_live_class.return_value = mock_live

        mock_task_id = MagicMock()
        mock_progress.add_task.return_value = mock_task_id

        # Mock the tasks dict access
        mock_task_obj = MagicMock()
        mock_task_obj.description = "[cyan]Semgrep[/cyan]"
        mock_task_obj.total = 100
        mock_progress.tasks = {mock_task_id: mock_task_obj}

        tracker = ProgressTracker(enable_rich=True)
        tracker.start()
        task_id = tracker.start_scan("Semgrep", total_files=100)

        tracker.complete_scan(task_id, message="Timeout error", error=True)

        assert tracker.stats["scanners_completed"] == 0
        assert tracker.stats["errors"] == 1


class TestProgressTrackerOperations:
    """Test operation tracking (spinners)"""

    def test_start_operation_with_rich_disabled(self):
        """Test start_operation with rich disabled"""
        tracker = ProgressTracker(enable_rich=False)

        op_id = tracker.start_operation("LLM Analysis")

        assert op_id == "llm_analysis"
        assert op_id in tracker.operation_spinners
        assert tracker.stats["llm_calls"] == 1

    @patch("progress_tracker.Live")
    @patch("progress_tracker.Progress")
    def test_start_operation_with_rich_enabled(self, mock_progress_class, mock_live_class):
        """Test start_operation with rich enabled"""
        mock_progress = MagicMock()
        mock_live = MagicMock()
        mock_progress_class.return_value = mock_progress
        mock_live_class.return_value = mock_live

        mock_task_id = MagicMock()
        mock_progress.add_task.return_value = mock_task_id

        tracker = ProgressTracker(enable_rich=True)
        tracker.start()

        op_id = tracker.start_operation("Report Generation")

        assert op_id == "report_generation"
        assert op_id in tracker.operation_spinners
        mock_progress.add_task.assert_called()

    def test_start_operation_llm_counter(self):
        """Test that LLM operations increment llm_calls counter"""
        tracker = ProgressTracker(enable_rich=False)

        tracker.start_operation("LLM Analysis")
        tracker.start_operation("LLM Triage")
        tracker.start_operation("Report Generation")  # Not LLM

        assert tracker.stats["llm_calls"] == 2

    def test_complete_operation_with_rich_disabled(self):
        """Test complete_operation with rich disabled"""
        tracker = ProgressTracker(enable_rich=False)
        op_id = tracker.start_operation("Report Generation")

        tracker.complete_operation(op_id)

        assert tracker.stats["errors"] == 0

    def test_complete_operation_with_error_rich_disabled(self):
        """Test complete_operation with error and rich disabled"""
        tracker = ProgressTracker(enable_rich=False)
        op_id = tracker.start_operation("LLM Analysis")

        tracker.complete_operation(op_id, message="API timeout", error=True)

        assert tracker.stats["errors"] == 1

    @patch("progress_tracker.Live")
    @patch("progress_tracker.Progress")
    def test_complete_operation_success(self, mock_progress_class, mock_live_class):
        """Test complete_operation with success"""
        mock_progress = MagicMock()
        mock_live = MagicMock()
        mock_progress_class.return_value = mock_progress
        mock_live_class.return_value = mock_live

        mock_task_id = MagicMock()
        mock_progress.add_task.return_value = mock_task_id

        # Mock the tasks dict access
        mock_task_obj = MagicMock()
        mock_task_obj.description = "[bright_cyan]Report[/bright_cyan]"
        mock_progress.tasks = {mock_task_id: mock_task_obj}

        tracker = ProgressTracker(enable_rich=True)
        tracker.start()
        op_id = tracker.start_operation("Report Generation")

        tracker.complete_operation(op_id, message="Report generated")

        mock_progress.remove_task.assert_called_once_with(mock_task_id)
        assert op_id not in tracker.operation_spinners
        assert tracker.stats["errors"] == 0

    @patch("progress_tracker.Live")
    @patch("progress_tracker.Progress")
    def test_complete_operation_error(self, mock_progress_class, mock_live_class):
        """Test complete_operation with error"""
        mock_progress = MagicMock()
        mock_live = MagicMock()
        mock_progress_class.return_value = mock_progress
        mock_live_class.return_value = mock_live

        mock_task_id = MagicMock()
        mock_progress.add_task.return_value = mock_task_id

        # Mock the tasks dict access
        mock_task_obj = MagicMock()
        mock_task_obj.description = "[bright_magenta]LLM[/bright_magenta]"
        mock_progress.tasks = {mock_task_id: mock_task_obj}

        tracker = ProgressTracker(enable_rich=True)
        tracker.start()
        op_id = tracker.start_operation("LLM Analysis")

        tracker.complete_operation(op_id, message="API error", error=True)

        assert tracker.stats["errors"] == 1
        assert op_id not in tracker.operation_spinners

    def test_operation_context_manager_success(self):
        """Test operation context manager with success"""
        tracker = ProgressTracker(enable_rich=False)

        with tracker.operation("Test Operation"):
            pass

        # Should complete without errors

    def test_operation_context_manager_error(self):
        """Test operation context manager with error"""
        tracker = ProgressTracker(enable_rich=False)

        with pytest.raises(ValueError):
            with tracker.operation("Test Operation"):
                raise ValueError("Test error")

        assert tracker.stats["errors"] == 1

    @patch("progress_tracker.Live")
    @patch("progress_tracker.Progress")
    def test_operation_context_manager_with_rich(self, mock_progress_class, mock_live_class):
        """Test operation context manager with rich enabled"""
        mock_progress = MagicMock()
        mock_live = MagicMock()
        mock_progress_class.return_value = mock_progress
        mock_live_class.return_value = mock_live

        mock_task_id = MagicMock()
        mock_progress.add_task.return_value = mock_task_id

        # Mock the tasks dict access
        mock_task_obj = MagicMock()
        mock_task_obj.description = "[white]Test Operation[/white]"
        mock_progress.tasks = {mock_task_id: mock_task_obj}

        tracker = ProgressTracker(enable_rich=True)
        tracker.start()

        with tracker.operation("Test Operation"):
            pass

        mock_progress.remove_task.assert_called_once()


class TestProgressTrackerLogging:
    """Test logging methods"""

    def test_log_info_with_rich_disabled(self):
        """Test log_info with rich disabled"""
        tracker = ProgressTracker(enable_rich=False)

        # Should not raise errors
        tracker.log_info("Test info message")

    @patch("progress_tracker.Console")
    def test_log_info_with_rich_enabled(self, mock_console_class):
        """Test log_info with rich enabled"""
        mock_console = MagicMock()
        mock_console_class.return_value = mock_console

        tracker = ProgressTracker(enable_rich=True)
        tracker.log_info("Test info message")

        mock_console.print.assert_called_once()
        call_args = mock_console.print.call_args[0][0]
        assert "ℹ" in call_args or "Test info message" in call_args

    def test_log_success_with_rich_disabled(self):
        """Test log_success with rich disabled"""
        tracker = ProgressTracker(enable_rich=False)
        tracker.log_success("Test success message")

    @patch("progress_tracker.Console")
    def test_log_success_with_rich_enabled(self, mock_console_class):
        """Test log_success with rich enabled"""
        mock_console = MagicMock()
        mock_console_class.return_value = mock_console

        tracker = ProgressTracker(enable_rich=True)
        tracker.log_success("Test success message")

        mock_console.print.assert_called_once()
        call_args = mock_console.print.call_args[0][0]
        assert "✓" in call_args or "Test success message" in call_args

    def test_log_warning_with_rich_disabled(self):
        """Test log_warning with rich disabled"""
        tracker = ProgressTracker(enable_rich=False)
        tracker.log_warning("Test warning message")

    @patch("progress_tracker.Console")
    def test_log_warning_with_rich_enabled(self, mock_console_class):
        """Test log_warning with rich enabled"""
        mock_console = MagicMock()
        mock_console_class.return_value = mock_console

        tracker = ProgressTracker(enable_rich=True)
        tracker.log_warning("Test warning message")

        mock_console.print.assert_called_once()
        call_args = mock_console.print.call_args[0][0]
        assert "⚠" in call_args or "Test warning message" in call_args

    def test_log_error_with_rich_disabled(self):
        """Test log_error with rich disabled"""
        tracker = ProgressTracker(enable_rich=False)
        tracker.log_error("Test error message")

    @patch("progress_tracker.Console")
    def test_log_error_with_rich_enabled(self, mock_console_class):
        """Test log_error with rich enabled"""
        mock_console = MagicMock()
        mock_console_class.return_value = mock_console

        tracker = ProgressTracker(enable_rich=True)
        tracker.log_error("Test error message")

        mock_console.print.assert_called_once()
        call_args = mock_console.print.call_args[0][0]
        assert "✗" in call_args or "Test error message" in call_args

    def test_print_header_with_rich_disabled(self):
        """Test print_header with rich disabled"""
        tracker = ProgressTracker(enable_rich=False)
        tracker.print_header("Test Title", "Test subtitle")

    @patch("progress_tracker.Console")
    def test_print_header_with_rich_enabled(self, mock_console_class):
        """Test print_header with rich enabled"""
        mock_console = MagicMock()
        mock_console_class.return_value = mock_console

        tracker = ProgressTracker(enable_rich=True)
        tracker.print_header("Test Title", "Test subtitle")

        mock_console.print.assert_called_once()

    @patch("progress_tracker.Console")
    def test_print_header_without_subtitle(self, mock_console_class):
        """Test print_header without subtitle"""
        mock_console = MagicMock()
        mock_console_class.return_value = mock_console

        tracker = ProgressTracker(enable_rich=True)
        tracker.print_header("Test Title")

        mock_console.print.assert_called_once()


class TestProgressTrackerStats:
    """Test statistics tracking"""

    def test_get_stats_initial(self):
        """Test get_stats with initial values"""
        tracker = ProgressTracker(enable_rich=False)

        stats = tracker.get_stats()

        assert stats["files_scanned"] == 0
        assert stats["scanners_completed"] == 0
        assert stats["llm_calls"] == 0
        assert stats["errors"] == 0
        assert "duration_seconds" in stats
        assert stats["duration_seconds"] >= 0

    def test_get_stats_after_operations(self):
        """Test get_stats after various operations"""
        tracker = ProgressTracker(enable_rich=False)

        # Simulate some operations
        task_id = tracker.start_scan("Semgrep", total_files=100)
        tracker.update_progress(task_id, completed=50)
        tracker.complete_scan(task_id)

        tracker.start_operation("LLM Analysis")

        stats = tracker.get_stats()

        assert stats["files_scanned"] == 50
        assert stats["scanners_completed"] == 1
        assert stats["llm_calls"] == 1
        assert stats["errors"] == 0

    def test_stats_files_scanned_increment(self):
        """Test files_scanned increments correctly"""
        tracker = ProgressTracker(enable_rich=False)

        task_id = tracker.start_scan("Semgrep", total_files=100)
        tracker.update_progress(task_id, advance=1)
        tracker.update_progress(task_id, advance=1)
        tracker.update_progress(task_id, advance=3)

        assert tracker.stats["files_scanned"] == 5

    def test_stats_scanners_completed_increment(self):
        """Test scanners_completed increments correctly"""
        tracker = ProgressTracker(enable_rich=False)

        task1 = tracker.start_scan("Semgrep", total_files=100)
        tracker.complete_scan(task1)

        task2 = tracker.start_scan("Trivy", total_files=50)
        tracker.complete_scan(task2)

        assert tracker.stats["scanners_completed"] == 2

    def test_stats_errors_increment(self):
        """Test errors increment correctly"""
        tracker = ProgressTracker(enable_rich=False)

        task1 = tracker.start_scan("Semgrep", total_files=100)
        tracker.complete_scan(task1, error=True)

        op_id = tracker.start_operation("LLM Analysis")
        tracker.complete_operation(op_id, error=True)

        assert tracker.stats["errors"] == 2


class TestProgressTrackerFactoryFunction:
    """Test factory function"""

    def test_create_progress_tracker_default(self):
        """Test create_progress_tracker with default settings"""
        tracker = create_progress_tracker()

        assert isinstance(tracker, ProgressTracker)

    def test_create_progress_tracker_rich_enabled(self):
        """Test create_progress_tracker with rich enabled"""
        tracker = create_progress_tracker(enable_rich=True)

        assert tracker.use_rich is True

    def test_create_progress_tracker_rich_disabled(self):
        """Test create_progress_tracker with rich disabled"""
        tracker = create_progress_tracker(enable_rich=False)

        assert tracker.use_rich is False


class TestProgressTrackerEdgeCases:
    """Test edge cases and error conditions"""

    def test_start_scan_before_start(self):
        """Test starting a scan before calling start()"""
        tracker = ProgressTracker(enable_rich=True)

        # Should auto-start if not already started
        task_id = tracker.start_scan("Semgrep", total_files=100)

        assert tracker.progress is not None
        assert task_id in tracker.tasks

    def test_start_operation_before_start(self):
        """Test starting an operation before calling start()"""
        tracker = ProgressTracker(enable_rich=True)

        # Should auto-start if not already started
        op_id = tracker.start_operation("LLM Analysis")

        assert tracker.progress is not None
        assert op_id in tracker.operation_spinners

    def test_update_progress_nonexistent_task(self):
        """Test updating progress for nonexistent task"""
        tracker = ProgressTracker(enable_rich=True)
        tracker.start()

        # Should not raise error
        tracker.update_progress("nonexistent_task", completed=10)

    def test_complete_scan_nonexistent_task(self):
        """Test completing nonexistent scan task"""
        tracker = ProgressTracker(enable_rich=True)
        tracker.start()

        # Should not raise error
        tracker.complete_scan("nonexistent_task")

    def test_complete_operation_nonexistent_operation(self):
        """Test completing nonexistent operation"""
        tracker = ProgressTracker(enable_rich=True)
        tracker.start()

        # Should not raise error
        tracker.complete_operation("nonexistent_operation")

    def test_stop_without_start(self):
        """Test stopping without starting"""
        tracker = ProgressTracker(enable_rich=True)

        # Should not raise error
        tracker.stop()

    def test_multiple_start_calls(self):
        """Test calling start() multiple times"""
        tracker = ProgressTracker(enable_rich=False)

        tracker.start()
        tracker.start()
        tracker.start()

        # Should not raise errors

    def test_multiple_stop_calls(self):
        """Test calling stop() multiple times"""
        tracker = ProgressTracker(enable_rich=False)
        tracker.start()

        tracker.stop()
        tracker.stop()
        tracker.stop()

        # Should not raise errors

    def test_task_id_case_insensitive(self):
        """Test that scanner names are converted to lowercase task IDs"""
        tracker = ProgressTracker(enable_rich=False)

        task_id1 = tracker.start_scan("Semgrep", total_files=100)
        task_id2 = tracker.start_scan("TRIVY", total_files=50)
        task_id3 = tracker.start_scan("TruffleHog", total_files=75)

        assert task_id1 == "semgrep"
        assert task_id2 == "trivy"
        assert task_id3 == "trufflehog"

    def test_operation_id_spaces_replaced(self):
        """Test that operation names have spaces replaced with underscores"""
        tracker = ProgressTracker(enable_rich=False)

        op_id1 = tracker.start_operation("LLM Analysis")
        op_id2 = tracker.start_operation("Report Generation")

        assert op_id1 == "llm_analysis"
        assert op_id2 == "report_generation"


class TestProgressTrackerIntegration:
    """Integration tests for complete workflows"""

    def test_full_scanner_workflow_rich_disabled(self):
        """Test complete scanner workflow with rich disabled"""
        tracker = ProgressTracker(enable_rich=False)
        tracker.start()

        # Start scan
        task_id = tracker.start_scan("Semgrep", total_files=100)

        # Update progress
        for i in range(100):
            tracker.update_progress(task_id, advance=1)

        # Complete scan
        tracker.complete_scan(task_id)

        # Stop tracker
        tracker.stop()

        stats = tracker.get_stats()
        assert stats["files_scanned"] == 100
        assert stats["scanners_completed"] == 1
        assert stats["errors"] == 0

    def test_multiple_scanners_workflow(self):
        """Test workflow with multiple scanners"""
        tracker = ProgressTracker(enable_rich=False)
        tracker.start()

        # Scanner 1
        task1 = tracker.start_scan("Semgrep", total_files=100)
        tracker.update_progress(task1, completed=100)
        tracker.complete_scan(task1)

        # Scanner 2
        task2 = tracker.start_scan("Trivy", total_files=50)
        tracker.update_progress(task2, completed=50)
        tracker.complete_scan(task2)

        # Scanner 3 with error
        task3 = tracker.start_scan("TruffleHog", total_files=75)
        tracker.update_progress(task3, completed=30)
        tracker.complete_scan(task3, message="Timeout", error=True)

        tracker.stop()

        stats = tracker.get_stats()
        assert stats["scanners_completed"] == 2
        assert stats["errors"] == 1

    def test_mixed_scanners_and_operations(self):
        """Test workflow with both scanners and operations"""
        tracker = ProgressTracker(enable_rich=False)
        tracker.start()

        # Scanner
        task_id = tracker.start_scan("Semgrep", total_files=100)
        tracker.update_progress(task_id, completed=100)
        tracker.complete_scan(task_id)

        # Operation with context manager
        with tracker.operation("LLM Analysis"):
            pass

        # Manual operation
        op_id = tracker.start_operation("Report Generation")
        tracker.complete_operation(op_id)

        tracker.stop()

        stats = tracker.get_stats()
        assert stats["scanners_completed"] == 1
        assert stats["llm_calls"] == 1
        assert stats["errors"] == 0

    def test_error_handling_in_context_manager(self):
        """Test error handling within context manager"""
        tracker = ProgressTracker(enable_rich=False)
        tracker.start()

        # Successful operation
        with tracker.operation("Operation 1"):
            pass

        # Failed operation
        try:
            with tracker.operation("Operation 2"):
                raise RuntimeError("Simulated error")
        except RuntimeError:
            pass

        tracker.stop()

        stats = tracker.get_stats()
        assert stats["errors"] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
