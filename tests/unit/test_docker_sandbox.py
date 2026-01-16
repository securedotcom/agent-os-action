#!/usr/bin/env python3
"""
Unit tests for Docker Sandbox
Tests safe execution of untrusted code in isolated containers
"""

import json
import pytest
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from sandbox.docker_sandbox import (
    DockerSandbox,
    SandboxConfig,
    SandboxResult,
    DOCKER_AVAILABLE
)


# Skip all tests if Docker is not available
pytestmark = pytest.mark.skipif(
    not DOCKER_AVAILABLE,
    reason="Docker not available"
)


class TestSandboxConfig:
    """Test SandboxConfig dataclass"""

    def test_default_config(self):
        """Test default configuration values"""
        config = SandboxConfig()
        assert config.cpu_limit == 1.0
        assert config.memory_limit == "512m"
        assert config.timeout == 60
        assert config.network_disabled is True
        assert config.enable_coverage is False

    def test_custom_config(self):
        """Test custom configuration values"""
        config = SandboxConfig(
            cpu_limit=2.0,
            memory_limit="1g",
            timeout=120,
            network_disabled=False,
            enable_coverage=True
        )
        assert config.cpu_limit == 2.0
        assert config.memory_limit == "1g"
        assert config.timeout == 120
        assert config.network_disabled is False
        assert config.enable_coverage is True


class TestSandboxResult:
    """Test SandboxResult dataclass"""

    def test_successful_result(self):
        """Test successful execution result"""
        result = SandboxResult(
            success=True,
            output="Hello, World!",
            error="",
            exit_code=0,
            execution_time_ms=100,
            crashed=False
        )
        assert result.success is True
        assert result.output == "Hello, World!"
        assert result.crashed is False
        assert result.exit_code == 0

    def test_crashed_result(self):
        """Test crashed execution result"""
        result = SandboxResult(
            success=False,
            output="",
            error="Exception occurred",
            exit_code=1,
            execution_time_ms=50,
            crashed=True,
            crash_type="exception",
            stack_trace="Traceback..."
        )
        assert result.success is False
        assert result.crashed is True
        assert result.crash_type == "exception"
        assert "Traceback" in result.stack_trace


class TestDockerSandboxMocked:
    """Test DockerSandbox with mocked Docker manager"""

    @patch('sandbox.docker_sandbox.DockerManager')
    def test_init_with_default_config(self, mock_docker_manager_class):
        """Test initialization with default config"""
        mock_manager = Mock()
        mock_docker_manager_class.return_value = mock_manager

        sandbox = DockerSandbox()

        assert sandbox.config.cpu_limit == 1.0
        assert sandbox.config.memory_limit == "512m"
        assert sandbox.config.timeout == 60
        assert sandbox.container_id is None
        assert sandbox._execution_count == 0

    @patch('sandbox.docker_sandbox.DockerManager')
    def test_init_with_custom_config(self, mock_docker_manager_class):
        """Test initialization with custom config"""
        mock_manager = Mock()
        mock_docker_manager_class.return_value = mock_manager

        config = SandboxConfig(cpu_limit=2.0, memory_limit="1g")
        sandbox = DockerSandbox(config=config)

        assert sandbox.config.cpu_limit == 2.0
        assert sandbox.config.memory_limit == "1g"

    @patch('sandbox.docker_sandbox.DockerManager')
    def test_create_container(self, mock_docker_manager_class):
        """Test container creation"""
        mock_manager = Mock()
        mock_manager.create_container.return_value = "container-123"
        mock_docker_manager_class.return_value = mock_manager

        sandbox = DockerSandbox()
        container_id = sandbox.create_container()

        assert container_id == "container-123"
        assert sandbox.container_id == "container-123"
        mock_manager.create_container.assert_called_once()

        # Verify container created with correct parameters
        call_kwargs = mock_manager.create_container.call_args[1]
        assert call_kwargs['cpu_limit'] == 1.0
        assert call_kwargs['memory_limit'] == "512m"
        assert call_kwargs['network_disabled'] is True

    @patch('sandbox.docker_sandbox.DockerManager')
    def test_execute_python_safe_code(self, mock_docker_manager_class):
        """Test executing safe Python code"""
        mock_manager = Mock()
        mock_manager.create_container.return_value = "container-123"

        # Mock successful execution
        mock_manager.execute_code.return_value = {
            'stdout': json.dumps({
                'success': True,
                'output': '2',
                'error': '',
                'crashed': False
            }),
            'stderr': '',
            'exit_code': 0,
            'success': True
        }

        mock_docker_manager_class.return_value = mock_manager

        sandbox = DockerSandbox()
        code = "def add(a, b):\n    return a + b"
        result = sandbox.execute_python(code, "add", [1, 1])

        assert result.success is True
        assert result.output == '2'
        assert result.crashed is False
        assert result.execution_time_ms >= 0  # Mocked execution may return 0
        assert sandbox._execution_count == 1

    @patch('sandbox.docker_sandbox.DockerManager')
    def test_execute_python_malicious_code_contained(self, mock_docker_manager_class):
        """Test that malicious code is safely contained"""
        mock_manager = Mock()
        mock_manager.create_container.return_value = "container-123"

        # Mock execution that would be dangerous outside sandbox
        mock_manager.execute_code.return_value = {
            'stdout': json.dumps({
                'success': False,
                'error': 'Permission denied',
                'crashed': True,
                'crash_type': 'exception',
                'stack_trace': 'PermissionError: ...'
            }),
            'stderr': '',
            'exit_code': 1,
            'success': False
        }

        mock_docker_manager_class.return_value = mock_manager

        sandbox = DockerSandbox()
        code = "def evil():\n    import os\n    os.system('rm -rf /')"
        result = sandbox.execute_python(code, "evil", None)

        # Code executed but failed safely in container
        assert result.crashed is True
        assert 'Permission' in result.error or result.crash_type == 'exception'

    @patch('sandbox.docker_sandbox.DockerManager')
    def test_execute_python_timeout(self, mock_docker_manager_class):
        """Test execution timeout"""
        mock_manager = Mock()
        mock_manager.create_container.return_value = "container-123"

        # Mock timeout
        mock_manager.execute_code.return_value = {
            'stdout': json.dumps({
                'success': False,
                'error': 'Execution timeout',
                'crashed': True,
                'crash_type': 'timeout',
                'stack_trace': 'TimeoutError'
            }),
            'stderr': 'timeout',
            'exit_code': 124,
            'success': False
        }

        mock_docker_manager_class.return_value = mock_manager

        sandbox = DockerSandbox()
        code = "def infinite():\n    while True: pass"
        result = sandbox.execute_python(code, "infinite", None, timeout=5)

        assert result.crashed is True
        assert result.crash_type == 'timeout'

    @patch('sandbox.docker_sandbox.DockerManager')
    def test_execute_python_exception(self, mock_docker_manager_class):
        """Test execution with exception"""
        mock_manager = Mock()
        mock_manager.create_container.return_value = "container-123"

        mock_manager.execute_code.return_value = {
            'stdout': json.dumps({
                'success': False,
                'error': 'division by zero',
                'crashed': True,
                'crash_type': 'exception',
                'stack_trace': 'ZeroDivisionError: division by zero'
            }),
            'stderr': '',
            'exit_code': 1,
            'success': False
        }

        mock_docker_manager_class.return_value = mock_manager

        sandbox = DockerSandbox()
        code = "def divide(a, b):\n    return a / b"
        result = sandbox.execute_python(code, "divide", [1, 0])

        assert result.crashed is True
        assert result.crash_type == 'exception'
        assert 'division by zero' in result.error

    @patch('sandbox.docker_sandbox.DockerManager')
    def test_execute_python_module(self, mock_docker_manager_class):
        """Test executing function from a module file"""
        mock_manager = Mock()
        mock_manager.create_container.return_value = "container-123"
        mock_manager.execute_code.return_value = {
            'stdout': json.dumps({
                'success': True,
                'output': '3',
                'error': '',
                'crashed': False
            }),
            'stderr': '',
            'exit_code': 0,
            'success': True
        }

        mock_docker_manager_class.return_value = mock_manager

        # Create temporary Python file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("def multiply(a, b):\n    return a * b\n")
            temp_file = f.name

        try:
            sandbox = DockerSandbox()
            result = sandbox.execute_python_module(temp_file, "multiply", [3, 1])

            assert result.success is True
            assert result.output == '3'
            assert result.crashed is False
        finally:
            Path(temp_file).unlink(missing_ok=True)

    @patch('sandbox.docker_sandbox.DockerManager')
    def test_execute_python_module_file_not_found(self, mock_docker_manager_class):
        """Test executing from non-existent module"""
        mock_manager = Mock()
        mock_docker_manager_class.return_value = mock_manager

        sandbox = DockerSandbox()
        result = sandbox.execute_python_module(
            "/nonexistent/module.py",
            "some_function",
            None
        )

        assert result.success is False
        assert result.crashed is True
        assert result.crash_type == "file_read_error"
        assert "Failed to read module" in result.error

    @patch('sandbox.docker_sandbox.DockerManager')
    def test_cleanup(self, mock_docker_manager_class):
        """Test sandbox cleanup"""
        mock_manager = Mock()
        mock_manager.create_container.return_value = "container-123"
        mock_docker_manager_class.return_value = mock_manager

        sandbox = DockerSandbox()
        sandbox.create_container()

        assert sandbox.container_id == "container-123"

        sandbox.cleanup()

        mock_manager.stop_container.assert_called_once_with("container-123", timeout=5)
        mock_manager.remove_container.assert_called_once_with("container-123", force=True)
        assert sandbox.container_id is None

    @patch('sandbox.docker_sandbox.DockerManager')
    def test_context_manager(self, mock_docker_manager_class):
        """Test using sandbox as context manager"""
        mock_manager = Mock()
        mock_manager.create_container.return_value = "container-123"
        mock_docker_manager_class.return_value = mock_manager

        with DockerSandbox() as sandbox:
            assert sandbox.container_id == "container-123"

        # Cleanup should be called automatically
        mock_manager.stop_container.assert_called_once()
        mock_manager.remove_container.assert_called_once()

    @patch('sandbox.docker_sandbox.DockerManager')
    def test_multiple_executions(self, mock_docker_manager_class):
        """Test multiple executions in same sandbox"""
        mock_manager = Mock()
        mock_manager.create_container.return_value = "container-123"
        mock_manager.execute_code.return_value = {
            'stdout': json.dumps({
                'success': True,
                'output': 'result',
                'error': '',
                'crashed': False
            }),
            'stderr': '',
            'exit_code': 0,
            'success': True
        }

        mock_docker_manager_class.return_value = mock_manager

        sandbox = DockerSandbox()
        code = "def test():\n    return 'result'"

        # Execute multiple times
        sandbox.execute_python(code, "test", None)
        sandbox.execute_python(code, "test", None)
        sandbox.execute_python(code, "test", None)

        assert sandbox._execution_count == 3
        # Container created only once
        assert mock_manager.create_container.call_count == 1
        # Code executed 3 times
        assert mock_manager.execute_code.call_count == 3

    @patch('sandbox.docker_sandbox.DockerManager')
    def test_build_execution_wrapper(self, mock_docker_manager_class):
        """Test execution wrapper generation"""
        mock_manager = Mock()
        mock_docker_manager_class.return_value = mock_manager

        sandbox = DockerSandbox()

        code = "def test(x):\n    return x * 2"
        wrapper = sandbox._build_execution_wrapper(code, "test", 5)

        # Verify wrapper contains expected elements
        assert "CODE = " in wrapper
        assert "TEST_INPUT = " in wrapper
        assert "FUNCTION_NAME = " in wrapper
        assert "def run_test():" in wrapper
        assert "exec(CODE, namespace)" in wrapper

    @patch('sandbox.docker_sandbox.DockerManager')
    def test_parse_result_success(self, mock_docker_manager_class):
        """Test parsing successful result"""
        mock_manager = Mock()
        mock_docker_manager_class.return_value = mock_manager

        sandbox = DockerSandbox()

        docker_result = {
            'stdout': json.dumps({
                'success': True,
                'output': 'test output',
                'error': '',
                'crashed': False
            }),
            'stderr': '',
            'exit_code': 0
        }

        result = sandbox._parse_result(docker_result, 100)

        assert result.success is True
        assert result.output == 'test output'
        assert result.crashed is False
        assert result.execution_time_ms == 100

    @patch('sandbox.docker_sandbox.DockerManager')
    def test_parse_result_invalid_json(self, mock_docker_manager_class):
        """Test parsing result with invalid JSON"""
        mock_manager = Mock()
        mock_docker_manager_class.return_value = mock_manager

        sandbox = DockerSandbox()

        docker_result = {
            'stdout': 'invalid json',
            'stderr': 'Segmentation fault',
            'exit_code': 139
        }

        result = sandbox._parse_result(docker_result, 50)

        assert result.success is False
        assert result.crashed is True
        assert result.crash_type == 'segfault'
        assert result.execution_time_ms == 50

    @patch('sandbox.docker_sandbox.DockerManager')
    def test_parse_result_timeout(self, mock_docker_manager_class):
        """Test parsing timeout result"""
        mock_manager = Mock()
        mock_docker_manager_class.return_value = mock_manager

        sandbox = DockerSandbox()

        docker_result = {
            'stdout': '',
            'stderr': 'Command timed out',
            'exit_code': 124  # timeout command exit code
        }

        result = sandbox._parse_result(docker_result, 5000)

        assert result.crashed is True
        assert result.crash_type == 'timeout'


class TestDockerSandboxIntegration:
    """Integration tests - only run if Docker is actually available"""

    @pytest.mark.skipif(
        not DOCKER_AVAILABLE,
        reason="Docker not available for integration test"
    )
    def test_real_docker_execution_simple(self):
        """Test real Docker execution with simple code"""
        pytest.skip("Integration test - run manually with Docker available")

        config = SandboxConfig(timeout=30)
        with DockerSandbox(config=config) as sandbox:
            code = "def add(a, b):\n    return a + b"
            result = sandbox.execute_python(code, "add", [2, 3])

            assert result.success is True
            assert '5' in result.output
            assert result.crashed is False

    @pytest.mark.skipif(
        not DOCKER_AVAILABLE,
        reason="Docker not available for integration test"
    )
    def test_real_docker_execution_exception(self):
        """Test real Docker execution with exception"""
        pytest.skip("Integration test - run manually with Docker available")

        with DockerSandbox() as sandbox:
            code = "def fail():\n    raise ValueError('test error')"
            result = sandbox.execute_python(code, "fail", None)

            assert result.crashed is True
            assert 'ValueError' in result.stack_trace or 'test error' in result.error


def test_module_imports():
    """Test that all required modules can be imported"""
    # This test always runs
    from sandbox.docker_sandbox import (
        DockerSandbox,
        SandboxConfig,
        SandboxResult
    )
    assert DockerSandbox is not None
    assert SandboxConfig is not None
    assert SandboxResult is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
