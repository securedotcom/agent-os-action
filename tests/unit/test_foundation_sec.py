"""Unit tests for Foundation-Sec-8B provider"""

import sys
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

# Add scripts directory to path for imports
scripts_dir = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(scripts_dir))


class TestFoundationSecProvider:
    """Test suite for Foundation-Sec provider functionality"""

    @patch("providers.foundation_sec.AutoModelForCausalLM")
    @patch("providers.foundation_sec.AutoTokenizer")
    @patch("providers.foundation_sec.pipeline")
    @patch("providers.foundation_sec.torch")
    def test_provider_initialization_gpu(self, mock_torch, mock_pipeline, mock_tokenizer, mock_model):
        """Test Foundation-Sec provider initialization with GPU"""
        from providers.foundation_sec import FoundationSecProvider

        # Mock GPU availability
        mock_torch.cuda.is_available.return_value = True
        mock_torch.cuda.get_device_name.return_value = "NVIDIA RTX 4090"
        mock_torch.cuda.get_device_properties.return_value = Mock(total_memory=24e9)
        mock_torch.float16 = Mock()

        # Mock model and tokenizer
        mock_tokenizer_instance = Mock()
        mock_tokenizer.from_pretrained.return_value = mock_tokenizer_instance

        mock_model_instance = Mock()
        mock_model.from_pretrained.return_value = mock_model_instance

        mock_pipeline_instance = Mock()
        mock_pipeline.return_value = mock_pipeline_instance

        # Initialize provider
        provider = FoundationSecProvider()

        # Verify initialization
        assert provider.device == "cuda"
        assert provider.model is not None
        assert provider.tokenizer is not None
        assert provider.pipeline is not None

        # Verify model loaded with GPU settings
        mock_model.from_pretrained.assert_called_once()
        call_kwargs = mock_model.from_pretrained.call_args[1]
        assert call_kwargs["device_map"] == "auto"
        assert call_kwargs["torch_dtype"] == mock_torch.float16

    @patch("providers.foundation_sec.AutoModelForCausalLM")
    @patch("providers.foundation_sec.AutoTokenizer")
    @patch("providers.foundation_sec.pipeline")
    @patch("providers.foundation_sec.torch")
    def test_provider_initialization_cpu(self, mock_torch, mock_pipeline, mock_tokenizer, mock_model):
        """Test Foundation-Sec provider initialization with CPU"""
        from providers.foundation_sec import FoundationSecProvider

        # Mock no GPU
        mock_torch.cuda.is_available.return_value = False

        # Mock model and tokenizer
        mock_tokenizer_instance = Mock()
        mock_tokenizer.from_pretrained.return_value = mock_tokenizer_instance

        mock_model_instance = Mock()
        mock_model.from_pretrained.return_value = mock_model_instance

        mock_pipeline_instance = Mock()
        mock_pipeline.return_value = mock_pipeline_instance

        # Initialize provider
        provider = FoundationSecProvider()

        # Verify CPU initialization
        assert provider.device == "cpu"

        # Verify model loaded with CPU settings
        call_kwargs = mock_model.from_pretrained.call_args[1]
        assert call_kwargs["device_map"] == "cpu"

    @patch("providers.foundation_sec.AutoModelForCausalLM")
    @patch("providers.foundation_sec.AutoTokenizer")
    @patch("providers.foundation_sec.pipeline")
    @patch("providers.foundation_sec.torch")
    def test_generate_text(self, mock_torch, mock_pipeline, mock_tokenizer, mock_model):
        """Test text generation"""
        from providers.foundation_sec import FoundationSecProvider

        # Mock torch
        mock_torch.cuda.is_available.return_value = False

        # Mock tokenizer
        mock_tokenizer_instance = Mock()
        mock_tokenizer_instance.encode.return_value = Mock(shape=(1, 100))  # 100 input tokens
        mock_tokenizer_instance.eos_token_id = 2
        mock_tokenizer.from_pretrained.return_value = mock_tokenizer_instance

        # Mock model
        mock_model_instance = Mock()
        mock_model.from_pretrained.return_value = mock_model_instance

        # Mock pipeline
        mock_pipeline_instance = Mock()
        mock_pipeline_instance.return_value = [
            {"generated_text": "This is a security vulnerability in the authentication system."}
        ]
        mock_pipeline.return_value = mock_pipeline_instance

        # Initialize provider
        provider = FoundationSecProvider()
        provider.tokenizer = mock_tokenizer_instance
        provider.pipeline = mock_pipeline_instance

        # Generate text
        prompt = "Analyze this code for security vulnerabilities: def login(user, password): ..."
        response, input_tokens, output_tokens = provider.generate(prompt, max_tokens=8000)

        # Verify generation
        assert response == "This is a security vulnerability in the authentication system."
        assert input_tokens == 100
        assert output_tokens > 0

        # Verify pipeline called with correct parameters
        mock_pipeline_instance.assert_called_once()
        call_args = mock_pipeline_instance.call_args
        assert call_args[0][0] == prompt
        assert call_args[1]["max_new_tokens"] == 8000

    @patch("providers.foundation_sec.AutoModelForCausalLM")
    @patch("providers.foundation_sec.AutoTokenizer")
    @patch("providers.foundation_sec.pipeline")
    @patch("providers.foundation_sec.torch")
    def test_cost_estimation_always_zero(self, mock_torch, mock_pipeline, mock_tokenizer, mock_model):
        """Test that Foundation-Sec always reports zero cost"""
        from providers.foundation_sec import FoundationSecProvider

        # Mock minimal setup
        mock_torch.cuda.is_available.return_value = False
        mock_tokenizer.from_pretrained.return_value = Mock()
        mock_model.from_pretrained.return_value = Mock()
        mock_pipeline.return_value = Mock()

        # Initialize provider
        provider = FoundationSecProvider()

        # Test cost estimation
        cost = provider.estimate_cost(input_tokens=10000, output_tokens=5000)
        assert cost == 0.0

    @patch("providers.foundation_sec.AutoModelForCausalLM")
    @patch("providers.foundation_sec.AutoTokenizer")
    @patch("providers.foundation_sec.pipeline")
    @patch("providers.foundation_sec.torch")
    def test_get_info(self, mock_torch, mock_pipeline, mock_tokenizer, mock_model):
        """Test provider info retrieval"""
        from providers.foundation_sec import FoundationSecProvider

        # Mock setup
        mock_torch.cuda.is_available.return_value = True
        mock_torch.cuda.get_device_name.return_value = "NVIDIA RTX 4090"
        mock_torch.cuda.get_device_properties.return_value = Mock(total_memory=24e9)
        mock_torch.float16 = Mock()

        mock_tokenizer.from_pretrained.return_value = Mock()
        mock_model.from_pretrained.return_value = Mock()
        mock_pipeline.return_value = Mock()

        # Initialize provider
        provider = FoundationSecProvider()

        # Get info
        info = provider.get_info()

        # Verify info structure
        assert info["provider"] == "foundation-sec"
        assert info["model"] == "cisco-ai/foundation-sec-8b-instruct"
        assert info["device"] == "cuda"
        assert info["cost_per_1m_input_tokens"] == 0.0
        assert info["cost_per_1m_output_tokens"] == 0.0
        assert info["local_inference"] is True
        assert info["security_optimized"] is True

    @patch("providers.foundation_sec.FoundationSecProvider")
    def test_get_foundation_sec_client(self, mock_provider_class):
        """Test client initialization wrapper"""
        from providers.foundation_sec import get_foundation_sec_client

        # Mock provider instance
        mock_provider_instance = Mock()
        mock_provider_class.return_value = mock_provider_instance

        # Test with default config
        config = {}
        client, provider_name = get_foundation_sec_client(config)

        # Verify
        assert client == mock_provider_instance
        assert provider_name == "foundation-sec"

        # Verify provider initialized with defaults
        mock_provider_class.assert_called_once_with(
            model_name="cisco-ai/foundation-sec-8b-instruct", cache_dir=None, device=None
        )

    @patch("providers.foundation_sec.FoundationSecProvider")
    def test_get_foundation_sec_client_custom_config(self, mock_provider_class):
        """Test client initialization with custom config"""
        from providers.foundation_sec import get_foundation_sec_client

        # Mock provider instance
        mock_provider_instance = Mock()
        mock_provider_class.return_value = mock_provider_instance

        # Test with custom config
        config = {
            "foundation_sec_model": "custom-org/custom-model",
            "foundation_sec_cache_dir": "/custom/cache",
            "foundation_sec_device": "cuda",
        }
        client, provider_name = get_foundation_sec_client(config)

        # Verify custom settings used
        mock_provider_class.assert_called_once_with(
            model_name="custom-org/custom-model", cache_dir="/custom/cache", device="cuda"
        )

    @patch("providers.foundation_sec.FoundationSecProvider")
    def test_call_foundation_sec_api(self, mock_provider_class):
        """Test API wrapper function"""
        from providers.foundation_sec import call_foundation_sec_api

        # Mock provider with generate method
        mock_provider = Mock()
        mock_provider.generate.return_value = ("Generated security analysis", 500, 300)

        # Call API
        response, input_tokens, output_tokens = call_foundation_sec_api(
            mock_provider, "Analyze this code", max_tokens=8000
        )

        # Verify
        assert response == "Generated security analysis"
        assert input_tokens == 500
        assert output_tokens == 300

        # Verify generate called with correct args
        mock_provider.generate.assert_called_once_with("Analyze this code", max_tokens=8000)

    def test_import_error_handling(self):
        """Test graceful handling of missing dependencies"""
        from providers.foundation_sec import FoundationSecProvider

        # Test that ImportError is raised with helpful message
        with patch(
            "providers.foundation_sec.AutoModelForCausalLM", side_effect=ImportError("No module named 'transformers'")
        ):
            with pytest.raises(ImportError) as exc_info:
                FoundationSecProvider()

            assert "Required dependencies not installed" in str(exc_info.value)
            assert "pip install transformers torch accelerate" in str(exc_info.value)


class TestFoundationSecIntegrationWithRunAudit:
    """Test Foundation-Sec integration with run_ai_audit.py"""

    def test_detect_foundation_sec_provider(self):
        """Test auto-detection of Foundation-Sec provider"""
        # Import after adding to path
        import sys

        sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
        from run_ai_audit import detect_ai_provider

        config = {
            "ai_provider": "auto",
            "anthropic_api_key": "",
            "openai_api_key": "",
            "foundation_sec_enabled": True,
            "ollama_endpoint": "",
        }

        provider = detect_ai_provider(config)
        assert provider == "foundation-sec"

    def test_manual_foundation_sec_selection(self):
        """Test manual selection of Foundation-Sec provider"""
        import sys

        sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
        from run_ai_audit import detect_ai_provider

        config = {
            "ai_provider": "foundation-sec",
            "anthropic_api_key": "sk-ant-test",  # Even with other keys
            "openai_api_key": "sk-test",
        }

        provider = detect_ai_provider(config)
        assert provider == "foundation-sec"

    def test_get_model_name_foundation_sec(self):
        """Test model name retrieval for Foundation-Sec"""
        import sys

        sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
        from run_ai_audit import get_model_name

        config = {"model": "auto"}
        model = get_model_name("foundation-sec", config)
        assert model == "cisco-ai/foundation-sec-8b-instruct"

    def test_estimate_call_cost_foundation_sec(self):
        """Test cost estimation for Foundation-Sec (should be $0)"""
        import sys

        sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
        from run_ai_audit import estimate_call_cost

        cost = estimate_call_cost(prompt_length=10000, max_output_tokens=8000, provider="foundation-sec")
        assert cost == 0.0

    def test_calculate_actual_cost_foundation_sec(self):
        """Test actual cost calculation for Foundation-Sec (should be $0)"""
        import sys

        sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
        from run_ai_audit import calculate_actual_cost

        cost = calculate_actual_cost(input_tokens=5000, output_tokens=3000, provider="foundation-sec")
        assert cost == 0.0


@pytest.fixture
def mock_config():
    """Fixture providing mock configuration"""
    return {
        "ai_provider": "foundation-sec",
        "foundation_sec_enabled": True,
        "foundation_sec_model": "cisco-ai/foundation-sec-8b-instruct",
        "foundation_sec_device": "cpu",
        "model": "auto",
        "max_tokens": 8000,
        "cost_limit": 1.0,
    }
