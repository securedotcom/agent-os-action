#!/usr/bin/env python3
"""
Foundation-Sec-8B Provider for Agent OS
Security-optimized LLM provider using Cisco's Foundation-Sec-8B-Instruct model

This provider offers:
- 75% cost savings (always $0, local inference)
- GPU/CPU auto-detection for optimal performance
- Same interface as Anthropic/OpenAI providers
- Specialized for security vulnerability analysis
"""

import os
import logging
from typing import Tuple, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class FoundationSecProvider:
    """
    Foundation-Sec-8B Provider

    Loads and runs Cisco's Foundation-Sec-8B-Instruct model for security analysis.
    This is a local model that provides zero-cost inference with security-specific training.

    Attributes:
        model: The loaded transformers model
        tokenizer: The model's tokenizer
        device: Computation device (cuda/cpu)
        model_name: HuggingFace model identifier
    """

    def __init__(
        self,
        model_name: str = "fdtn-ai/Foundation-Sec-8B",
        cache_dir: Optional[str] = None,
        device: Optional[str] = None,
        use_quantization: bool = True
    ):
        """
        Initialize Foundation-Sec provider

        Args:
            model_name: HuggingFace model identifier (default: fdtn-ai/Foundation-Sec-8B)
            cache_dir: Directory to cache model weights (default: ~/.cache/huggingface)
            device: Force specific device ('cuda' or 'cpu'), auto-detect if None
            use_quantization: Use 4-bit quantization to reduce model size (16GB → 4GB)
        """
        self.model_name = model_name
        self.cache_dir = cache_dir or os.path.expanduser("~/.cache/huggingface")
        self.device = device
        self.use_quantization = use_quantization
        self.model = None
        self.tokenizer = None
        self.pipeline = None

        # Load model on initialization
        self._load_model()

    def _detect_device(self) -> str:
        """
        Auto-detect optimal computation device

        Returns:
            Device string: 'cuda' if GPU available, 'cpu' otherwise
        """
        try:
            import torch
            if torch.cuda.is_available():
                gpu_name = torch.cuda.get_device_name(0)
                gpu_memory = torch.cuda.get_device_properties(0).total_memory / 1e9
                logger.info(f"GPU detected: {gpu_name} ({gpu_memory:.1f}GB)")
                return 'cuda'
            else:
                logger.info("No GPU detected, using CPU")
                return 'cpu'
        except ImportError:
            logger.warning("PyTorch not available, defaulting to CPU")
            return 'cpu'

    def _load_model(self):
        """
        Load Foundation-Sec-8B model and tokenizer

        Handles:
        - Device auto-detection (GPU/CPU)
        - Model caching for fast subsequent loads
        - Memory-efficient loading for large models
        - Error handling for missing dependencies
        """
        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline
            import torch

            # Detect device if not specified
            if self.device is None:
                self.device = self._detect_device()

            logger.info(f"Loading Foundation-Sec-8B model: {self.model_name}")
            logger.info(f"Device: {self.device}")
            logger.info(f"Cache directory: {self.cache_dir}")

            # Load tokenizer
            logger.debug("Loading tokenizer...")
            self.tokenizer = AutoTokenizer.from_pretrained(
                self.model_name,
                cache_dir=self.cache_dir,
                trust_remote_code=True  # Required for some custom models
            )

            # Load model with appropriate settings for device
            logger.debug("Loading model...")

            # Configure quantization if enabled (reduces 16GB → 4GB)
            model_kwargs = {
                'cache_dir': self.cache_dir,
                'trust_remote_code': True
            }

            if self.use_quantization and self.device == 'cuda':
                # 4-bit quantization for GPU (75% memory reduction)
                try:
                    from transformers import BitsAndBytesConfig

                    quantization_config = BitsAndBytesConfig(
                        load_in_4bit=True,
                        bnb_4bit_compute_dtype=torch.float16,
                        bnb_4bit_use_double_quant=True,
                        bnb_4bit_quant_type="nf4"
                    )

                    model_kwargs['quantization_config'] = quantization_config
                    model_kwargs['device_map'] = 'auto'
                    logger.info("Using 4-bit quantization (16GB → 4GB)")

                except ImportError:
                    logger.warning("bitsandbytes not available, using fp16 instead")
                    model_kwargs['device_map'] = 'auto'
                    model_kwargs['torch_dtype'] = torch.float16

            elif self.device == 'cuda':
                # GPU: Load with fp16 for memory efficiency
                model_kwargs['device_map'] = 'auto'
                model_kwargs['torch_dtype'] = torch.float16
            else:
                # CPU: Load with default settings
                model_kwargs['device_map'] = 'cpu'

            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_name,
                **model_kwargs
            )

            # Create text generation pipeline
            self.pipeline = pipeline(
                "text-generation",
                model=self.model,
                tokenizer=self.tokenizer,
                device=0 if self.device == 'cuda' else -1  # 0 for GPU, -1 for CPU
            )

            logger.info(f"Foundation-Sec-8B model loaded successfully on {self.device}")

        except ImportError as e:
            error_msg = (
                f"Required dependencies not installed: {e}\n"
                "Install with: pip install transformers torch accelerate"
            )
            logger.error(error_msg)
            raise ImportError(error_msg)

        except Exception as e:
            error_msg = f"Failed to load Foundation-Sec-8B model: {type(e).__name__}: {e}"
            logger.error(error_msg)
            raise RuntimeError(error_msg)

    def generate(
        self,
        prompt: str,
        max_tokens: int = 8000,
        temperature: float = 0.7,
        top_p: float = 0.9
    ) -> Tuple[str, int, int]:
        """
        Generate text using Foundation-Sec-8B model

        Args:
            prompt: Input prompt for the model
            max_tokens: Maximum number of tokens to generate
            temperature: Sampling temperature (0.0-1.0, higher = more random)
            top_p: Nucleus sampling parameter (0.0-1.0)

        Returns:
            Tuple of (generated_text, input_tokens, output_tokens)
        """
        if self.pipeline is None:
            raise RuntimeError("Model not loaded. Call _load_model() first.")

        try:
            # Tokenize input to count tokens
            input_ids = self.tokenizer.encode(prompt, return_tensors='pt')
            input_token_count = input_ids.shape[1]

            logger.debug(f"Input tokens: {input_token_count}")
            logger.debug(f"Generating with max_tokens={max_tokens}, temperature={temperature}")

            # Generate text
            outputs = self.pipeline(
                prompt,
                max_new_tokens=max_tokens,
                temperature=temperature,
                top_p=top_p,
                do_sample=True,  # Enable sampling for more diverse outputs
                pad_token_id=self.tokenizer.eos_token_id,  # Proper padding
                return_full_text=False  # Only return generated text, not prompt
            )

            # Extract generated text
            generated_text = outputs[0]['generated_text']

            # Count output tokens
            output_ids = self.tokenizer.encode(generated_text, return_tensors='pt')
            output_token_count = output_ids.shape[1]

            logger.debug(f"Output tokens: {output_token_count}")

            return generated_text, input_token_count, output_token_count

        except Exception as e:
            error_msg = f"Text generation failed: {type(e).__name__}: {e}"
            logger.error(error_msg)
            raise RuntimeError(error_msg)

    def estimate_cost(self, input_tokens: int, output_tokens: int) -> float:
        """
        Estimate cost for Foundation-Sec provider (always $0 for local models)

        Args:
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens

        Returns:
            Cost in USD (always 0.0 for local inference)
        """
        return 0.0

    def get_info(self) -> dict:
        """
        Get provider information

        Returns:
            Dictionary with provider metadata
        """
        return {
            'provider': 'foundation-sec',
            'model': self.model_name,
            'device': self.device,
            'cache_dir': self.cache_dir,
            'cost_per_1m_input_tokens': 0.0,
            'cost_per_1m_output_tokens': 0.0,
            'local_inference': True,
            'security_optimized': True
        }


def get_foundation_sec_client(config: dict) -> Tuple[FoundationSecProvider, str]:
    """
    Initialize Foundation-Sec client for Agent OS

    Args:
        config: Configuration dictionary with optional keys:
            - foundation_sec_model: Custom model name (default: cisco-ai/foundation-sec-8b-instruct)
            - foundation_sec_cache_dir: Custom cache directory
            - foundation_sec_device: Force specific device ('cuda' or 'cpu')
            - foundation_sec_quantization: Use 4-bit quantization (default: True)

    Returns:
        Tuple of (FoundationSecProvider instance, provider_name)
    """
    model_name = config.get(
        'foundation_sec_model',
        'fdtn-ai/Foundation-Sec-8B'
    )
    cache_dir = config.get('foundation_sec_cache_dir')
    device = config.get('foundation_sec_device')
    use_quantization = config.get('foundation_sec_quantization', True)

    logger.info("Initializing Foundation-Sec provider")
    if use_quantization:
        logger.info("4-bit quantization enabled (reduces 16GB → 4GB)")

    provider = FoundationSecProvider(
        model_name=model_name,
        cache_dir=cache_dir,
        device=device,
        use_quantization=use_quantization
    )

    return provider, 'foundation-sec'


def call_foundation_sec_api(
    client: FoundationSecProvider,
    prompt: str,
    max_tokens: int = 8000
) -> Tuple[str, int, int]:
    """
    Call Foundation-Sec API (wrapper for compatibility with run_ai_audit.py)

    Args:
        client: FoundationSecProvider instance
        prompt: Input prompt
        max_tokens: Maximum tokens to generate

    Returns:
        Tuple of (response_text, input_tokens, output_tokens)
    """
    return client.generate(prompt, max_tokens=max_tokens)
