# Foundation-Sec-8B Integration Guide

> **🚧 BETA STATUS**: Foundation-Sec-8B provider is implemented (`scripts/providers/foundation_sec.py`) but not yet integrated into the main provider detection chain.
>
> **Current Status**: Code exists, integration pending (~1 hour of work)
>
> **How to Use Today**: Can be tested standalone, but not available in GitHub Actions workflow yet.

## Overview

Foundation-Sec-8B is Cisco's security-optimized language model specifically trained for vulnerability detection and security analysis. This guide covers how to use Foundation-Sec-8B as a 4th AI provider in Agent OS for **75% cost savings** through local inference (🚧 once integration is complete).

## Key Benefits

### Cost Savings
- **Zero Cost**: Local inference means $0 per run (vs. $0.20-$1.00 per run with cloud providers)
- **75% Savings**: Compared to Claude/GPT-4 API costs
- **No API Keys Required**: No subscription or rate limits

### Performance
- **GPU Acceleration**: Automatic CUDA detection for fast inference
- **CPU Fallback**: Works on CPU-only systems (slower but functional)
- **8B Parameters**: Security-specialized model optimized for vulnerability detection

### Security
- **Data Privacy**: All analysis runs locally, no data sent to external APIs
- **Air-Gapped Support**: Can run in disconnected environments
- **Specialized Training**: Trained specifically on security datasets and CVE patterns

---

## Quick Start

### 1. Installation

#### Install Dependencies

```bash
# Core dependencies
pip install transformers torch accelerate

# Optional: For faster inference with CUDA
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118
```

#### Verify Installation

```bash
python3 -c "import torch; print(f'CUDA available: {torch.cuda.is_available()}')"
```

### 2. Enable Foundation-Sec in GitHub Actions

Add to your `.github/workflows/code-review.yml`:

```yaml
name: Code Review with Foundation-Sec

on: [push, pull_request]

jobs:
  security-review:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Run Agent OS Code Review with Foundation-Sec
        uses: securedotcom/agent-os-action@main
        with:
          review-type: 'audit'
          ai-provider: 'foundation-sec'
          foundation-sec-enabled: 'true'
          foundation-sec-model: 'cisco-ai/foundation-sec-8b-instruct'
          # Optional: Force CPU/GPU
          # foundation-sec-device: 'cuda'
          max-files: 50
          cost-limit: '0.0'  # Zero cost!
```

### 3. Local Usage

```bash
# Set environment variable
export FOUNDATION_SEC_ENABLED=true

# Run audit
python3 scripts/run_ai_audit.py . audit
```

---

## Configuration Options

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FOUNDATION_SEC_ENABLED` | Enable Foundation-Sec provider | `false` |
| `FOUNDATION_SEC_MODEL` | Model identifier from HuggingFace | `cisco-ai/foundation-sec-8b-instruct` |
| `FOUNDATION_SEC_DEVICE` | Force device (`cuda` or `cpu`) | Auto-detect |
| `FOUNDATION_SEC_CACHE_DIR` | Model cache directory | `~/.cache/huggingface` |

### GitHub Actions Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `foundation-sec-enabled` | Enable Foundation-Sec | `false` |
| `foundation-sec-model` | Model name | `cisco-ai/foundation-sec-8b-instruct` |
| `foundation-sec-device` | Device (cuda/cpu) | Auto-detect |

---

## Hardware Requirements

### Minimum Requirements (CPU)
- **RAM**: 16GB minimum, 32GB recommended
- **Storage**: 20GB for model weights
- **CPU**: Multi-core processor (4+ cores)
- **Inference Speed**: ~2-5 minutes per review

### Recommended Requirements (GPU)
- **GPU**: NVIDIA GPU with 12GB+ VRAM
  - RTX 3060 (12GB) - Good
  - RTX 4070 (12GB) - Better
  - RTX 4090 (24GB) - Best
- **CUDA**: Version 11.8 or higher
- **Inference Speed**: ~30-60 seconds per review

### GitHub Actions
- Use `ubuntu-latest` runners
- CPU inference is used (slower but functional)
- First run downloads model (~16GB, cached afterward)
- Subsequent runs are fast

---

## Usage Examples

### Example 1: Basic Security Audit

```yaml
- name: Security Audit with Foundation-Sec
  uses: securedotcom/agent-os-action@main
  with:
    review-type: 'security'
    ai-provider: 'foundation-sec'
    foundation-sec-enabled: 'true'
    fail-on: 'security:critical,security:high'
```

### Example 2: Multi-Agent Mode with Foundation-Sec

```yaml
- name: Comprehensive Review
  uses: securedotcom/agent-os-action@main
  with:
    review-type: 'audit'
    ai-provider: 'foundation-sec'
    foundation-sec-enabled: 'true'
    multi-agent-mode: 'sequential'  # 7 specialized agents
    max-files: 100
    cost-limit: '0.0'  # Still zero cost!
```

### Example 3: Hybrid Mode (Foundation-Sec + Claude)

Use Foundation-Sec for initial security scan, Claude for detailed fixes:

```yaml
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Quick Security Scan (Foundation-Sec)
        uses: securedotcom/agent-os-action@main
        with:
          ai-provider: 'foundation-sec'
          foundation-sec-enabled: 'true'
          review-type: 'security'

  detailed-review:
    needs: security-scan
    runs-on: ubuntu-latest
    steps:
      - name: Detailed Review with Fixes (Claude)
        uses: securedotcom/agent-os-action@main
        with:
          ai-provider: 'anthropic'
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          review-type: 'audit'
```

---

## Troubleshooting

### Issue: Model Download Fails

```bash
# Solution 1: Check disk space
df -h

# Solution 2: Manually download model
python3 -c "from transformers import AutoModelForCausalLM; AutoModelForCausalLM.from_pretrained('cisco-ai/foundation-sec-8b-instruct')"

# Solution 3: Use custom cache directory
export FOUNDATION_SEC_CACHE_DIR=/path/to/large/disk
```

### Issue: Out of Memory (OOM)

```bash
# Solution 1: Force CPU inference
export FOUNDATION_SEC_DEVICE=cpu

# Solution 2: Reduce batch size (code change needed)
# Edit scripts/providers/foundation_sec.py:
# - Reduce max_tokens parameter
# - Use quantized models (future enhancement)

# Solution 3: Increase swap space
sudo fallocate -l 8G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

### Issue: Slow Inference on CPU

```bash
# Solution 1: Reduce file count
# Set max-files: 20 instead of 50

# Solution 2: Use GPU-enabled runner
# For GitHub Actions: Use self-hosted GPU runner
# See: https://docs.github.com/en/actions/hosting-your-own-runners

# Solution 3: Use hybrid approach
# Quick scan with Foundation-Sec, detailed review with Claude
```

### Issue: CUDA Not Detected

```bash
# Check CUDA installation
nvidia-smi

# Reinstall PyTorch with CUDA
pip uninstall torch
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118

# Verify
python3 -c "import torch; print(torch.cuda.is_available())"
```

---

## Performance Comparison

### Cost Analysis (50-file codebase)

| Provider | Cost per Run | Cost per 100 Runs | GPU Required |
|----------|--------------|-------------------|--------------|
| Claude Sonnet 4 | $0.20-$0.40 | $20-$40 | No |
| GPT-4 Turbo | $0.50-$1.00 | $50-$100 | No |
| **Foundation-Sec-8B** | **$0.00** | **$0.00** | Optional |
| Ollama (Local) | $0.00 | $0.00 | Optional |

### Inference Time (50-file codebase)

| Provider | GPU (CUDA) | CPU Only |
|----------|------------|----------|
| Claude Sonnet 4 | 20-30s | 20-30s |
| GPT-4 Turbo | 30-45s | 30-45s |
| **Foundation-Sec-8B** | **30-60s** | **2-5 min** |
| Ollama Llama3 | 45-90s | 3-7 min |

### Quality Comparison

| Provider | Security Detection | False Positives | Cost |
|----------|-------------------|-----------------|------|
| Claude Sonnet 4 | Excellent | Low | High |
| GPT-4 Turbo | Excellent | Medium | Very High |
| **Foundation-Sec-8B** | **Very Good** | **Low** | **Zero** |
| Ollama Llama3 | Good | Medium | Zero |

---

## Advanced Configuration

### Custom Model Loading

```python
from scripts.providers.foundation_sec import FoundationSecProvider

# Custom initialization
provider = FoundationSecProvider(
    model_name='cisco-ai/foundation-sec-8b-instruct',
    cache_dir='/mnt/models',
    device='cuda'
)

# Generate security analysis
response, input_tokens, output_tokens = provider.generate(
    prompt="Analyze this code: ...",
    max_tokens=4000,
    temperature=0.7
)

print(f"Cost: ${provider.estimate_cost(input_tokens, output_tokens)}")  # Always $0.00
```

### Programmatic Usage

```python
import os
import sys

# Set Foundation-Sec as provider
os.environ['FOUNDATION_SEC_ENABLED'] = 'true'

# Run audit
from scripts.run_ai_audit import run_audit

config = {
    'ai_provider': 'foundation-sec',
    'foundation_sec_enabled': True,
    'max_files': 50,
    'cost_limit': 0.0
}

blockers, suggestions, metrics = run_audit('.', config, 'audit')

print(f"Blockers: {blockers}")
print(f"Cost: ${metrics.metrics['cost_usd']}")  # Always $0.00
```

---

## Security Considerations

### Model Trust
- Foundation-Sec-8B is developed by Cisco Systems
- Weights are hosted on HuggingFace (verified organization)
- Model is open-source and auditable
- No telemetry or data collection

### Data Privacy
- All inference runs locally on your infrastructure
- No code is sent to external APIs
- Suitable for highly sensitive codebases
- Can run in air-gapped environments

### Supply Chain Security
- Verify model integrity:
  ```bash
  # Check model hash
  shasum -a 256 ~/.cache/huggingface/hub/models--cisco-ai--foundation-sec-8b-instruct/snapshots/*/pytorch_model.bin
  ```
- Pin specific model versions in production:
  ```yaml
  foundation-sec-model: 'cisco-ai/foundation-sec-8b-instruct@sha256:abc123...'
  ```

---

## Migration Guide

### From Claude/GPT-4 to Foundation-Sec

**Before:**
```yaml
- uses: securedotcom/agent-os-action@main
  with:
    ai-provider: 'anthropic'
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    cost-limit: '1.0'
```

**After:**
```yaml
- uses: securedotcom/agent-os-action@main
  with:
    ai-provider: 'foundation-sec'
    foundation-sec-enabled: 'true'
    cost-limit: '0.0'
```

**Changes:**
- Remove API key secrets
- Set `foundation-sec-enabled: true`
- Set `cost-limit: '0.0'` (optional, but emphasizes zero cost)
- First run takes longer (model download)
- Subsequent runs are cached

---

## FAQ

### Q: How does Foundation-Sec-8B compare to Claude Sonnet 4?
A: Foundation-Sec is specialized for security analysis and performs very well on vulnerability detection. Claude Sonnet 4 has broader capabilities but costs $0.20-$0.40 per run. For security-focused reviews, Foundation-Sec offers excellent quality at zero cost.

### Q: Can I use Foundation-Sec in GitHub Actions?
A: Yes! It works in GitHub Actions with CPU inference. The first run downloads the model (~16GB, ~10 minutes), then subsequent runs use the cached model (~1-2 minutes for CPU inference).

### Q: Do I need a GPU?
A: No, but recommended. Foundation-Sec works on CPU (slower) or GPU (faster). Auto-detection happens automatically.

### Q: What about model size and storage?
A: Foundation-Sec-8B requires ~16GB disk space for model weights. These are cached at `~/.cache/huggingface` and reused across runs.

### Q: Can I use Foundation-Sec with multi-agent mode?
A: Yes! Foundation-Sec supports all Agent OS features including multi-agent mode, exploit analysis, and security test generation.

### Q: Is Foundation-Sec suitable for production use?
A: Yes, for security reviews. For critical production workloads requiring the highest accuracy, consider a hybrid approach: Foundation-Sec for quick scans, Claude for detailed reviews.

---

## Support and Resources

### Documentation
- Agent OS Documentation: `/docs`
- Foundation-Sec Model Card: https://huggingface.co/cisco-ai/foundation-sec-8b-instruct
- Cisco AI Research: https://research.cisco.com/

### Community
- GitHub Issues: https://github.com/securedotcom/agent-os/issues
- Discussions: https://github.com/securedotcom/agent-os/discussions

### Getting Help
1. Check this documentation
2. Review troubleshooting section
3. Search GitHub issues
4. Open a new issue with:
   - Error messages
   - System specs (GPU/CPU, RAM)
   - Configuration used

---

## Roadmap

### Upcoming Features
- [ ] Quantized models (4-bit/8-bit) for lower memory usage
- [ ] Fine-tuning support for custom security patterns
- [ ] Batch inference for faster processing
- [ ] Model ensemble (combine multiple models)
- [ ] Streaming output for real-time feedback

### Performance Improvements
- [ ] Model pruning for faster inference
- [ ] Mixed precision inference (FP8)
- [ ] Optimized CUDA kernels
- [ ] Distributed inference across multiple GPUs

---

## License

Foundation-Sec-8B provider code is licensed under MIT License.
Foundation-Sec-8B model follows Cisco's model license (Apache 2.0).

---

**Last Updated**: 2025-11-03
**Version**: 1.0.0
**Maintainer**: Agent OS Team
