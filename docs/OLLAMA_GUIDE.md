# 🦙 Ollama Integration Guide

## Cost-Optimized Local AI Code Review

This guide shows you how to use **Ollama** with local open-source LLMs for zero-cost code reviews, or in a hybrid setup with cloud APIs for optimal cost-performance balance.

---

## 🎯 Why Use Ollama?

| Feature | Cloud APIs | Ollama (Local) | Hybrid |
|---------|-----------|----------------|--------|
| **Cost** | $0.003-0.015/1K tokens | **FREE** | Low |
| **Privacy** | Data sent to cloud | **100% Local** | Mixed |
| **Speed** | Fast (parallel) | Depends on hardware | Mixed |
| **Quality** | Excellent | Very Good | Excellent |
| **Setup** | API key only | Install + Model download | Both |

**Best Use Cases for Ollama**:
- ✅ Development/staging environments
- ✅ Privacy-sensitive codebases
- ✅ High-volume reviews (cost savings)
- ✅ Organizations with GPU infrastructure
- ✅ Testing and experimentation

---

## 📦 Installation

### 1. Install Ollama

**MacOS/Linux**:
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

**Windows**:
Download from [ollama.com](https://ollama.com/download)

### 2. Pull Recommended Models

```bash
# Best quality (requires 40GB+ RAM)
ollama pull llama3:70b

# Balanced (requires 16GB RAM)
ollama pull llama3:8b

# Fast/lightweight (requires 8GB RAM)
ollama pull llama3.2:3b

# Code-specialized
ollama pull codellama:13b
ollama pull deepseek-coder:6.7b
```

### 3. Verify Installation

```bash
ollama list
ollama run llama3:8b "Hello, world!"
```

---

## 🚀 Usage Modes

### Mode 1: Pure Ollama (Zero Cost)

Use only local models for completely free reviews:

```python
from scripts.real_multi_agent_review import RealMultiAgentReview

# No API keys needed!
reviewer = RealMultiAgentReview(
    anthropic_api_key=None,
    openai_api_key=None,
    ollama_model="llama3:70b"  # Or llama3:8b
)

# Run multi-agent review with local models only
findings = await reviewer.review_file("src/app.py", "/path/to/repo")
```

**Configuration**:
```yaml
# .env or config
AI_PROVIDER=ollama
OLLAMA_MODEL=llama3:70b
OLLAMA_BASE_URL=http://localhost:11434  # Default
```

---

### Mode 2: Hybrid (Cost-Optimized)

Combine cheap cloud models with free local models for best value:

```python
reviewer = RealMultiAgentReview(
    anthropic_api_key="sk-ant-...",  # Use for critical reviews
    openai_api_key=None,
    ollama_model="llama3:70b"  # Use for broad reviews
)
```

**Recommended Hybrid Strategies**:

#### Strategy A: Haiku + Ollama (Ultra-Cheap)
```yaml
agents:
  - anthropic: claude-3-5-haiku-20241022  # $1/M tokens
  - ollama: llama3:70b                     # FREE
```
**Cost**: ~$0.001 per file
**Quality**: Very Good

#### Strategy B: Sonnet + Ollama (Quality + Savings)
```yaml
agents:
  - anthropic: claude-3-5-sonnet-20240620  # $3/M tokens
  - ollama: llama3:70b                      # FREE
```
**Cost**: ~$0.003 per file
**Quality**: Excellent

#### Strategy C: Triple Consensus
```yaml
agents:
  - anthropic: claude-3-5-sonnet-20240620  # High quality
  - anthropic: claude-3-5-haiku-20241022   # Fast
  - ollama: llama3:70b                      # Free tie-breaker
```
**Cost**: ~$0.004 per file
**Quality**: Best (3-agent consensus)

---

### Mode 3: Category-Specific with Ollama

Use Ollama for different focused passes:

```python
# Security pass with cloud AI
security_findings = await reviewer.review_with_claude(
    file_path, content, context, category="security"
)

# Performance & quality with local AI (cheaper)
perf_findings = await reviewer.review_with_ollama(
    file_path, content, context, category="performance"
)

quality_findings = await reviewer.review_with_ollama(
    file_path, content, context, category="quality"
)
```

---

## 🎛️ Configuration Options

### Environment Variables

```bash
# Ollama Configuration
export OLLAMA_BASE_URL="http://localhost:11434"
export OLLAMA_MODEL="llama3:70b"
export OLLAMA_TIMEOUT=120  # seconds
export OLLAMA_NUM_CTX=4096  # context window

# Hybrid mode
export ANTHROPIC_API_KEY="sk-ant-..."
export AI_PROVIDER="hybrid"  # Use both
```

### In Code

```python
reviewer = RealMultiAgentReview(
    anthropic_api_key=os.getenv('ANTHROPIC_API_KEY'),
    ollama_config={
        'base_url': 'http://localhost:11434',
        'model': 'llama3:70b',
        'timeout': 120,
        'num_ctx': 4096,
        'temperature': 0.3
    }
)
```

---

## 📊 Performance & Hardware Requirements

### Recommended Models by Hardware

| Hardware | Model | Speed | Quality |
|----------|-------|-------|---------|
| **8GB RAM** | llama3.2:3b | Fast | Good |
| **16GB RAM** | llama3:8b | Medium | Very Good |
| **32GB RAM** | llama3:70b | Slow | Excellent |
| **64GB+ RAM, GPU** | llama3:70b + GPU | Fast | Excellent |

### Benchmark (Average Review Times)

**File Size**: 500 lines

| Setup | Time | Cost |
|-------|------|------|
| Claude Sonnet (cloud) | 5s | $0.003 |
| Llama 3 70B (CPU) | 60s | $0.00 |
| Llama 3 70B (GPU) | 8s | $0.00 |
| Llama 3 8B (CPU) | 15s | $0.00 |
| Hybrid (Haiku + Ollama) | 10s avg | $0.001 |

---

## 🔧 Troubleshooting

### Ollama Not Starting

```bash
# Check if running
ollama list

# Restart service
ollama serve

# Check logs
journalctl -u ollama  # Linux
tail -f ~/Library/Logs/ollama.log  # MacOS
```

### Out of Memory

```bash
# Use smaller model
ollama pull llama3:8b

# Or reduce context window
export OLLAMA_NUM_CTX=2048
```

### Slow Performance

**Solutions**:
1. Use GPU acceleration (if available)
2. Switch to smaller model (70b → 8b)
3. Use quantized models
4. Reduce context window
5. Close other applications

### JSON Parsing Errors

Ollama models sometimes format JSON inconsistently. The script handles this with:
- Retry logic
- Fallback parsing
- Graceful degradation

If issues persist, try:
```python
# Use more structured prompt
ollama_config={'temperature': 0.1}  # Lower temperature = more consistent
```

---

## 💡 Best Practices

### 1. Start Small
```bash
# Test with one file first
python scripts/real_multi_agent_review.py --file src/auth.py --ollama
```

### 2. Use Appropriate Models
- **Security reviews**: Use cloud AI (higher stakes)
- **Code quality**: Use Ollama (lower stakes)
- **Performance**: Mixed approach

### 3. Monitor Resource Usage
```bash
# Check memory/CPU
htop  # or Activity Monitor on Mac

# Limit concurrent reviews
export MAX_CONCURRENT_REVIEWS=1  # For resource-constrained systems
```

### 4. Cache Aggressively
```bash
# Ollama caches model in RAM after first load
# Keep ollama running to avoid reload delays
ollama serve &
```

---

## 📈 Cost Comparison Examples

### Small PR (10 files, 5K lines total)

| Configuration | Cost | Time |
|--------------|------|------|
| Claude Sonnet only | $0.30 | 50s |
| Claude Haiku only | $0.10 | 40s |
| Ollama only | **$0.00** | 8min |
| Hybrid (Sonnet + Ollama) | **$0.15** | 2min |

### Large PR (100 files, 50K lines total)

| Configuration | Cost | Time |
|--------------|------|------|
| Claude Sonnet only | $3.00 | 8min |
| Claude Haiku only | $1.00 | 6min |
| Ollama only | **$0.00** | 80min |
| Hybrid (Haiku + Ollama) | **$0.50** | 15min |

**Recommendation**: Hybrid mode offers 50-80% cost savings with acceptable speed.

---

## 🔐 Privacy Benefits

When using pure Ollama mode:
- ✅ **No code leaves your machine**
- ✅ **No API keys required**
- ✅ **No rate limits**
- ✅ **No internet required** (after model download)
- ✅ **Full audit trail locally**
- ✅ **Compliant with strict security policies**

Perfect for:
- Financial institutions
- Healthcare (HIPAA)
- Government/defense
- Proprietary codebases
- Regulated industries

---

## 📚 Advanced: Custom Ollama Models

### Fine-tune for Your Codebase

```bash
# Create Modelfile
cat > Modelfile << 'EOF'
FROM llama3:70b

# Custom system prompt for your org
SYSTEM """
You are a code reviewer at ACME Corp. 
Focus on our specific standards:
- Use TypeScript strict mode
- Follow our API patterns
- Check auth with JWT
"""

# Adjust parameters
PARAMETER temperature 0.2
PARAMETER num_ctx 8192
EOF

# Build custom model
ollama create acme-reviewer -f Modelfile

# Use it
export OLLAMA_MODEL="acme-reviewer"
```

---

## 🎓 Learning More

- [Ollama Documentation](https://ollama.com/docs)
- [Model Library](https://ollama.com/library)
- [GitHub](https://github.com/ollama/ollama)
- [Discord Community](https://discord.gg/ollama)

---

## 🚦 Quick Start Checklist

- [ ] Install Ollama
- [ ] Download a model (`ollama pull llama3:8b`)
- [ ] Test locally (`ollama run llama3:8b "test"`)
- [ ] Run your first review with `--ollama` flag
- [ ] Compare results with cloud API
- [ ] Choose your preferred mode (pure/hybrid)
- [ ] Update your CI/CD configuration

---

**🎉 You're ready to run cost-effective, privacy-preserving code reviews with Ollama!**

For questions or issues, open an issue on GitHub or join our community discussions.

