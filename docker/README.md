# Agent-OS Docker Sandbox

Docker configuration for safe exploit validation.

## Quick Start

### 1. Build the Sandbox Image

```bash
docker build -f docker/security-sandbox.dockerfile -t agent-os-sandbox:latest .
```

This creates an isolated container with:
- Python 3.x
- Node.js 20.x
- Java (OpenJDK 17)
- Go 1.21
- Common security testing tools

**Build time:** ~5-10 minutes
**Image size:** ~2GB

### 2. Verify the Image

```bash
docker images | grep agent-os-sandbox
```

You should see:
```
agent-os-sandbox   latest   <image-id>   <time>   ~2GB
```

### 3. Test the Sandbox

```bash
# Run sample exploit validation
python3 scripts/validate_sample_exploit.py
```

This will:
1. Check Docker availability
2. Create an isolated container
3. Execute a safe SQL injection PoC
4. Analyze results
5. Generate metrics
6. Clean up resources

## Manual Testing

Test the container manually:

```bash
# Start container
docker run -it --rm \
  --network none \
  --memory 512m \
  --cpus 1.0 \
  agent-os-sandbox:latest

# Inside container
sandbox@container:/workspace$ python3 --version
sandbox@container:/workspace$ node --version
sandbox@container:/workspace$ java --version
sandbox@container:/workspace$ go version
```

## Integration

Use the sandbox in your code:

```python
from scripts.docker_manager import DockerManager
from scripts.sandbox_validator import SandboxValidator, ExploitConfig, ExploitType

# Create validator
validator = SandboxValidator()

# Define exploit
exploit = ExploitConfig(
    name="SQL Injection Test",
    exploit_type=ExploitType.SQL_INJECTION,
    language="python",
    code="...",
    expected_indicators=["SUCCESS"],
)

# Validate
result = validator.validate_exploit(exploit)
print(f"Result: {result.result}")
```

## Security

The sandbox provides:
- ✓ Network isolation (--network none)
- ✓ Resource limits (CPU, memory)
- ✓ Process limits (max 100)
- ✓ Non-root user
- ✓ Read-only filesystem (except /tmp)
- ✓ Automatic cleanup

## Troubleshooting

### Docker Not Available

```bash
# Check Docker is running
docker ps

# On Linux
sudo systemctl start docker

# On Mac/Windows
# Start Docker Desktop
```

### Image Build Fails

```bash
# Clean Docker cache
docker system prune -a

# Rebuild with no cache
docker build --no-cache -f docker/security-sandbox.dockerfile -t agent-os-sandbox:latest .
```

### Container Creation Fails

```bash
# Check available resources
docker info | grep -A 5 "Memory\|CPUs"

# Remove old containers
docker container prune -f
```

## Documentation

See full documentation:
- [Sandbox Validation Guide](../docs/sandbox-validation.md)
- [Strix Project (upstream)](https://github.com/usestrix/strix)

## License

Adapted from [Strix](https://github.com/usestrix/strix) (Apache 2.0 License)
