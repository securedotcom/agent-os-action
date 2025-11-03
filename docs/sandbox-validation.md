# Sandbox Validation System

> **🚧 BETA STATUS**: Sandbox validator is fully implemented (`scripts/sandbox_validator.py`, 672 LOC) but not yet integrated into the main review workflow.
>
> **Current Status**: Standalone validator works, workflow integration pending (~2 hours of work)
>
> **How to Use Today**: Run standalone: `python3 scripts/sandbox_validator.py exploit_file.py`

Adapted from [Strix](https://github.com/usestrix/strix)'s Docker sandbox for safe exploit validation in agent-os.

## Overview

The sandbox validation system provides a safe, isolated environment for validating security exploits discovered during code reviews. It uses Docker containers to ensure exploits cannot affect the host system.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Agent-OS Review                       │
│  ┌──────────────────────────────────────────────────┐  │
│  │  Security Agents (Finding Vulnerabilities)       │  │
│  └──────────────────────┬───────────────────────────┘  │
│                         │                               │
│                         ▼                               │
│  ┌──────────────────────────────────────────────────┐  │
│  │  Sandbox Integration                             │  │
│  │  - Convert findings to exploits                  │  │
│  │  - Schedule validations                          │  │
│  │  - Update metrics                                │  │
│  └──────────────────────┬───────────────────────────┘  │
│                         │                               │
│                         ▼                               │
│  ┌──────────────────────────────────────────────────┐  │
│  │  Sandbox Validator                               │  │
│  │  - Create exploit configs                        │  │
│  │  - Run safety checks                             │  │
│  │  - Analyze results                               │  │
│  └──────────────────────┬───────────────────────────┘  │
│                         │                               │
│                         ▼                               │
│  ┌──────────────────────────────────────────────────┐  │
│  │  Docker Manager                                  │  │
│  │  - Create isolated containers                    │  │
│  │  - Execute exploit code                          │  │
│  │  - Clean up resources                            │  │
│  └──────────────────────┬───────────────────────────┘  │
│                         │                               │
└─────────────────────────┼───────────────────────────────┘
                          │
                          ▼
        ┌─────────────────────────────────┐
        │  Docker Container (Isolated)    │
        │  - No network access            │
        │  - Limited CPU/memory           │
        │  - Multi-language support       │
        │  - Safe exploit execution       │
        └─────────────────────────────────┘
```

## Components

### 1. Docker Manager (`scripts/docker_manager.py`)

Manages Docker containers for exploit validation.

**Features:**
- Isolated container creation
- Multi-language support (Python, JavaScript, Java, Go)
- Resource limits (CPU, memory)
- Network isolation
- Safe cleanup

**Example:**
```python
from docker_manager import DockerManager

with DockerManager() as manager:
    # Create isolated container
    container_id = manager.create_container(
        name="sandbox-test",
        memory_limit="512m",
        cpu_limit=1.0,
        network_disabled=True,
    )

    # Execute code safely
    result = manager.execute_code(
        container_id,
        "print('Hello from sandbox!')",
        language="python",
        timeout=30,
    )

    print(result["stdout"])
    # Container is automatically cleaned up on exit
```

### 2. Sandbox Validator (`scripts/sandbox_validator.py`)

Validates security exploits in Docker containers.

**Features:**
- Exploit configuration and execution
- Safety checks (prevents dangerous code)
- Result analysis (indicator matching)
- Metrics tracking
- Multi-exploit batch validation

**Exploit Types Supported:**
- SQL Injection
- Command Injection
- Path Traversal
- XSS (Cross-Site Scripting)
- SSRF (Server-Side Request Forgery)
- Deserialization
- XXE (XML External Entity)
- Buffer Overflow
- Race Condition
- Authentication Bypass
- Privilege Escalation
- Information Disclosure
- Denial of Service

**Example:**
```python
from sandbox_validator import (
    SandboxValidator,
    ExploitConfig,
    ExploitType,
)

# Create exploit configuration
exploit = ExploitConfig(
    name="SQL Injection Test",
    exploit_type=ExploitType.SQL_INJECTION,
    language="python",
    code="""
import sqlite3
conn = sqlite3.connect(':memory:')
cursor = conn.cursor()
cursor.execute('CREATE TABLE users (id INTEGER, username TEXT)')
cursor.execute("INSERT INTO users VALUES (1, 'admin')")

# Test SQL injection
payload = "admin' OR '1'='1"
query = f"SELECT * FROM users WHERE username = '{payload}'"
cursor.execute(query)
results = cursor.fetchall()

if results:
    print("SQL_INJECTION_SUCCESS")
""",
    expected_indicators=["SQL_INJECTION_SUCCESS"],
    timeout=30,
)

# Validate exploit
validator = SandboxValidator()
result = validator.validate_exploit(exploit)

print(f"Result: {result.result}")
print(f"Indicators found: {result.indicators_found}")
```

### 3. Sandbox Integration (`scripts/sandbox_integration.py`)

Integrates sandbox validation with agent-os review system.

**Features:**
- Converts security findings to exploits
- Extends ReviewMetrics with sandbox data
- Auto-generates exploit code
- Filters high-severity findings

**Example:**
```python
from sandbox_integration import (
    validate_findings_in_sandbox,
    extend_review_metrics,
    update_sandbox_metrics,
)

# Example finding from security agent
findings = [
    {
        "issue_type": "SQL Injection",
        "severity": "critical",
        "description": "Vulnerable query in user search",
        "file": "src/api/users.py",
    }
]

# Validate in sandbox
results = validate_findings_in_sandbox(
    findings,
    project_root="/path/to/project",
    max_validations=10,
)

# Update metrics
metrics = {"version": "1.0.16"}
metrics = extend_review_metrics(metrics)
metrics = update_sandbox_metrics(metrics, results)

print(f"Validated: {metrics['sandbox_validation']['total_validations']}")
print(f"Exploitable: {metrics['sandbox_validation']['exploitable']}")
```

## Docker Image

The sandbox uses a custom Docker image built from `docker/security-sandbox.dockerfile`.

**Includes:**
- Ubuntu 22.04 base
- Python 3.x with common security testing libraries
- Node.js 20.x
- Java (OpenJDK 17)
- Go 1.21
- Common security tools (netcat, nmap, curl, etc.)
- Isolated sandbox user with limited privileges

**Building the Image:**
```bash
cd /path/to/agent-os
docker build -f docker/security-sandbox.dockerfile -t agent-os-sandbox:latest .
```

**Image Size:** ~2GB (includes all language runtimes and tools)

## Safety Features

### 1. Safety Checks

Before executing any exploit, the system performs safety checks:

- **Dangerous patterns detected:**
  - `rm -rf /` (filesystem deletion)
  - Fork bombs
  - Disk filling attacks
  - Remote code execution via wget/curl pipes
  - System shutdown/reboot commands

**Example:**
```python
# This exploit will be blocked
dangerous_exploit = ExploitConfig(
    name="Dangerous",
    exploit_type=ExploitType.CUSTOM,
    language="bash",
    code="rm -rf /",  # BLOCKED!
    expected_indicators=["SUCCESS"],
)

result = validator.validate_exploit(dangerous_exploit)
assert result.result == "unsafe"
```

### 2. Container Isolation

- **Network disabled:** No external network access
- **Resource limits:** CPU and memory capped
- **Process limits:** Maximum 100 processes
- **Read-only filesystem:** Except `/tmp` (100MB limit)
- **No privileged access:** Runs as non-root user

### 3. Automatic Cleanup

All containers are automatically cleaned up after validation:
- Timeout enforcement (default 30s)
- Graceful shutdown (5s grace period)
- Force removal if needed
- Resource deallocation

## Metrics

Sandbox validation extends ReviewMetrics with:

```json
{
  "sandbox_validation": {
    "enabled": true,
    "total_validations": 10,
    "exploitable": 7,
    "not_exploitable": 2,
    "partial": 0,
    "errors": 1,
    "timeouts": 0,
    "unsafe_skipped": 0,
    "total_execution_time_ms": 5420,
    "avg_execution_time_ms": 542,
    "success_rate_percent": 70.0,
    "validations_by_type": {
      "sql_injection": {
        "total": 4,
        "exploitable": 3
      },
      "command_injection": {
        "total": 3,
        "exploitable": 2
      },
      "path_traversal": {
        "total": 3,
        "exploitable": 2
      }
    }
  }
}
```

## Integration with Security-Test-Generator Agent

The sandbox system integrates with the `security-test-generator` agent:

1. **Agent discovers vulnerability** → Security finding created
2. **Sandbox integration** → Converts finding to exploit config
3. **Safety check** → Validates exploit is safe to run
4. **Docker execution** → Runs exploit in isolated container
5. **Result analysis** → Checks for expected indicators
6. **Metrics update** → Updates ReviewMetrics with results
7. **Report generation** → Includes validation results

### Agent Configuration

Update `profiles/default/agents/security-test-generator.md` to use sandbox:

```markdown
## Step 4: Validate Exploit PoC (NEW)

Use sandbox validation to test exploits safely:

1. Generate exploit code
2. Configure expected indicators
3. Submit to sandbox for validation
4. Include validation results in report

**Safety First:** All exploits run in isolated Docker containers with:
- No network access
- Limited resources
- Automatic cleanup
- Safety checks
```

## Usage Examples

### Example 1: Validate SQL Injection

```python
#!/usr/bin/env python3
from sandbox_validator import SandboxValidator, ExploitConfig, ExploitType

exploit = ExploitConfig(
    name="SQL Injection - User Search",
    exploit_type=ExploitType.SQL_INJECTION,
    language="python",
    code="""
import sqlite3

conn = sqlite3.connect(':memory:')
cursor = conn.cursor()
cursor.execute('CREATE TABLE users (id INTEGER, username TEXT, password TEXT)')
cursor.execute("INSERT INTO users VALUES (1, 'admin', 'secret123')")
conn.commit()

# Vulnerable query
username = "admin' OR '1'='1"
query = f"SELECT * FROM users WHERE username = '{username}'"

cursor.execute(query)
results = cursor.fetchall()

if len(results) > 0:
    print("SQL_INJECTION_SUCCESS")
    print(f"Extracted {len(results)} rows")
""",
    expected_indicators=["SQL_INJECTION_SUCCESS"],
    timeout=10,
)

validator = SandboxValidator()
result = validator.validate_exploit(exploit)

print(f"Result: {result.result}")
print(f"Execution time: {result.execution_time_ms}ms")
print(f"Indicators found: {result.indicators_found}")
```

### Example 2: Validate Multiple Exploits

```python
#!/usr/bin/env python3
from sandbox_validator import SandboxValidator, create_example_exploits

# Create example exploits
exploits = create_example_exploits()

# Validate all exploits
validator = SandboxValidator()
results = validator.validate_multiple(exploits, reuse_container=False)

# Print summary
summary = validator.get_metrics_summary()
print(f"Total: {summary['total_validations']}")
print(f"Success rate: {summary['success_rate']}%")
print(f"Avg time: {summary['avg_execution_time_ms']}ms")

# Export metrics
validator.export_metrics(".agent-os/sandbox-results/metrics.json")
```

### Example 3: Integration with Review System

```python
#!/usr/bin/env python3
from sandbox_integration import validate_findings_in_sandbox

# Security findings from agents
findings = [
    {
        "issue_type": "SQL Injection",
        "severity": "critical",
        "file": "src/api/users.py",
        "description": "Vulnerable query in user search",
    },
    {
        "issue_type": "Command Injection",
        "severity": "high",
        "file": "src/utils/exec.py",
        "description": "Unsanitized user input in shell command",
    },
]

# Validate findings
results = validate_findings_in_sandbox(
    findings,
    project_root="/path/to/project",
    max_validations=10,
)

# Print results
for result in results:
    print(f"\n{result.exploit_name}")
    print(f"  Result: {result.result}")
    print(f"  Time: {result.execution_time_ms}ms")
    print(f"  Indicators: {len(result.indicators_found)}/{len(result.indicators_found) + len(result.indicators_missing)}")
```

## Testing

Run unit tests:

```bash
# Run all sandbox tests
python -m pytest tests/unit/test_sandbox.py -v

# Run specific test class
python -m pytest tests/unit/test_sandbox.py::TestDockerManager -v

# Run with coverage
python -m pytest tests/unit/test_sandbox.py --cov=scripts --cov-report=html
```

## Troubleshooting

### Docker Not Available

**Error:** `Docker is not available or not running`

**Solution:**
1. Ensure Docker is installed: `docker --version`
2. Start Docker daemon: `sudo systemctl start docker` (Linux) or start Docker Desktop (Mac/Windows)
3. Verify access: `docker ps`

### Image Not Found

**Error:** `Image agent-os-sandbox:latest not found`

**Solution:**
```bash
# Build the image
cd /path/to/agent-os
docker build -f docker/security-sandbox.dockerfile -t agent-os-sandbox:latest .
```

### Container Creation Fails

**Error:** `Failed to create container`

**Possible causes:**
1. Insufficient resources (memory/CPU)
2. Port conflicts
3. Docker daemon issues

**Solutions:**
1. Increase Docker resource limits
2. Stop conflicting containers: `docker ps -a`
3. Restart Docker daemon
4. Check logs: `docker logs <container-id>`

### Exploit Timeout

**Error:** Result shows `timeout`

**Solutions:**
1. Increase timeout in ExploitConfig
2. Optimize exploit code
3. Check for infinite loops
4. Verify resource limits aren't too restrictive

### Safety Check Failed

**Error:** Result shows `unsafe`

**Solution:**
Review the exploit code for dangerous patterns. The safety check is intentional to prevent harmful exploits.

## Performance Considerations

### Container Creation Time

- **First container:** ~5-10 seconds (image pull + startup)
- **Subsequent containers:** ~2-3 seconds
- **Reusing containers:** ~0 seconds (recommended for batch validation)

### Exploit Execution Time

- **Simple exploits:** 100-500ms
- **Complex exploits:** 1-5 seconds
- **Network-based:** N/A (network disabled)

### Resource Usage

- **Memory per container:** 512MB (configurable)
- **CPU per container:** 1 core (configurable)
- **Disk per container:** 100MB /tmp
- **Max containers:** Limited by host resources

### Optimization Tips

1. **Reuse containers** for batch validation
2. **Limit validations** to high-severity findings
3. **Use timeouts** to prevent hanging
4. **Clean up** containers promptly
5. **Cache Docker images** locally

## Security Considerations

### Threats Mitigated

✅ **Container escape:** Disabled privileged mode, limited capabilities
✅ **Network attacks:** Network disabled by default
✅ **Resource exhaustion:** CPU/memory limits enforced
✅ **Filesystem damage:** Read-only filesystem (except /tmp)
✅ **Process bombing:** Process limits (max 100)
✅ **Dangerous code:** Safety checks before execution

### Threats NOT Mitigated

⚠️ **Docker daemon compromise:** Requires secure Docker installation
⚠️ **Host kernel exploits:** Use updated kernel versions
⚠️ **Side-channel attacks:** Out of scope for this system

### Best Practices

1. **Only validate on trusted systems** (not production servers)
2. **Review exploit code** before validation
3. **Monitor container resource usage**
4. **Keep Docker updated** to latest stable version
5. **Use separate Docker network** for sandbox
6. **Log all validations** for audit trail
7. **Limit concurrent containers** to prevent resource exhaustion

## License

This sandbox system is adapted from [Strix](https://github.com/usestrix/strix) (Apache 2.0 License) for use in agent-os.

## References

- [Strix GitHub Repository](https://github.com/usestrix/strix)
- [Docker Security Documentation](https://docs.docker.com/engine/security/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

## Future Enhancements

Potential improvements for future versions:

1. **Enhanced exploit templates** for more vulnerability types
2. **ML-based exploit generation** from vulnerability descriptions
3. **Distributed validation** across multiple hosts
4. **Real-time monitoring** of exploit execution
5. **Integration with CI/CD** pipelines
6. **Cloud provider support** (AWS ECS, Azure Container Instances)
7. **Result visualization** dashboard
8. **Automated fix validation** after patches applied

## Support

For issues or questions:
1. Check troubleshooting section above
2. Review Docker and Python logs
3. Consult Strix documentation for sandbox concepts
4. Submit issues to agent-os repository
