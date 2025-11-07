# Scan Repository Workflow

This workflow analyzes the target repository to discover its structure, components, and dependencies.

## Prerequisites

- Access to target repository
- Read permissions for all directories
- Git installed (for git blame analysis)

## Workflow Steps

### 1. Initialize Scan

**Objective**: Set up scanning environment and load configuration

**Actions**:
1. Load configuration from `config.yml` or `docs.agent.config.json`
2. Determine target repository path
3. Create output directory for scan results
4. Initialize scan metadata

**Output**:
- Scan session ID
- Timestamp
- Configuration loaded

### 2. Project Structure Analysis

**Objective**: Identify project type, languages, and directory structure

**Actions**:
1. Detect project type (monorepo vs single-repo)
2. Identify primary and secondary languages
3. Map directory structure
4. Find entry points and main modules

**Tools**:
```bash
# Detect languages
find . -name "*.ts" -o -name "*.js" -o -name "*.py" -o -name "*.go" | head -20

# Find package files
find . -name "package.json" -o -name "requirements.txt" -o -name "go.mod"

# Identify entry points
grep -r "main\|index\|app" --include="*.ts" --include="*.py" --include="*.go"
```

**Output**:
- Project type
- Languages used
- Directory structure
- Entry points

### 3. Component Discovery

**Objective**: Identify services, modules, and components

**Actions**:
1. Scan for services (in `services/`, `apps/`, `packages/`)
2. Identify component boundaries
3. Detect component types (backend, frontend, library)
4. Find component entry points

**Patterns to Look For**:
- Service directories with their own `package.json`
- Microservice patterns
- Module boundaries
- Component naming conventions

**Output**:
- List of components with:
  - Name
  - Type
  - Path
  - Language
  - Framework
  - Entry point

### 4. Dependency Analysis

**Objective**: Map external and internal dependencies

**Actions**:
1. Parse dependency files (`package.json`, `requirements.txt`, etc.)
2. Identify internal dependencies (between components)
3. Detect external service dependencies
4. Find shared libraries

**Tools**:
```bash
# Node.js dependencies
cat package.json | jq '.dependencies'

# Python dependencies
cat requirements.txt

# Go dependencies
cat go.mod
```

**Output**:
- External dependencies with versions
- Internal component dependencies
- Shared library usage

### 5. Infrastructure Discovery

**Objective**: Identify infrastructure configuration and deployment setup

**Actions**:
1. Find Docker files and compose configurations
2. Locate Kubernetes manifests
3. Identify IaC files (Terraform, CloudFormation)
4. Detect CI/CD configurations

**Locations to Check**:
- `Dockerfile*`, `docker-compose*.yml`
- `k8s/`, `kubernetes/`, `helm/`
- `terraform/`, `*.tf`
- `.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`

**Output**:
- Containerization strategy
- Orchestration platform
- Cloud provider
- CI/CD tools

### 6. Data Layer Analysis

**Objective**: Identify databases, caches, and message queues

**Actions**:
1. Find database configuration
2. Locate migration files
3. Identify cache usage
4. Detect message queue integration

**Indicators**:
- Database client libraries in dependencies
- Migration directories
- Cache configuration
- Queue client usage

**Output**:
- Database type and configuration
- Cache systems
- Message queues
- Data stores

### 7. External Integration Detection

**Objective**: Identify third-party services and APIs

**Actions**:
1. Search for API client libraries
2. Find SDK imports
3. Locate configuration keys for external services
4. Identify webhook handlers

**Common Integrations**:
- Payment processors (Stripe, PayPal)
- Auth providers (Auth0, Okta)
- Email/SMS (SendGrid, Twilio)
- Analytics (Google Analytics, Mixpanel)
- Monitoring (Datadog, New Relic)

**Output**:
- List of external services
- Integration points
- Configuration requirements

### 8. ML/AI Component Detection

**Objective**: Identify machine learning components if present

**Actions**:
1. Look for ML framework imports
2. Find model files
3. Locate training scripts
4. Identify notebooks

**Indicators**:
- `*.ipynb` notebooks
- ML framework imports (TensorFlow, PyTorch, scikit-learn)
- Model directories
- Training configuration

**Output**:
- ML frameworks used
- Model files
- Training scripts
- Dataset references

**Conditional**: Only execute if ML indicators found

### 9. Configuration Analysis

**Objective**: Catalog configuration files and environment variables

**Actions**:
1. Find all configuration files
2. Extract environment variable names
3. Identify feature flags
4. Document configuration patterns

**Locations**:
- `config/`, `*.config.js`, `*.yml`
- `.env.example`, `.env.template`
- Environment variable usage in code

**Output**:
- Configuration file list
- Environment variable catalog
- Feature flags

**Security**: Never expose actual secret values

### 10. Generate Scan Report

**Objective**: Compile all findings into structured output

**Actions**:
1. Aggregate all scan results
2. Generate JSON output
3. Save to `docs/.docs-metadata.json`
4. Create human-readable summary

**Output Format**:
```json
{
  "scan_timestamp": "2024-11-07T10:30:00Z",
  "repository": {
    "name": "project-name",
    "type": "monorepo|single-repo",
    "primary_language": "typescript"
  },
  "components": [...],
  "infrastructure": {...},
  "data_stores": [...],
  "external_services": [...],
  "ml_components": {...},
  "config_files": [...]
}
```

### 11. Incremental Scan Setup

**Objective**: Prepare for future incremental scans

**Actions**:
1. Calculate file hashes for key files
2. Store component-to-file mappings
3. Create change detection baseline
4. Save incremental scan metadata

**Output**:
```json
{
  "last_scan": "2024-11-07T10:30:00Z",
  "file_hashes": {
    "services/api/src/index.ts": "abc123...",
    "services/auth/main.go": "def456..."
  },
  "component_files": {
    "api-service": ["services/api/**"],
    "auth-service": ["services/auth/**"]
  }
}
```

## Error Handling

### Inaccessible Files
- Log warning
- Continue with available files
- Mark component as incomplete

### Malformed Configuration
- Attempt to parse with fallbacks
- Log error details
- Use default values where possible

### Permission Denied
- Log error
- Skip protected directories
- Note in scan report

## Output Files

1. `docs/.docs-metadata.json` - Complete scan results
2. `docs/.scan-log.txt` - Detailed scan log
3. `docs/.file-hashes.json` - File hashes for incremental updates

## Next Steps

After successful scan:
1. Review scan results
2. Proceed to documentation generation workflows
3. Use scan data for architecture docs, ADRs, etc.

## Usage

### With Claude Code

```
Run the scan-repository workflow to analyze this codebase
```

### Manual Invocation

```bash
# From project root
~/agent-doc-creator/workflows/scan-repository.sh
```

## Configuration Options

From `config.yml`:

```yaml
scan:
  exclude_dirs:
    - node_modules
    - .git
    - dist
    - build
  max_file_size: 1048576  # 1MB
  follow_symlinks: false
```

