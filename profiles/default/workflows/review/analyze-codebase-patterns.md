# Codebase Pattern Analysis

## Step 1: Technology Stack Detection

### Framework and Language Detection
```bash
# Detect JavaScript/Node.js projects
if [ -f package.json ]; then
    echo "Node.js project detected"
    cat package.json | grep -E '"name"|"version"|"dependencies"'
fi

# Detect Python projects
if [ -f requirements.txt ] || [ -f setup.py ] || [ -f pyproject.toml ]; then
    echo "Python project detected"
    find . -name "*.py" | head -5
fi

# Detect Ruby projects
if [ -f Gemfile ]; then
    echo "Ruby project detected"
    cat Gemfile | head -10
fi

# Detect Java projects
if [ -f pom.xml ] || [ -f build.gradle ]; then
    echo "Java project detected"
    find . -name "*.java" | head -5
fi
```

### Database and ORM Detection
```bash
# Check for database configurations
grep -r "database\|db\|mysql\|postgres\|mongodb\|redis" --include="*.js" --include="*.py" --include="*.rb" . | head -10

# Look for ORM usage
grep -r "sequelize\|mongoose\|active_record\|django\|sqlalchemy" --include="*.js" --include="*.py" --include="*.rb" . | head -5
```

## Step 2: Architecture Pattern Analysis

### Project Structure Analysis
```bash
# Analyze directory structure
find . -type d -name "src" -o -name "lib" -o -name "app" -o -name "controllers" -o -name "models" -o -name "views" | head -10

# Check for common patterns
ls -la | grep -E "(src|lib|app|controllers|models|views|routes|middleware)"
```

### API and Service Patterns
```bash
# Look for API patterns
grep -r "app\.get\|app\.post\|app\.put\|app\.delete\|@RequestMapping\|@GetMapping" --include="*.js" --include="*.py" --include="*.rb" --include="*.java" . | head -10

# Check for service layer patterns
grep -r "service\|controller\|repository\|dao" --include="*.js" --include="*.py" --include="*.rb" . | head -10
```

## Step 3: Security Pattern Analysis

### Authentication Patterns
```bash
# Look for authentication implementations
grep -r "auth\|jwt\|session\|login\|passport" --include="*.js" --include="*.py" --include="*.rb" . | head -10

# Check for middleware patterns
grep -r "middleware\|before_action\|@require_auth" --include="*.js" --include="*.py" --include="*.rb" . | head -5
```

### Security Configuration
```bash
# Check for security configurations
grep -r "cors\|helmet\|csrf\|rate.*limit" --include="*.js" --include="*.py" --include="*.rb" . | head -5

# Look for environment variable usage
grep -r "process\.env\|ENV\|getenv\|os\.environ" --include="*.js" --include="*.py" --include="*.rb" . | head -10
```

## Step 4: Performance Pattern Analysis

### Database Query Patterns
```bash
# Look for database query patterns
grep -r "SELECT\|INSERT\|UPDATE\|DELETE\|find\|query" --include="*.js" --include="*.py" --include="*.rb" . | head -10

# Check for ORM usage patterns
grep -r "\.find\|\.create\|\.update\|\.delete" --include="*.js" --include="*.py" --include="*.rb" . | head -10
```

### Caching Patterns
```bash
# Look for caching implementations
grep -r "cache\|redis\|memcache\|lru" --include="*.js" --include="*.py" --include="*.rb" . | head -5
```

## Step 5: Testing Pattern Analysis

### Test Structure Analysis
```bash
# Find test files
find . -name "*test*" -o -name "*spec*" | head -10

# Check test frameworks
grep -r "describe\|it\|test\|assert\|expect" --include="*.js" --include="*.py" --include="*.rb" . | head -5
```

### Test Organization
```bash
# Analyze test organization
find . -name "*test*" -o -name "*spec*" | xargs ls -la | head -10

# Check for test utilities
grep -r "beforeEach\|afterEach\|setup\|teardown" --include="*.js" --include="*.py" --include="*.rb" . | head -5
```

## Step 6: Code Quality Pattern Analysis

### Linting and Formatting
```bash
# Check for linting configurations
find . -name ".eslintrc*" -o -name ".pylintrc" -o -name ".rubocop.yml" -o -name "prettier.config.*"

# Look for formatting tools
grep -r "prettier\|black\|rubocop\|eslint" --include="package.json" --include="requirements.txt" --include="Gemfile" .
```

### Documentation Patterns
```bash
# Check for documentation
find . -name "README*" -o -name "*.md" | head -5

# Look for inline documentation
grep -r "/\*\*\|#.*def\|#.*function" --include="*.js" --include="*.py" --include="*.rb" . | head -5
```

## Step 7: Dependency Analysis

### Package Dependencies
```bash
# Analyze package dependencies
if [ -f package.json ]; then
    echo "Node.js dependencies:"
    cat package.json | grep -A 20 '"dependencies"'
fi

if [ -f requirements.txt ]; then
    echo "Python dependencies:"
    cat requirements.txt
fi

if [ -f Gemfile ]; then
    echo "Ruby dependencies:"
    cat Gemfile
fi
```

### Security Dependencies
```bash
# Check for security-related packages
grep -r "bcrypt\|passport\|jwt\|helmet\|cors" --include="package.json" --include="requirements.txt" --include="Gemfile" .
```

## Step 8: Configuration Analysis

### Environment Configuration
```bash
# Check for configuration files
find . -name "*.env*" -o -name "config*" -o -name "settings*" | head -5

# Look for configuration patterns
grep -r "config\|settings\|environment" --include="*.js" --include="*.py" --include="*.rb" . | head -5
```

### Build and Deployment
```bash
# Check for build configurations
find . -name "Dockerfile" -o -name "docker-compose*" -o -name "*.yml" -o -name "*.yaml" | head -5

# Look for CI/CD configurations
find . -name ".github" -o -name ".gitlab-ci.yml" -o -name "Jenkinsfile" | head -5
```

## Pattern Analysis Output

Generate pattern analysis report with:

### Technology Stack
- **Primary Language:** [JavaScript/Python/Ruby/Java/Other]
- **Framework:** [Express/Django/Rails/Spring/Other]
- **Database:** [PostgreSQL/MySQL/MongoDB/Redis/Other]
- **Testing Framework:** [Jest/pytest/RSpec/JUnit/Other]

### Architecture Patterns
- **Project Structure:** [MVC/Microservices/Monolith/Other]
- **API Design:** [REST/GraphQL/RPC/Other]
- **Data Layer:** [ORM/Active Record/Repository/Other]

### Security Patterns
- **Authentication:** [JWT/Session/OAuth/Other]
- **Authorization:** [RBAC/ABAC/Other]
- **Security Middleware:** [CORS/Helmet/CSRF/Other]

### Performance Patterns
- **Database:** [Query optimization/Caching/Indexing]
- **Caching:** [Redis/Memcached/Application-level]
- **Monitoring:** [Logging/Metrics/Tracing]

### Quality Patterns
- **Linting:** [ESLint/Pylint/RuboCop/Other]
- **Formatting:** [Prettier/Black/RuboCop/Other]
- **Testing:** [Unit/Integration/E2E/Other]

### Recommendations
- **Security:** [Specific security improvements needed]
- **Performance:** [Performance optimization opportunities]
- **Testing:** [Test coverage and quality improvements]
- **Quality:** [Code quality and maintainability improvements]
