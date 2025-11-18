#!/bin/bash

# Detect project type based on files in the repository
# Usage: detect-project-type.sh <project-path>

PROJECT_PATH="${1:-.}"

cd "$PROJECT_PATH" || exit 1

# Check for backend API indicators
if [ -f "pom.xml" ] || [ -f "build.gradle" ] || [ -f "build.gradle.kts" ]; then
  echo "backend-api"
  exit 0
fi

if [ -f "package.json" ]; then
  # Check if it's a frontend framework
  if grep -q '"react"\|"vue"\|"angular"\|"next"\|"nuxt"' package.json 2>/dev/null; then
    echo "dashboard-ui"
    exit 0
  fi
  # Check if it's a backend framework
  if grep -q '"express"\|"fastify"\|"koa"\|"hapi"\|"nest"' package.json 2>/dev/null; then
    echo "backend-api"
    exit 0
  fi
fi

if [ -f "requirements.txt" ] || [ -f "setup.py" ] || [ -f "pyproject.toml" ]; then
  # Check if it's Django/Flask
  if grep -q "django\|flask\|fastapi\|tornado" requirements.txt 2>/dev/null || \
     grep -q "django\|flask\|fastapi\|tornado" setup.py 2>/dev/null || \
     grep -q "django\|flask\|fastapi\|tornado" pyproject.toml 2>/dev/null; then
    echo "backend-api"
    exit 0
  fi
fi

if [ -f "go.mod" ]; then
  if grep -q "gin\|echo\|fiber\|chi" go.mod 2>/dev/null; then
    echo "backend-api"
    exit 0
  fi
fi

# Check for data pipeline indicators
if [ -f "airflow.cfg" ] || [ -f "dbt_project.yml" ] || [ -d "spark" ]; then
  echo "data-pipeline"
  exit 0
fi

# Check for infrastructure indicators
if find . -name "*.tf" -type f | head -1 | grep -q . || \
   find . -name "*.tfvars" -type f | head -1 | grep -q . || \
   [ -d "k8s" ] || [ -d "kubernetes" ] || \
   find . -name "ansible" -type d | head -1 | grep -q .; then
  echo "infrastructure"
  exit 0
fi

# Check for frontend indicators
if [ -f "next.config.js" ] || [ -f "next.config.ts" ] || \
   [ -f "nuxt.config.js" ] || [ -f "nuxt.config.ts" ] || \
   [ -f "vite.config.js" ] || [ -f "vite.config.ts" ] || \
   [ -d "src" ] && [ -f "src/index.html" ]; then
  echo "dashboard-ui"
  exit 0
fi

# Default to backend-api if we can't determine
echo "backend-api"











