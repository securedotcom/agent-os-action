#!/bin/bash
# Agent-OS Complete 6-Phase Security Scanner
# Quick scan script for any repository

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}   Agent-OS Complete 6-Phase Security Scanner${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}❌ Error: Docker is not running${NC}"
    echo -e "${YELLOW}Please start Docker and try again${NC}"
    exit 1
fi

# Check for required environment variables
if [ -z "$ANTHROPIC_API_KEY" ] && [ -z "$OPENAI_API_KEY" ]; then
    echo -e "${RED}❌ Error: No AI API key found${NC}"
    echo -e "${YELLOW}Please set ANTHROPIC_API_KEY or OPENAI_API_KEY:${NC}"
    echo -e "  export ANTHROPIC_API_KEY=your-key-here"
    exit 1
fi

# Parse arguments
TARGET_REPO="${1:-.}"
OUTPUT_DIR="${2:-./output}"

if [ "$TARGET_REPO" = "--help" ] || [ "$TARGET_REPO" = "-h" ]; then
    echo ""
    echo "Usage: $0 [target_repo] [output_dir]"
    echo ""
    echo "Examples:"
    echo "  $0                              # Scan current directory"
    echo "  $0 /path/to/repo               # Scan specific repository"
    echo "  $0 /path/to/repo /path/output  # Scan with custom output directory"
    echo ""
    echo "Environment Variables:"
    echo "  ANTHROPIC_API_KEY - Claude API key (required)"
    echo "  OPENAI_API_KEY    - OpenAI API key (alternative)"
    echo ""
    exit 0
fi

# Convert to absolute paths
TARGET_REPO=$(cd "$TARGET_REPO" && pwd)
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR=$(cd "$OUTPUT_DIR" && pwd)

echo -e "${GREEN}✅ Docker is running${NC}"
echo -e "${GREEN}✅ AI API key configured${NC}"
echo -e "${BLUE}📁 Target: $TARGET_REPO${NC}"
echo -e "${BLUE}📄 Output: $OUTPUT_DIR${NC}"
echo ""

# Build image if it doesn't exist
if [[ "$(docker images -q agent-os-scanner:latest 2> /dev/null)" == "" ]]; then
    echo -e "${YELLOW}🏗️  Building Agent-OS scanner image (first time only)...${NC}"
    docker-compose build
    echo -e "${GREEN}✅ Image built successfully${NC}"
    echo ""
fi

# Run the scan
echo -e "${BLUE}🔍 Starting 6-Phase Security Scan...${NC}"
echo ""

docker run --rm \
    -v "$TARGET_REPO:/workspace:ro" \
    -v "$OUTPUT_DIR:/output" \
    -v "$OUTPUT_DIR/.cache:/cache" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
    -e OPENAI_API_KEY="$OPENAI_API_KEY" \
    -e ENABLE_REMEDIATION=true \
    -e ENABLE_THREAT_INTEL=true \
    agent-os-scanner:latest \
    /workspace \
    --enable-ai-enrichment \
    --ai-provider anthropic \
    --enable-semgrep \
    --enable-trivy \
    --enable-checkov \
    --enable-api-security \
    --enable-supply-chain \
    --enable-threat-intel \
    --enable-remediation \
    --enable-regression-testing \
    --output-dir /output

EXIT_CODE=$?

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✅ Scan completed successfully!${NC}"
    echo -e "${BLUE}📊 Results saved to: $OUTPUT_DIR${NC}"
else
    echo -e "${RED}❌ Scan failed with exit code $EXIT_CODE${NC}"
fi

exit $EXIT_CODE
