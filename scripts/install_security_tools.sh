#!/bin/bash
#
# Install Security Tools for Hybrid Analyzer
# Installs: Semgrep, Trivy, and optionally Foundation-Sec-8B
#
# Usage:
#   ./install_security_tools.sh [--foundation-sec] [--skip-trivy] [--skip-semgrep]
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse arguments
INSTALL_FOUNDATION_SEC=false
INSTALL_TRIVY=true
INSTALL_SEMGREP=true

while [[ $# -gt 0 ]]; do
    case $1 in
        --foundation-sec)
            INSTALL_FOUNDATION_SEC=true
            shift
            ;;
        --skip-trivy)
            INSTALL_TRIVY=false
            shift
            ;;
        --skip-semgrep)
            INSTALL_SEMGREP=false
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --foundation-sec    Install Foundation-Sec-8B model (~16GB)"
            echo "  --skip-trivy        Skip Trivy installation"
            echo "  --skip-semgrep      Skip Semgrep installation"
            echo "  -h, --help          Show this help message"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║    Security Tools Installation for Hybrid Analyzer            ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}📦 Will install:${NC}"
[[ "$INSTALL_SEMGREP" == "true" ]] && echo "   ✅ Semgrep (SAST)"
[[ "$INSTALL_TRIVY" == "true" ]] && echo "   ✅ Trivy (CVE Scanner)"
[[ "$INSTALL_FOUNDATION_SEC" == "true" ]] && echo "   ✅ Foundation-Sec-8B (~16GB)"
echo ""

# Detect OS
OS="unknown"
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
else
    echo -e "${YELLOW}⚠️  Warning: Unsupported OS: $OSTYPE${NC}"
    echo "   Continuing anyway..."
fi

echo -e "${BLUE}🖥️  Detected OS: $OS${NC}"
echo ""

# Function: Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function: Install Semgrep
install_semgrep() {
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}1. Installing Semgrep${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    if command_exists semgrep; then
        SEMGREP_VERSION=$(semgrep --version 2>&1 | head -1)
        echo -e "${YELLOW}⚠️  Semgrep already installed: $SEMGREP_VERSION${NC}"
        echo "   Skipping installation"
        return 0
    fi
    
    echo "📥 Installing Semgrep via pip..."
    
    # Install via pip
    if command_exists pip3; then
        pip3 install semgrep
    elif command_exists pip; then
        pip install semgrep
    else
        echo -e "${RED}❌ Error: pip not found. Please install Python and pip first.${NC}"
        return 1
    fi
    
    # Verify installation
    if command_exists semgrep; then
        SEMGREP_VERSION=$(semgrep --version 2>&1 | head -1)
        echo -e "${GREEN}✅ Semgrep installed successfully: $SEMGREP_VERSION${NC}"
    else
        echo -e "${RED}❌ Error: Semgrep installation failed${NC}"
        return 1
    fi
    
    echo ""
}

# Function: Install Trivy
install_trivy() {
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}2. Installing Trivy${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    if command_exists trivy; then
        TRIVY_VERSION=$(trivy --version 2>&1 | head -1)
        echo -e "${YELLOW}⚠️  Trivy already installed: $TRIVY_VERSION${NC}"
        echo "   Skipping installation"
        return 0
    fi
    
    echo "📥 Installing Trivy..."
    
    if [[ "$OS" == "linux" ]]; then
        # Linux installation
        curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
    elif [[ "$OS" == "macos" ]]; then
        # macOS installation
        if command_exists brew; then
            echo "   Using Homebrew..."
            brew install trivy
        else
            echo "   Homebrew not found, using install script..."
            curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
        fi
    else
        # Fallback: Use install script
        curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
    fi
    
    # Verify installation
    if command_exists trivy; then
        TRIVY_VERSION=$(trivy --version 2>&1 | head -1)
        echo -e "${GREEN}✅ Trivy installed successfully: $TRIVY_VERSION${NC}"
        
        # Initialize Trivy DB
        echo "📦 Updating Trivy vulnerability database..."
        trivy image --download-db-only
        echo -e "${GREEN}✅ Trivy database updated${NC}"
    else
        echo -e "${RED}❌ Error: Trivy installation failed${NC}"
        return 1
    fi
    
    echo ""
}

# Function: Install Foundation-Sec-8B
install_foundation_sec() {
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}3. Installing Foundation-Sec-8B${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    echo -e "${YELLOW}⚠️  WARNING: Foundation-Sec-8B is ~16GB and requires:${NC}"
    echo "   - 16GB+ disk space"
    echo "   - 8GB+ RAM (16GB+ recommended)"
    echo "   - GPU recommended (NVIDIA CUDA) but CPU works"
    echo ""
    
    read -p "Continue with installation? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "   Skipping Foundation-Sec-8B installation"
        return 0
    fi
    
    echo "📦 Installing Python dependencies..."
    
    # Check if pip is available
    if command_exists pip3; then
        PIP_CMD="pip3"
    elif command_exists pip; then
        PIP_CMD="pip"
    else
        echo -e "${RED}❌ Error: pip not found${NC}"
        return 1
    fi
    
    # Install transformers and PyTorch
    echo "   Installing transformers..."
    $PIP_CMD install transformers>=4.30.0 --quiet
    
    echo "   Installing torch..."
    # Detect CUDA
    if command_exists nvidia-smi; then
        echo "   GPU detected, installing PyTorch with CUDA support..."
        $PIP_CMD install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118 --quiet
    else
        echo "   No GPU detected, installing PyTorch (CPU-only)..."
        $PIP_CMD install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu --quiet
    fi
    
    echo "   Installing accelerate..."
    $PIP_CMD install accelerate>=0.20.0 --quiet
    
    echo -e "${GREEN}✅ Dependencies installed${NC}"
    
    # Download model
    echo "📥 Downloading Foundation-Sec-8B model (~16GB)..."
    echo "   This may take 10-30 minutes depending on your connection..."
    
    python3 << 'EOF'
from transformers import AutoModelForCausalLM, AutoTokenizer
import sys

try:
    print("   Downloading tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained("fdtn-ai/Foundation-Sec-8B")
    
    print("   Downloading model weights...")
    model = AutoModelForCausalLM.from_pretrained("fdtn-ai/Foundation-Sec-8B")
    
    print("   ✅ Model downloaded successfully!")
    sys.exit(0)
except Exception as e:
    print(f"   ❌ Error downloading model: {e}")
    sys.exit(1)
EOF
    
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}✅ Foundation-Sec-8B installed successfully${NC}"
    else
        echo -e "${RED}❌ Foundation-Sec-8B installation failed${NC}"
        return 1
    fi
    
    echo ""
}

# Function: Verify installations
verify_installations() {
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}✅ Installation Verification${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    ALL_OK=true
    
    # Check Semgrep
    if [[ "$INSTALL_SEMGREP" == "true" ]]; then
        if command_exists semgrep; then
            echo -e "${GREEN}✅ Semgrep: $(semgrep --version 2>&1 | head -1)${NC}"
        else
            echo -e "${RED}❌ Semgrep: Not found${NC}"
            ALL_OK=false
        fi
    fi
    
    # Check Trivy
    if [[ "$INSTALL_TRIVY" == "true" ]]; then
        if command_exists trivy; then
            echo -e "${GREEN}✅ Trivy: $(trivy --version 2>&1 | head -1)${NC}"
        else
            echo -e "${RED}❌ Trivy: Not found${NC}"
            ALL_OK=false
        fi
    fi
    
    # Check Foundation-Sec
    if [[ "$INSTALL_FOUNDATION_SEC" == "true" ]]; then
        python3 << 'EOF' 2>/dev/null
try:
    from transformers import AutoModelForCausalLM
    AutoModelForCausalLM.from_pretrained("fdtn-ai/Foundation-Sec-8B")
    print("✅ Foundation-Sec-8B: Available")
    exit(0)
except:
    print("❌ Foundation-Sec-8B: Not available")
    exit(1)
EOF
        if [[ $? -ne 0 ]]; then
            ALL_OK=false
        fi
    fi
    
    echo ""
    
    if [[ "$ALL_OK" == "true" ]]; then
        echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║           ✅ ALL TOOLS INSTALLED SUCCESSFULLY!                 ║${NC}"
        echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo "🚀 Next steps:"
        echo "   1. Run hybrid analyzer:"
        echo "      python3 scripts/hybrid_analyzer.py /path/to/your/repo"
        echo ""
        echo "   2. Or run individual tools:"
        echo "      python3 scripts/trivy_scanner.py /path/to/your/repo"
        echo "      semgrep --config=auto /path/to/your/repo"
        echo ""
        return 0
    else
        echo -e "${YELLOW}⚠️  WARNING: Some tools failed to install${NC}"
        echo "   Please check the errors above and try again"
        return 1
    fi
}

# Main installation flow
main() {
    # Install Semgrep
    if [[ "$INSTALL_SEMGREP" == "true" ]]; then
        install_semgrep || {
            echo -e "${RED}Semgrep installation failed${NC}"
            exit 1
        }
    fi
    
    # Install Trivy
    if [[ "$INSTALL_TRIVY" == "true" ]]; then
        install_trivy || {
            echo -e "${RED}Trivy installation failed${NC}"
            exit 1
        }
    fi
    
    # Install Foundation-Sec
    if [[ "$INSTALL_FOUNDATION_SEC" == "true" ]]; then
        install_foundation_sec || {
            echo -e "${YELLOW}Foundation-Sec installation failed (optional)${NC}"
        }
    fi
    
    # Verify all installations
    verify_installations
    
    exit $?
}

# Run main
main

