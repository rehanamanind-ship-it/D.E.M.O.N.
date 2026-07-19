#!/usr/bin/env bash
# setup.sh – one‑shot build & environment setup for EXE Intent Analyser
# Place this script in your project root (where Cargo.toml and ai_brain.py live)

set -e  # exit on any error

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}======================================${NC}"
echo -e "${GREEN} EXE Intent Analyser - Setup Script   ${NC}"
echo -e "${GREEN}======================================${NC}"

# ------------------------------------------------------------------------------
# 1. Check and install Rust
# ------------------------------------------------------------------------------
if ! command -v rustc &> /dev/null; then
    echo -e "${YELLOW}[!] Rust not found.${NC}"
    read -p "Do you want to install Rust via rustup? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}[*] Installing Rust...${NC}"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
        echo -e "${GREEN}[*] Rust installed successfully.${NC}"
    else
        echo -e "${RED}[!] Rust is required to compile the application. Exiting.${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}[✓] Rust is installed:${NC} $(rustc --version)"
fi

# ------------------------------------------------------------------------------
# 2. Check and install Python 3 + pip
# ------------------------------------------------------------------------------
if ! command -v python3 &> /dev/null; then
    echo -e "${YELLOW}[!] Python 3 not found.${NC}"
    case "$(uname -s)" in
        Linux)
            if command -v apt-get &> /dev/null; then
                sudo apt-get update && sudo apt-get install -y python3 python3-pip
            elif command -v dnf &> /dev/null; then
                sudo dnf install -y python3 python3-pip
            else
                echo -e "${RED}[!] Please install Python 3 manually.${NC}"
                exit 1
            fi
            ;;
        Darwin)
            if command -v brew &> /dev/null; then
                brew install python3
            else
                echo -e "${RED}[!] Please install Python 3 manually (e.g., from python.org).${NC}"
                exit 1
            fi
            ;;
        *)
            echo -e "${RED}[!] Unsupported OS. Please install Python 3 manually.${NC}"
            exit 1
            ;;
    esac
    echo -e "${GREEN}[*] Python 3 installed.${NC}"
else
    echo -e "${GREEN}[✓] Python 3 is installed:${NC} $(python3 --version)"
fi

# Ensure pip is available
if ! command -v pip3 &> /dev/null; then
    echo -e "${YELLOW}[!] pip3 not found. Installing pip...${NC}"
    python3 -m ensurepip --upgrade 2>/dev/null || {
        echo -e "${RED}[!] Failed to install pip. Please install it manually.${NC}"
        exit 1
    }
fi

# ------------------------------------------------------------------------------
# 3. Install Python dependencies
# ------------------------------------------------------------------------------
echo -e "${GREEN}[*] Installing Python packages...${NC}"
# Core dependencies: llama-cpp-python for GGUF models, onnx/onnxruntime for fallback
pip3 install --user llama-cpp-python onnxruntime onnx  2>&1 | tail -1
# Optional: gguf2onnx for conversion feature (won't fail the script)
pip3 install --user gguf2onnx 2>/dev/null || echo -e "${YELLOW}[!] gguf2onnx not installed (conversion will not work).${NC}"

echo -e "${GREEN}[✓] Python dependencies installed.${NC}"

# ------------------------------------------------------------------------------
# 4. Verify project files
# ------------------------------------------------------------------------------
if [ ! -f "Cargo.toml" ]; then
    echo -e "${RED}[!] Cargo.toml not found in current directory. Please run this script from your project root.${NC}"
    exit 1
fi
if [ ! -f "src/main.rs" ]; then
    echo -e "${RED}[!] src/main.rs not found.${NC}"
    exit 1
fi
if [ ! -f "ai_brain.py" ]; then
    echo -e "${RED}[!] ai_brain.py not found.${NC}"
    exit 1
fi

# ------------------------------------------------------------------------------
# 5. Build the Rust application
# ------------------------------------------------------------------------------
echo -e "${GREEN}[*] Building the application (release mode)...${NC}"
cargo build --release 2>&1 | tail -5
if [ $? -ne 0 ]; then
    echo -e "${RED}[!] Build failed.${NC}"
    exit 1
fi
echo -e "${GREEN}[✓] Build successful.${NC}"

# ------------------------------------------------------------------------------
# 6. Copy ai_brain.py next to the binary
# ------------------------------------------------------------------------------
BINARY_DIR="target/release"
cp ai_brain.py "$BINARY_DIR/"
echo -e "${GREEN}[✓] ai_brain.py copied to ${BINARY_DIR}/.${NC}"

# ------------------------------------------------------------------------------
# 7. Final instructions
# ------------------------------------------------------------------------------
echo ""
echo -e "${GREEN}======================================${NC}"
echo -e "${GREEN} Setup complete!                      ${NC}"
echo -e "${GREEN}======================================${NC}"
echo ""
echo "To run the tool:"
echo "  cd ${BINARY_DIR}"
echo "  ./exe_intent"
echo ""
echo "On first run you can:"
echo "  - Select a real GGUF model file (if you have one)"
echo "  - Generate a default dummy ONNX model (no AI)"
echo ""
echo "Model path will be saved in config.json next to the binary."