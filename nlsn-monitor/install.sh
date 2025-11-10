#!/bin/bash
# install.sh - Installation script for nlsn-monitor

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}   nlsn-monitor Installation Script${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Detect OS
OS="$(uname -s)"
ARCH="$(uname -m)"

echo -e "${GREEN}System Information:${NC}"
echo "  OS: $OS"
echo "  Architecture: $ARCH"
echo ""

# Installation directory (default to /usr/local/bin)
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
CONFIG_DIR="$HOME/.config/nlsn-pcap"
DATA_DIR="$HOME/.local/share/nlsn-pcap"

echo -e "${GREEN}Installation Paths:${NC}"
echo "  Binary: $INSTALL_DIR/nlsn-monitor"
echo "  Config: $CONFIG_DIR/"
echo "  Data: $DATA_DIR/"
echo ""

# Check if running as root for system install
if [[ "$INSTALL_DIR" == /usr/* ]] && [[ $EUID -ne 0 ]]; then
   echo -e "${YELLOW}⚠️  Warning: Installing to $INSTALL_DIR requires root${NC}"
   echo "   Either run with sudo, or set INSTALL_DIR to a user directory:"
   echo "   INSTALL_DIR=$HOME/.local/bin ./install.sh"
   echo ""
   read -p "Continue with sudo? (y/n): " CONTINUE
   if [[ "$CONTINUE" != "y" ]]; then
       echo "Aborted."
       exit 0
   fi
   echo ""
   echo "Running with sudo..."
   exec sudo -E "$0" "$@"
fi

# Step 1: Check dependencies
echo -e "${CYAN}Step 1: Checking Dependencies${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check for Go
if command -v go &> /dev/null; then
    GO_VERSION=$(go version | awk '{print $3}')
    echo -e "  ✅ Go: $GO_VERSION"
else
    echo -e "${RED}  ❌ Go: Not found${NC}"
    echo ""
    echo "Please install Go 1.21 or higher:"
    echo "  macOS: brew install go"
    echo "  Linux: sudo apt install golang-go"
    echo "  Or visit: https://go.dev/dl/"
    exit 1
fi

# Check for libpcap
echo -n "  Checking libpcap... "
if command -v pkg-config &> /dev/null && pkg-config --exists libpcap; then
    echo -e "${GREEN}✅${NC}"
elif [ "$OS" == "Darwin" ]; then
    echo -e "${GREEN}✅ (built-in)${NC}"
elif [ -f /usr/include/pcap.h ] || [ -f /usr/local/include/pcap.h ]; then
    echo -e "${GREEN}✅${NC}"
else
    echo -e "${RED}❌${NC}"
    echo ""
    echo "libpcap development headers not found."
    echo "Install with:"
    echo "  macOS: (built-in, no action needed)"
    echo "  Debian/Ubuntu: sudo apt-get install libpcap-dev"
    echo "  Fedora/RHEL: sudo dnf install libpcap-devel"
    exit 1
fi

# Check for SQLite (optional, Go includes driver)
if command -v sqlite3 &> /dev/null; then
    SQLITE_VERSION=$(sqlite3 --version | awk '{print $1}')
    echo "  ✅ SQLite: $SQLITE_VERSION"
else
    echo "  ⚠️  SQLite CLI not found (optional, database will still work)"
fi

echo ""

# Step 2: Build binary
echo -e "${CYAN}Step 2: Building Binary${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Compiling nlsn-monitor..."

if make build; then
    echo -e "  ${GREEN}✅ Build successful${NC}"
else
    echo -e "${RED}  ❌ Build failed${NC}"
    exit 1
fi

if [ ! -f "nlsn-monitor" ]; then
    echo -e "${RED}  ❌ Binary not found after build${NC}"
    exit 1
fi

# Get binary size
BINARY_SIZE=$(du -h nlsn-monitor | cut -f1)
echo "  Binary size: $BINARY_SIZE"
echo ""

# Step 3: Install binary
echo -e "${CYAN}Step 3: Installing Binary${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Create install directory if it doesn't exist
if [ ! -d "$INSTALL_DIR" ]; then
    echo "  Creating $INSTALL_DIR..."
    mkdir -p "$INSTALL_DIR"
fi

# Copy binary
echo "  Installing to $INSTALL_DIR/nlsn-monitor..."
cp -f nlsn-monitor "$INSTALL_DIR/nlsn-monitor"
chmod +x "$INSTALL_DIR/nlsn-monitor"

echo -e "  ${GREEN}✅ Binary installed${NC}"
echo ""

# Step 4: Set capabilities (Linux only)
if [ "$OS" == "Linux" ]; then
    echo -e "${CYAN}Step 4: Setting Capabilities${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Setting CAP_NET_RAW and CAP_NET_ADMIN..."

    if command -v setcap &> /dev/null; then
        if setcap cap_net_raw,cap_net_admin=eip "$INSTALL_DIR/nlsn-monitor" 2>/dev/null; then
            echo -e "  ${GREEN}✅ Capabilities set${NC}"
            echo "  You can now run nlsn-monitor without sudo"
        else
            echo -e "  ${YELLOW}⚠️  Failed to set capabilities (need root)${NC}"
            echo "  You'll need to run nlsn-monitor with sudo"
        fi
    else
        echo -e "  ${YELLOW}⚠️  setcap not found${NC}"
        echo "  You'll need to run nlsn-monitor with sudo"
    fi
else
    echo -e "${CYAN}Step 4: Capabilities${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  (macOS - you'll need to run with sudo)"
fi

echo ""

# Step 5: Create configuration
echo -e "${CYAN}Step 5: Configuration${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Create config directory
if [ ! -d "$CONFIG_DIR" ]; then
    echo "  Creating $CONFIG_DIR..."
    mkdir -p "$CONFIG_DIR"
fi

# Create config file if it doesn't exist
CONFIG_FILE="$CONFIG_DIR/config.yaml"
if [ -f "$CONFIG_FILE" ]; then
    echo -e "  ⚠️  Config file already exists: $CONFIG_FILE"
    echo "  Skipping (not overwriting existing config)"
else
    echo "  Creating default config: $CONFIG_FILE..."
    cat > "$CONFIG_FILE" << 'EOF'
# nlsn-monitor configuration

capture:
  interface: "auto"           # Network interface (auto-detect)
  filter: "port 53"           # BPF filter (DNS traffic)
  snaplen: 65535              # Snapshot length
  promisc: true               # Promiscuous mode
  buffer_size: 1000           # Packet buffer size

detection:
  enabled: true               # Enable threat detection
  min_confidence: 50          # Minimum confidence threshold (0-100)

storage:
  type: "sqlite"
  path: "~/.local/share/nlsn-pcap/nlsn.db"
  retention_days: 30          # Keep data for 30 days

logging:
  level: "info"               # Log level: debug, info, warn, error
  format: "text"              # Log format: text, json
EOF
    echo -e "  ${GREEN}✅ Config created${NC}"
fi

echo ""

# Step 6: Create data directory
echo -e "${CYAN}Step 6: Data Directory${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ ! -d "$DATA_DIR" ]; then
    echo "  Creating $DATA_DIR..."
    mkdir -p "$DATA_DIR"
    echo -e "  ${GREEN}✅ Data directory created${NC}"
else
    echo "  Data directory exists: $DATA_DIR"
fi

echo ""

# Step 7: Verify installation
echo -e "${CYAN}Step 7: Verification${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ -f "$INSTALL_DIR/nlsn-monitor" ]; then
    VERSION=$("$INSTALL_DIR/nlsn-monitor" version 2>/dev/null || echo "unknown")
    echo -e "  ${GREEN}✅ Installation verified${NC}"
    echo "  Version: $VERSION"
else
    echo -e "${RED}  ❌ Installation verification failed${NC}"
    exit 1
fi

echo ""

# Installation complete
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}   ✅ Installation Complete!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo -e "${CYAN}Next Steps:${NC}"
echo ""
echo "  1. View available commands:"
echo "     nlsn-monitor --help"
echo ""
echo "  2. Start monitoring (requires sudo/root on most systems):"
if [ "$OS" == "Linux" ] && command -v setcap &> /dev/null; then
    echo "     nlsn-monitor start"
else
    echo "     sudo nlsn-monitor start"
fi
echo ""
echo "  3. View detected threats:"
echo "     nlsn-monitor threats"
echo ""
echo "  4. Edit configuration:"
echo "     vi $CONFIG_FILE"
echo ""

echo -e "${CYAN}Documentation:${NC}"
echo "  README: $(pwd)/README.md"
echo "  Status: $(pwd)/STATUS.md"
echo "  Config: $CONFIG_FILE"
echo ""

echo -e "${CYAN}Troubleshooting:${NC}"
echo "  • If you get permission errors, run with sudo"
echo "  • Check interface with: ip link show (Linux) or ifconfig (macOS)"
echo "  • View logs with: nlsn-monitor start --verbose"
echo ""

echo "🎉 Happy monitoring!"
