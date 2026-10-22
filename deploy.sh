#!/usr/bin/env bash
# =============================================================================
# GhostPort OS — Universal POSIX Deployment & Lifecycle Script (Linux & macOS)
# Usage:
#   ./deploy.sh                # Install GhostPort
#   ./deploy.sh --uninstall    # Purge GhostPort from system
# =============================================================================
set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
RESET='\033[0m'

# ── 0. Handle Uninstallation Flag ─────────────────────────────────────────────
if [ "$1" == "--uninstall" ] || [ "$1" == "-u" ] || [ "$1" == "--purge" ]; then
    echo -e "${YELLOW}${BOLD}[*] Initiating GhostPort OS System Purge...${RESET}"

    # Try binary uninstaller first if available
    if command -v ghostport >/dev/null 2>&1; then
        ghostport --uninstall && exit 0
    elif [ -x "$HOME/.local/bin/ghostport" ]; then
        "$HOME/.local/bin/ghostport" --uninstall && exit 0
    fi

    # Fallback bash purge
    TARGETS=(
        "$HOME/.local/bin/ghostport"
        "$HOME/.local/bin/hostport"
        "/usr/local/bin/ghostport"
        "/usr/local/bin/hostport"
        "/etc/sudoers.d/ghostport"
    )

    for target in "${TARGETS[@]}"; do
        if [ -e "$target" ] || [ -L "$target" ]; then
            if rm -f "$target" 2>/dev/null; then
                echo -e "${GREEN}[+] Purged: $target${RESET}"
            elif command -v sudo >/dev/null 2>&1; then
                sudo rm -f "$target" 2>/dev/null && echo -e "${GREEN}[+] Purged (via sudo): $target${RESET}"
            fi
        fi
    done

    # Clean PATH from shell configs
    for RC in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.config/fish/config.fish"; do
        if [ -f "$RC" ]; then
            sed -i '/# GhostPort OS Global PATH/d' "$RC" 2>/dev/null || true
            sed -i '/export PATH=".*\.local\/bin:\$PATH"/d' "$RC" 2>/dev/null || true
            sed -i '/fish_add_path.*\.local\/bin/d' "$RC" 2>/dev/null || true
            echo -e "${GREEN}[+] Cleaned PATH entries from: $RC${RESET}"
        fi
    done

    echo ""
    echo -e "${CYAN}=======================================================${RESET}"
    echo -e "${GREEN}${BOLD}   GHOSTPORT OS PURGE COMPLETE${RESET}"
    echo -e "${CYAN}=======================================================${RESET}"
    echo -e "${YELLOW}All binaries, aliases, sudo rules, and PATH entries removed.${RESET}"
    exit 0
fi

echo -e "${CYAN}${BOLD}[*] Initiating GhostPort OS Deployment Protocol...${RESET}"

# ── 1. Locate the compiled binary ─────────────────────────────────────────────
POSSIBLE_PATHS=(
    "./build/shadow"
    "./build/Release/shadow"
    "./dist/ghostport"
    "./ghostport"
    "./shadow"
    "$(dirname "$0")/build/shadow"
    "$(dirname "$0")/dist/ghostport"
    "$(dirname "$0")/ghostport"
)

SOURCE_BIN=""
for path in "${POSSIBLE_PATHS[@]}"; do
    if [ -f "$path" ] && [ -x "$path" ]; then
        SOURCE_BIN="$path"
        break
    fi
done

if [ -z "$SOURCE_BIN" ]; then
    echo -e "${RED}[!] ERROR: GhostPort binary not found.${RESET}"
    echo -e "${YELLOW}[*] Build from source with CMake:${RESET}"
    echo "    cmake -B build -S . -DCMAKE_BUILD_TYPE=Release \\"
    echo "          -DCMAKE_TOOLCHAIN_FILE=\"\$VCPKG_INSTALLATION_ROOT/scripts/buildsystems/vcpkg.cmake\""
    echo "    cmake --build build --config Release"
    exit 1
fi

echo -e "${GREEN}[+] Located binary at: ${SOURCE_BIN}${RESET}"

# ── 2. Determine installation directory ───────────────────────────────────────
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    if [ -w "/usr/local/bin" ]; then
        INSTALL_DIR="/usr/local/bin"
    else
        INSTALL_DIR="$HOME/.local/bin"
    fi
else
    # Linux: user-local installation (no root needed)
    INSTALL_DIR="$HOME/.local/bin"
fi

echo -e "[*] Target installation directory: ${CYAN}$INSTALL_DIR${RESET}"
mkdir -p "$INSTALL_DIR"
cp "$SOURCE_BIN" "$INSTALL_DIR/ghostport"
chmod +x "$INSTALL_DIR/ghostport"
ln -sf "$INSTALL_DIR/ghostport" "$INSTALL_DIR/hostport"
echo -e "${GREEN}[+] Binary successfully installed to: $INSTALL_DIR/ghostport${RESET}"
echo -e "${GREEN}[+] Alias created: $INSTALL_DIR/hostport -> ghostport${RESET}"

# ── 3. Check and update PATH environment ──────────────────────────────────────
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo -e "[*] Adding ${CYAN}$INSTALL_DIR${RESET} to PATH registry..."

    RC_UPDATED=0
    if [[ "$SHELL" == *"zsh"* ]]; then
        RC="$HOME/.zshrc"
    elif [[ "$SHELL" == *"fish"* ]]; then
        RC="$HOME/.config/fish/config.fish"
        mkdir -p "$(dirname "$RC")"
        echo "fish_add_path $INSTALL_DIR" >> "$RC"
        echo -e "${GREEN}[+] Added to $RC${RESET}"
        RC_UPDATED=1
    else
        RC="$HOME/.bashrc"
    fi

    if [ "$RC_UPDATED" -eq 0 ] && [ -n "$RC" ]; then
        echo "" >> "$RC"
        echo "# GhostPort OS Global PATH" >> "$RC"
        echo "export PATH=\"$INSTALL_DIR:\$PATH\"" >> "$RC"
        echo -e "${GREEN}[+] Successfully added to $RC${RESET}"
    fi

    echo -e "${YELLOW}[!] Please run: source $RC (or restart terminal) to refresh PATH.${RESET}"
else
    echo -e "${GREEN}[+] $INSTALL_DIR is already configured in system PATH.${RESET}"
fi

# ── 4. Completion Banner ──────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}=======================================================${RESET}"
echo -e "${GREEN}${BOLD}   GHOSTPORT OS DEPLOYMENT COMPLETE${RESET}"
echo -e "${CYAN}=======================================================${RESET}"
echo -e "${YELLOW}You can now summon GhostPort from any terminal: ${BOLD}ghostport${RESET}"
echo ""
echo -e "${CYAN}[*] ONE-TIME PASSWORDLESS PERMISSION SETUP:${RESET}"
echo -e "    To grant GhostPort permanent root access so you ${BOLD}never have to enter a password again${RESET}:"
echo -e "    ${GREEN}ghostport --grant-permanent${RESET}"
echo ""
echo -e "${CYAN}[*] UNINSTALLATION COMMAND:${RESET}"
echo -e "    To completely purge GhostPort from this system at any time:"
echo -e "    ${GREEN}ghostport --uninstall${RESET}  or  ${GREEN}./deploy.sh --uninstall${RESET}"
