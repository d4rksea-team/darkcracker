#!/bin/bash
# install.sh — DARK CRACKER OPS Gen 2 — Full system installer
# Installs all system dependencies and Python packages.
# Must be run as root on Kali Linux / Debian-based systems.

set -e

# ── Root check ────────────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo ""
    echo "  [!] This installer must be run as root."
    echo "      Usage:  sudo bash install.sh"
    echo ""
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo "  ██████╗  █████╗ ██████╗ ██╗  ██╗"
echo "  ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝"
echo "  ██║  ██║███████║██████╔╝█████╔╝"
echo "  ██║  ██║██╔══██║██╔══██╗██╔═██╗"
echo "  ██████╔╝██║  ██║██║  ██║██║  ██╗"
echo "  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝"
echo "        CRACKER OPS — Gen 2 Installer"
echo ""
echo "  [*] DARK SEA — Elite WiFi & Bluetooth Penetration Suite"
echo "  [*] For Authorized Penetration Testing Only"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── System package update ─────────────────────────────────────────────────────
echo "[*] Updating package lists..."
apt-get update -qq

echo "[*] Upgrading existing packages..."
apt-get upgrade -y -qq

# ── Core wireless attack tools ────────────────────────────────────────────────
echo ""
echo "[*] Installing wireless attack tools..."

apt-get install -y \
    aircrack-ng \
    airodump-ng \
    aireplay-ng \
    airmon-ng \
    hcxdumptool \
    hcxtools \
    reaver \
    bully \
    cowpatty \
    pixiewps

echo "  [+] Wireless tools installed."

# ── Password cracking ─────────────────────────────────────────────────────────
echo ""
echo "[*] Installing password cracking tools..."

apt-get install -y \
    hashcat \
    john \
    wordlists

echo "  [+] Password cracking tools installed."

# ── Network tools ─────────────────────────────────────────────────────────────
echo ""
echo "[*] Installing network tools..."

apt-get install -y \
    nmap \
    arp-scan \
    netdiscover \
    masscan \
    dnsutils \
    net-tools \
    iproute2 \
    iw \
    wireless-tools \
    rfkill \
    ethtool \
    tcpdump \
    wireshark-common \
    tshark \
    iptables \
    network-manager \
    hostapd \
    dnsmasq

echo "  [+] Network tools installed."

# ── Bluetooth tools ───────────────────────────────────────────────────────────
echo ""
echo "[*] Installing Bluetooth tools..."

apt-get install -y \
    bluetooth \
    bluez \
    bluez-tools \
    bluez-hcidump \
    btscanner \
    ubertooth \
    libglib2.0-dev || true

# gatttool is part of bluez on some systems
which gatttool >/dev/null 2>&1 && echo "  [+] gatttool found." || echo "  [!] gatttool not found (may be part of bluez-deprecated on newer systems)."

echo "  [+] Bluetooth tools installed."

# ── Web / post-exploit tools ──────────────────────────────────────────────────
echo ""
echo "[*] Installing post-exploitation tools..."

apt-get install -y \
    nikto \
    gobuster \
    dirb \
    sshpass \
    hydra \
    medusa \
    curl \
    wget

echo "  [+] Post-exploitation tools installed."

# ── Python3 and pip ───────────────────────────────────────────────────────────
echo ""
echo "[*] Installing Python3 and pip..."

apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    build-essential \
    libssl-dev \
    libffi-dev

echo "  [+] Python3 installed."

# ── Python pip packages ───────────────────────────────────────────────────────
echo ""
echo "[*] Installing Python dependencies..."

pip3 install --break-system-packages \
    scapy python-nmap netifaces \
    requests paramiko reportlab \
    pycryptodome impacket pwntools || \
pip3 install \
    scapy python-nmap netifaces \
    requests paramiko reportlab \
    pycryptodome impacket pwntools

echo "  [+] Python packages installed (CLI edition)."

# ── Application directories ───────────────────────────────────────────────────
echo ""
echo "[*] Creating application directories..."

DARKCRACKER_HOME="$HOME/.darkcracker"

mkdir -p "$DARKCRACKER_HOME/sessions"
mkdir -p "$DARKCRACKER_HOME/reports"
mkdir -p "$DARKCRACKER_HOME/wordlists"

echo "  [+] App directory: $DARKCRACKER_HOME"

# ── Wordlist symlinks ─────────────────────────────────────────────────────────
echo ""
echo "[*] Setting up wordlists..."

ROCKYOU="/usr/share/wordlists/rockyou.txt"
if [ -f "${ROCKYOU}.gz" ] && [ ! -f "$ROCKYOU" ]; then
    echo "  [*] Decompressing rockyou.txt..."
    gunzip -k "${ROCKYOU}.gz"
    echo "  [+] rockyou.txt ready."
fi

if [ -f "$ROCKYOU" ]; then
    ln -sf "$ROCKYOU" "$DARKCRACKER_HOME/wordlists/rockyou.txt" 2>/dev/null || true
    echo "  [+] Linked rockyou.txt"
fi

# ── Permissions ───────────────────────────────────────────────────────────────
echo ""
echo "[*] Setting permissions..."

chmod +x "$SCRIPT_DIR/run.sh"
chmod +x "$SCRIPT_DIR/install.sh"
chmod 700 "$DARKCRACKER_HOME"

echo "  [+] Permissions set."

# ── rfkill unblock wireless ───────────────────────────────────────────────────
echo ""
echo "[*] Unblocking wireless devices..."
rfkill unblock all 2>/dev/null && echo "  [+] Wireless unblocked." || echo "  [!] rfkill not available or nothing to unblock."

# ── Final summary ─────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  [+] DARK CRACKER OPS Gen 2 — Installation Complete!"
echo ""
echo "  Launch:    sudo bash $SCRIPT_DIR/run.sh"
echo "  App dir:   $DARKCRACKER_HOME"
echo ""
echo "  IMPORTANT: This tool is for authorized penetration testing only."
echo "  Unauthorized use is illegal. Always obtain written permission."
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
