#!/bin/bash
# run.sh — DARK CRACKER OPS Gen 2 launcher
# Must be executed as root.

if [ "$EUID" -ne 0 ]; then
    echo "[!] Root required. Run: sudo bash run.sh"
    exit 1
fi

# Change to the directory containing this script regardless of cwd
cd "$(dirname "$0")" || exit 1

# Allow Qt to connect to the X server as root
xhost +local:root 2>/dev/null || true

echo "[*] Launching DARK CRACKER OPS Gen 2..."
python3 main.py
