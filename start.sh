#!/usr/bin/env bash
# ciphernet PQC Scanner — Start Script
set -euo pipefail

cd "$(dirname "$0")"

echo "╔══════════════════════════════════════════════════╗"
echo "║  ciphernet PQC Scanner                         ║"
echo "╚══════════════════════════════════════════════════╝"

# Create venv if missing
if [ ! -d ".venv" ]; then
    echo "[+] Creating virtual environment..."
    python3 -m venv .venv
fi

# Activate
source .venv/bin/activate

# Install deps
echo "[+] Installing dependencies..."
pip install -q -r requirements.txt

# Launch
echo "[+] Starting server on http://127.0.0.1:8000"
python run.py
