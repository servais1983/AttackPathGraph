#!/bin/bash
set -euo pipefail

echo "[*] Installing AttackPathGraph..."

python3 -m pip install --upgrade pip
python3 -m pip install -e ".[dev]"

echo "[+] Installation complete."
echo "    Try: attackpathgraph --ascii --nmap demo/nmap_sample.xml --bh demo/bloodhound_sample.json"
