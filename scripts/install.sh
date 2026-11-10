#!/usr/bin/env bash
# Kali/Debian-safe installer: private virtualenv + `sentinel-x` command in ~/.local/bin
set -euo pipefail
cd "$(dirname "$0")/.."
command -v python3 >/dev/null || { echo "python3 is required: sudo apt install -y python3 python3-venv"; exit 1; }
python3 -m venv .venv || { echo "Run: sudo apt install -y python3-venv python3-full"; exit 1; }
.venv/bin/python -m pip install --quiet --upgrade pip
.venv/bin/python -m pip install --quiet .
mkdir -p "$HOME/.local/bin"
ln -sf "$PWD/.venv/bin/sentinel-x" "$HOME/.local/bin/sentinel-x"
echo "[+] Installed: $("$HOME/.local/bin/sentinel-x" --version)"
case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *) echo "[!] Add to PATH:  export PATH=\"\$HOME/.local/bin:\$PATH\"";; esac
echo "[+] Try:  sentinel-x demo"
