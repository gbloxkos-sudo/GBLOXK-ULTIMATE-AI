#!/usr/bin/env bash
# GBLOXKOS one-shot setup — installs system + python deps, Ollama, default model.
# Usage: ./setup.sh [sudo-password]
set -u
SUDO_PASS="${1:-}"
cd "$(dirname "$0")" || exit 1

run_sudo() {
  if [ -n "$SUDO_PASS" ]; then
    echo "$SUDO_PASS" | sudo -S "$@"
  else
    sudo "$@"
  fi
}

if [ -n "$SUDO_PASS" ] || sudo -n true 2>/dev/null; then
  run_sudo apt-get update || true
  run_sudo apt-get install -y --no-install-recommends python3-pip nmap whois dnsutils curl git netcat-openbsd poppler-utils tesseract-ocr xdg-utils || true
else
  echo "[!] no sudo available; skipping apt. Install deps manually if needed."
fi

python3 -m pip install --break-system-packages -r requirements.txt || python3 -m pip install -r requirements.txt

# Ollama (free local AI runtime)
if ! command -v ollama >/dev/null 2>&1; then
  echo "[*] installing ollama..."
  curl -fsSL https://ollama.com/install.sh | sh || true
fi

# start serve
if ! ollama list >/dev/null 2>&1; then
  (ollama serve >/tmp/ollama.log 2>&1 &) || true
  sleep 4
fi

# default model if none
if ! ollama list 2>/dev/null | grep -qE "qwen|llama|mistral|gemma|phi"; then
  echo "[*] pulling default free model (qwen2.5-coder:1.5b)..."
  ollama pull qwen2.5-coder:1.5b || ollama pull llama3.2:1b || true
fi

# optional sudo pass storage for Lab sudo commands
if [ -n "$SUDO_PASS" ]; then
  mkdir -p "$HOME/.config/gbloxk-ultimate"
  printf '%s' "$SUDO_PASS" > "$HOME/.config/gbloxk-ultimate/sudo_pass"
  chmod 600 "$HOME/.config/gbloxk-ultimate/sudo_pass"
fi

chmod +x start.sh stop.sh entrypoint.sh setup.sh
mkdir -p scans memory/browser ai_output rag_store
echo "GBLOXKOS setup complete. Run: ./start.sh  (then open http://127.0.0.1:5050)"
