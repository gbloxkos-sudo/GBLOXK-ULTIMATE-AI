#!/usr/bin/env bash
# GBLOXKOS launcher — closing stops everything
cd "$(dirname "$0")" || exit 1
APP_URL="http://127.0.0.1:5050"
cleanup() {
  echo "[GBLOXKOS] closing — stopping ALL jobs..."
  curl -s --max-time 5 -X POST "$APP_URL/api/system/kill-all" >/dev/null 2>&1 || true
  curl -s --max-time 5 -X POST "$APP_URL/api/scan/stop-all" >/dev/null 2>&1 || true
  curl -s --max-time 5 -X POST "$APP_URL/api/agent/stop-all" >/dev/null 2>&1 || true
  echo "[GBLOXKOS] stopped."
}
trap cleanup EXIT INT TERM HUP
export PATH="$PATH:$HOME/.local/bin:$HOME/go/bin"
python3 -m pip install --break-system-packages -q -r requirements.txt 2>&1 | tail -n 2 || true
if ! ollama list >/dev/null 2>&1; then
  echo "[*] starting ollama serve..."
  (ollama serve >/tmp/ollama.log 2>&1 &)
  sleep 3
fi
ollama list || true
echo "[*] GBLOXKOS on http://127.0.0.1:5050 (Ctrl+C stops ALL jobs)"
python3 app.py
