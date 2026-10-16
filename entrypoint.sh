#!/usr/bin/env bash
set -e
cd /app
export HOST=0.0.0.0
export PORT="${PORT:-5050}"

# Start Ollama (local, 100% free) if not already running
if ! pgrep -x "ollama" >/dev/null 2>&1; then
  echo "[GBLOXKOS] starting ollama serve..."
  (ollama serve >/tmp/ollama.log 2>&1 &) 
fi

# wait for Ollama to be ready
for i in $(seq 1 30); do
  if ollama list >/dev/null 2>&1; then break; fi
  sleep 1
done

# Pull a default model if none installed (free, local)
if ! ollama list 2>/dev/null | grep -qE "qwen|llama|mistral|gemma|phi"; then
  echo "[GBLOXKOS] no model found - pulling a small free default (qwen2.5-coder:1.5b)..."
  ollama pull qwen2.5-coder:1.5b || ollama pull llama3.2:1b || true
fi

echo "[GBLOXKOS] starting app on http://0.0.0.0:5050"
exec python3 /app/app.py
