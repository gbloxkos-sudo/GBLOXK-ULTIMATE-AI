#!/bin/bash
# Full installer for GBLOXK ULTIMATE AI — installs everything + desktop menu + full system access
set -u
SUDO_PASS="${1:-}"
cd "$(dirname "$0")" || exit 1
# system packages need sudo; do not exit whole install if apt fails (offline etc.)
if [ -n "$SUDO_PASS" ]; then
  echo "$SUDO_PASS" | sudo -S apt-get update || true
  echo "$SUDO_PASS" | sudo -S apt-get install -y python3-pip nmap whois dnsutils curl git netcat-openbsd poppler-utils tesseract-ocr xdg-utils || true
else
  if sudo -n true 2>/dev/null; then
    sudo apt-get update || true
    sudo apt-get install -y python3-pip nmap whois dnsutils curl git netcat-openbsd poppler-utils tesseract-ocr xdg-utils || true
  else
    echo "[!] no sudo password given and no NOPASSWD sudo — skipping apt install."
    echo "    Run: ./install.sh '<your-sudo-password>'  OR  sudo apt-get install -y python3-pip nmap whois dnsutils curl git netcat-openbsd poppler-utils tesseract-ocr xdg-utils"
  fi
fi
python3 -m pip install --break-system-packages -r requirements.txt
echo "[*] checking ollama..."
if ! command -v ollama >/dev/null 2>&1; then
  curl -fsSL https://ollama.com/install.sh | sh || true
fi
(ollama serve >/tmp/ollama.log 2>&1 &) || true
sleep 3
ollama list || true
if ! ollama list 2>/dev/null | grep -q "qwen\|llama\|mistral\|gemma"; then
  echo "[*] pulling fallback model..."
  ollama pull llama3.2:1b || ollama pull qwen2.5-coder:1.5b || true
fi
# --- FULL SYSTEM ACCESS: store sudo password 0600 for 'sudo ...' commands from Lab/AI ---
if [ -n "$SUDO_PASS" ]; then
  mkdir -p "$HOME/.config/gbloxk-ultimate"
  printf '%s' "$SUDO_PASS" > "$HOME/.config/gbloxk-ultimate/sudo_pass"
  chmod 600 "$HOME/.config/gbloxk-ultimate/sudo_pass"
  echo "[*] sudo pass stored 0600 at ~/.config/gbloxk-ultimate/sudo_pass (used only to run YOUR sudo commands)"
else
  echo "[*] no sudo password stored — 'sudo ...' from Lab will use NOPASSWD sudoers or fail with a clear message."
fi
# --- icon ---
if [ ! -f icon.png ]; then
  cp /home/dfatz/Downloads/py-gpt-2.9.1/icon.png ./icon.png 2>/dev/null || echo "[!] no icon found, continuing"
fi
chmod +x start.sh stop.sh gbloxk-ultimate-run.sh install.sh
# --- APPLICATION MENU entries (new tools menu) ---
mkdir -p "$HOME/.local/share/applications" "$HOME/Desktop"
cp -f gbloxk-ultimate.desktop "$HOME/.local/share/applications/gbloxk-ultimate.desktop"
cp -f gbloxk-ultimate.desktop "$HOME/Desktop/gbloxk-ultimate.desktop" 2>/dev/null || true
chmod +x "$HOME/Desktop/gbloxk-ultimate.desktop" 2>/dev/null || true
# trust on GNOME (allows launch from Desktop)
gio set "$HOME/Desktop/gbloxk-ultimate.desktop" metadata::trusted true 2>/dev/null || true
update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true
echo "[*] menu entry installed: Applications > Development > GBLOXK Ultimate AI"
echo "INSTALL DONE. Run ./start.sh (or click GBLOXK Ultimate AI in menu) then open http://127.0.0.1:5050"
echo "Closing the app window / Ctrl+C ALWAYS stops scans, agents, shell jobs (trap + atexit + signals)."
