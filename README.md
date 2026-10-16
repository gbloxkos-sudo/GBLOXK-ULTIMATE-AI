# GBLOXKOS — Full Auto Local AI Assistant

**Brand:** GBLOXKOS  
**Developer:** GBLOXK_OS LLC  
**License:** MIT

GBLOXKOS is a 100% local, free AI assistant that unifies:

- 💬 Chat, completion, research, RAG (your documents)
- 🤖 Autonomous multi-step agents
- 🧪 Full system access lab (Python + shell, sudo supported)
- 🛰 FREE auto-pentest (native port/web/SSL/subdomain/DNS scanners, no paid keys)
- 🕷 Advanced website crawler with tech detection + AI analysis
- 📚 Notes, scheduler, reports, model manager
- 🌐 Free internet browser + WAF bypass + AI page analysis
- 🧠 Self-aware AI subsystem (memory, lessons, watchdog, anti-hallucination)

Runs entirely on local **Ollama** models. No cloud keys, no paid APIs, no telemetry.

## Quick Start (bare metal)

```bash
git clone https://github.com/gbloxkos-sudo/GBLOXKOS.git
cd GBLOXKOS
chmod +x setup.sh start.sh
./setup.sh                 # or: ./setup.sh <sudo-password>
./start.sh                 # open http://127.0.0.1:5050
```

Requirements: Linux, Python 3.10+, Ollama. `setup.sh` installs system deps, Python deps, Ollama, and a default free model.

## Docker (recommended for easy install)

```bash
docker compose up -d --build
# open http://127.0.0.1:5050
```

The container bundles the app **and** Ollama. Model data persists in a Docker volume.

## Features

- 100% local Ollama models (list / pull / delete / show / use)
- Auto-pentest with native free recon: subdomains (crt.sh/certspotter/hackertarget), DNS brute, WHOIS/RDAP, ASN/Geo, nmap, socket ports, web probe, CORS/header/SSL checks, nuclei (if installed)
- AI reports (executive / brief / bughunter / pentest / exploit / remediation)
- RAG over your txt/md/pdf docs
- Agents (3-step autonomous loop) + research (free sources) + completion
- Lab: full Python/shell access, sudo via stored password, file browser, vision
- Website crawler: BFS, tech/stack detection, forms/links inventory, per-page + site AI analysis
- Browser fetch/render/screenshot + AI analyze
- Notes + scheduler + voice (browser) + reports export
- Self-healing watchdog, learning memory, anti-hallucination verification

## Security / Authorization

Only test targets you own or are explicitly authorized to test. This tool is provided for defensive security, research, and authorized assessments.

## Adding a Model

```bash
ollama pull llama3.2
# or in the app Models tab
```

## Configuration

- Sudo password (optional, for Lab sudo commands): stored 0600 in `~/.config/gbloxk-ultimate/sudo_pass`.
- Default model: first available Ollama model; set via `MODEL` env if needed.

## Pentest Tools

See `PENTEST_TOOLS.md` and run `./install_pentest_tools.sh` for optional tooling.

## Troubleshooting

- If Ollama isn't running: `ollama serve`
- If port 5050 busy: set `PORT` env? App defaults to 5050; edit `app.py` if needed.
- Docker logs: `docker compose logs -f`

## Contributing

PRs welcome. Please keep everything local/free.

## Developer

**GBLOXK_OS LLC**  
Brand: **GBLOXKOS**
