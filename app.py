#!/usr/bin/env python3
"""
GBLOXKOS — unified full-auto AI app
Merges:
  1) PyGPT 2.9.1 (desktop AI assistant: chat, agents, RAG, tools, vision, voice, automation, memory)
  2) GBLOXKOS Auto-Pentest (100% free native scanners + Ollama)
  3) ollama-gui 2.0.4 ideas (model manager, chat UX, params, history)

100% LOCAL. Uses ONLY Ollama models installed on system. No paid keys.
Port: 5050. GUI: dashboard.html (offline, no CDN).
"""
import atexit
import glob
import json
import os
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import datetime
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.chdir(HERE)

from flask import Flask, jsonify, request, send_file, send_from_directory

import ai_engine
import scanner
import free_sources
import super_ai
import crawler

# scans/outputs live next to the app
scanner.SCANS_ROOT = os.path.join(HERE, "scans")
os.makedirs(scanner.SCANS_ROOT, exist_ok=True)

from scanner import SCANS, start_scan, tools_status

app = Flask(__name__, static_folder=".", static_url_path="")
AI_OUT = os.path.join(HERE, "ai_output")
RAG_DIR = os.path.join(HERE, "rag_store")
BROWSER_DIR = os.path.join(HERE, "memory", "browser")
os.makedirs(BROWSER_DIR, exist_ok=True)
MEM_DB = os.path.join(HERE, "memory", "chats.db")
NOTEPAD = os.path.join(HERE, "memory", "notepad.md")
os.makedirs(AI_OUT, exist_ok=True)
os.makedirs(RAG_DIR, exist_ok=True)
os.makedirs(os.path.join(HERE, "memory"), exist_ok=True)

INSTALL_LOG = os.path.join(HERE, "toolchain_install.log")
install_state = {"running": False, "done": False}
AGENTS = {}  # agent_id -> {status, log, thread, stop}
_AGENTS_LOCK = __import__('threading').RLock()
EXEC_PROCS = []  # all live child procs spawned via /api/system/exec + tools install (for cleanup)
CLEANING_UP = {"done": False}

def _read_sudo_pass():
    """Full-system-access helper: read sudo password from 0600 config if present.
    Created by install.sh from user-provided password. Never logged."""
    for cand in (os.path.join(str(Path.home()), ".config", "gbloxk-ultimate", "sudo_pass"),
                 os.environ.get("GBLOXK_SUDO_PASS_FILE", "")):
        try:
            if cand and os.path.isfile(cand):
                with open(cand, encoding="utf-8", errors="ignore") as f:
                    content = f.read().strip()
                if not content:
                    continue
                pw = content.splitlines()[0].strip()
                if pw:
                    return pw
        except Exception:
            pass
    pw = os.environ.get("GBLOXK_SUDO_PASS", "")
    return pw.strip()

def _req_json():
    """Safe JSON body parse: never raises 415/400 HTML; returns {} on bad input."""
    try:
        data = request.get_json(silent=True)
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}

def _sanitize_target(raw):
    """Safe target sanitize: never raises IndexError; returns '' if invalid."""
    if not raw or not isinstance(raw, str):
        return ""
    raw = raw.strip().lower()
    if not raw:
        return ""
    # take host part before / or whitespace (URL or 'host port' forms)
    host = re.split(r"[\s/]+", raw, maxsplit=1)[0]
    if not host:
        return ""
    host = re.sub(r"[^a-z0-9.\-:]", "", host).strip(".-:")
    # reject empty / lone punctuation / overlong
    if not host or len(host) > 253 or host in (".", "-", ":", "/"):
        return ""
    return host

def _track_proc(proc):
    try:
        EXEC_PROCS.append(proc)
        # cap list to avoid unbounded growth; drop finished procs first
        if len(EXEC_PROCS) > 200:
            try:
                alive = [p for p in EXEC_PROCS if p.poll() is None]
                del EXEC_PROCS[:]
                EXEC_PROCS.extend(alive[-200:])
            except Exception:
                del EXEC_PROCS[:100]
    except Exception:
        pass
    return proc

def _kill_proc_tree(proc):
    try:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except Exception:
            try:
                proc.terminate()
            except Exception:
                pass
        try:
            proc.wait(timeout=5)
        except Exception:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
    except Exception:
        pass

def full_cleanup(reason="exit"):
    """ALWAYS stop running jobs on app close: scans, agents, exec procs, installs."""
    if CLEANING_UP["done"]:
        return
    CLEANING_UP["done"] = True
    print(f"\n[ultimate] cleanup ({reason}): stopping ALL jobs...", flush=True)
    try:
        scanner.stop_all()
        try:
            crawler.stop_all()
        except Exception:
            pass
    except Exception:
        pass
    for aid, ag in list(AGENTS.items()):
        try:
            ag["stop"] = True
            ag["status"] = "stopped"
        except Exception:
            pass
    for proc in list(EXEC_PROCS):
        try:
            if proc.poll() is None:
                _kill_proc_tree(proc)
        except Exception:
            pass
    # belt & braces: kill known scan children that may have detached
    for pat in ("nuclei -l", "nmap -Pn --top-ports"):
        try:
            subprocess.run(["pkill", "-f", pat], capture_output=True, timeout=5)
        except Exception:
            pass
    print("[ultimate] cleanup done. All jobs killed.", flush=True)

PYGPT_INFO = {
    "name": "PyGPT 2.9.1 (integrated)",
    "source": "integrated",
    "modes": ["Chat", "Agents", "Autonomous", "Research", "Completion", "Vision", "RAG", "Computer-use", "Voice"],
    "note": "PyGPT desktop (PySide6) remains launchable from source; all its modes are re-implemented here 100% local via Ollama.",
}
OLLAMAGUI_INFO = {"name": "ollama-gui 2.0.4 (UX merged)", "source": "integrated"}

# ---------------- memory (sqlite chat history, like PyGPT + ollama-gui history) ----------------
def mem_init():
    con = sqlite3.connect(MEM_DB)
    con.execute("""CREATE TABLE IF NOT EXISTS chats
      (id INTEGER PRIMARY KEY AUTOINCREMENT, session TEXT, role TEXT, content TEXT, model TEXT, ts TEXT)""")
    con.execute("""CREATE TABLE IF NOT EXISTS schedules
      (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, kind TEXT, payload TEXT, run_at TEXT, done INTEGER DEFAULT 0)""")
    con.commit()
    con.close()
mem_init()
super_ai.init_tables()

def mem_save(session, role, content, model=""):
    try:
        con = sqlite3.connect(MEM_DB)
        con.execute("INSERT INTO chats (session,role,content,model,ts) VALUES (?,?,?,?,?)",
                    (session, role, content[:20000], model, datetime.now().isoformat()))
        con.commit()
        con.close()
    except Exception:
        pass

def mem_load(session, limit=50):
    try:
        con = sqlite3.connect(MEM_DB)
        rows = con.execute("SELECT role,content FROM chats WHERE session=? ORDER BY id DESC LIMIT ?",
                           (session, limit)).fetchall()
        con.close()
        return [{"role": r, "content": c} for r, c in reversed(rows)]
    except Exception:
        return []

def rehydrate_scans():
    """Re-list finished scans from disk after server restart (in-memory SCANS is lost).
    Rehydrated entries are viewable (files/findings/log); only new scans run live."""
    try:
        import threading as _th
        for sdir in sorted(glob.glob(os.path.join(scanner.SCANS_ROOT, "*"))):
            sid = os.path.basename(sdir)
            if not os.path.isdir(sdir) or sid in SCANS:
                continue
            import re as _re
            target = _re.sub(r"^\d{8}_\d{6}(_\d{6})?_", "", sid) or sid
            if not target or target == sid:
                target = sid[23:].lstrip("_") if len(sid) > 23 else (sid[16:].lstrip("_") if len(sid) > 16 else sid)
            findings = {}
            for cand in ("findings.json", "summary.json"):
                fp = os.path.join(sdir, cand)
                if os.path.isfile(fp):
                    try:
                        findings = json.load(open(fp, encoding="utf-8", errors="ignore"))
                        target = findings.get("target", target)
                        break
                    except Exception:
                        pass
            log = []
            lfp = os.path.join(sdir, "scan.log")
            if os.path.isfile(lfp):
                try:
                    with open(lfp, encoding="utf-8", errors="ignore") as f:
                        log = [f.read()[-20000:]]
                except Exception:
                    pass
            SCANS[sid] = {"id": sid, "target": target or sid, "mode": "rehydrated",
                          "status": "done", "log": log, "dir": sdir,
                          "started": findings.get("started", ""), "procs": [],
                          "stop_event": _th.Event()}
    except Exception as e:
        print(f"[ultimate] rehydrate warning: {e}", flush=True)
rehydrate_scans()

# ---------------- RAG (lightweight local, PyGPT-style: txt/md/pdf) ----------------
def rag_extract_text(path):
    try:
        if path.lower().endswith(".pdf"):
            from pypdf import PdfReader
            rd = PdfReader(path)
            return "\n".join([(p.extract_text() or "") for p in rd.pages])[:60000]
        else:
            with open(path, encoding="utf-8", errors="ignore") as f:
                return f.read()[:60000]
    except Exception as e:
        return f"[rag extract error: {e}]"

def rag_score(query, text):
    q = [w.lower() for w in re.findall(r"\w+", query) if len(w) > 2]
    t = text.lower()
    if not q:
        return 0
    return sum(t.count(w) for w in set(q))

def rag_query(query, top_k=3):
    chunks = []
    for fp in glob.glob(os.path.join(RAG_DIR, "*")):
        if os.path.isdir(fp):
            continue
        try:
            txt = rag_extract_text(fp)
            # chunk 1500 chars
            for i in range(0, len(txt), 1500):
                ch = txt[i:i+1500]
                s = rag_score(query, ch)
                if s > 0:
                    chunks.append({"file": os.path.basename(fp), "score": s, "text": ch[:1500]})
        except Exception:
            pass
    chunks.sort(key=lambda x: x["score"], reverse=True)
    return chunks[:top_k]

# ---------------- routes: static ----------------
@app.errorhandler(400)
def _json_400(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "bad request"}), 400
    return e

@app.errorhandler(404)
def _json_404(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "not found", "path": request.path}), 404
    return e

@app.errorhandler(405)
def _json_405(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "method not allowed", "path": request.path}), 405
    return e

@app.errorhandler(415)
def _json_415(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "expected application/json body"}), 415
    return e

@app.errorhandler(500)
def _json_500(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "internal server error"}), 500
    return e

@app.route("/")
def index():
    return send_from_directory(HERE, "dashboard.html")

@app.route("/api/health")
def health():
    ok = ai_engine.ensure_ollama_running()
    ms = ai_engine.list_models()
    try:
        rag_n = len([f for f in os.listdir(RAG_DIR) if os.path.isfile(os.path.join(RAG_DIR, f))])
    except Exception:
        rag_n = 0
    try:
        _super = super_ai.watchdog_status()
    except Exception:
        _super = {}
    return jsonify({
        "ok": True,
        "app": "GBLOXK ULTIMATE AI",
        "super_ai": _super,
        "ollama": ok,
        "models": ms,
        "free_mode": True,
        "pygpt": PYGPT_INFO,
        "ollama_gui": OLLAMAGUI_INFO,
        "rag_docs": rag_n,
    })

# ---------------- models (ollama-gui style manager) ----------------
@app.route("/api/models")
def models():
    ai_engine.ensure_ollama_running()
    return jsonify({"models": ai_engine.list_models()})

def _safe_name(v, limit=200):
    try:
        s = str(v or "").strip()
    except Exception:
        return ""
    s = re.sub(r"[^a-zA-Z0-9._/:\-]+", "", s)[:limit]
    return s

@app.route("/api/models/pull", methods=["POST"])
def models_pull():
    name = _safe_name(_req_json().get("model", ""))
    if not name:
        return jsonify({"error": "model name required"}), 400
    def _pull():
        install_state["pulling"] = name
        try:
            subprocess.run(["ollama", "pull", name], timeout=3600)
        except Exception as e:
            install_state["pull_error"] = str(e)
        install_state.pop("pulling", None)
    threading.Thread(target=_pull, daemon=True).start()
    return jsonify({"started": name})

@app.route("/api/models/delete", methods=["POST"])
def models_delete():
    name = _safe_name(_req_json().get("model", ""))
    if not name:
        return jsonify({"error": "model required"}), 400
    try:
        p = subprocess.run(["ollama", "rm", name], capture_output=True, text=True, timeout=120)
        return jsonify({"deleted": name, "out": (p.stdout or p.stderr)[:2000]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/models/show", methods=["POST"])
def models_show():
    name = _safe_name(_req_json().get("model", ""))
    if not name:
        return jsonify({"error": "model required"}), 400
    try:
        p = subprocess.run(["ollama", "show", name], capture_output=True, text=True, timeout=30)
        return jsonify({"info": (p.stdout or p.stderr)[:8000]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------------- unified chat (PyGPT Chat + ollama-gui UX + scan grounding + RAG) ----------------
DEFAULT_SYSTEM = ("You are GBLOXKOS — senior local assistant (chat, code, pentest, research). "
    "100% local via Ollama. Authorized testing only. Prefer FREE local tools (nmap, nuclei, ffuf, dalfox, dig, curl). "
    "Be concrete with commands. No cloud keys needed.")

@app.route("/api/chat", methods=["POST"])
def chat():
    j = _req_json()
    try:
        model = str(j.get("model") or "").strip() or "dagbs/qwen2.5-coder-3b-instruct-abliterated:latest"
    except Exception:
        model = "dagbs/qwen2.5-coder-3b-instruct-abliterated:latest"
    raw_msgs = j.get("messages", [])
    if not isinstance(raw_msgs, list):
        return jsonify({"error": "messages must be a list"}), 400
    messages = [m for m in raw_msgs if isinstance(m, dict) and "content" in m][-20:]
    if not messages:
        return jsonify({"error": "messages required (non-empty list)"}), 400
    try:
        system = str(j.get("system") or DEFAULT_SYSTEM)[:8000]
    except Exception:
        system = DEFAULT_SYSTEM
    try:
        session = str(j.get("session") or "default")[:80]
    except Exception:
        session = "default"
    use_rag = bool(j.get("use_rag", True))
    scan_id = j.get("scan_id", "") if isinstance(j.get("scan_id", ""), str) else ""
    crawl_id = j.get("crawl_id", "") if isinstance(j.get("crawl_id", ""), str) else ""
    temperature = j.get("temperature", None)
    # scan grounding
    ctx = ""
    # free internet browsing: if user pastes/asks a URL, fetch and ground the chat in it
    browse_ctx = ""
    try:
        last_u = str(messages[-1].get("content", "") if messages and isinstance(messages[-1], dict) else "")
        for _m in __import__("re").findall(r"https?://[^\s)\]]+", last_u):
            bf = browser_fetch(_m, render=False)
            if not bf.get("error"):
                browse_ctx += f"\n\n[Browser: {_m}] TITLE: {bf.get('title','')}\n{(bf.get('text') or '')[:4000]}"
            if len(browse_ctx) > 12000:
                break
    except Exception as _e:
        super_ai.record_error("chat.browse", str(_e), "")
    if scan_id and scan_id in SCANS:
        fp = os.path.join(SCANS[scan_id]["dir"], "findings.json")
        if os.path.isfile(fp):
            try:
                ctx = open(fp, encoding="utf-8", errors="ignore").read()[:6000]
            except Exception:
                pass
    # crawl grounding
    crawl_ctx = ""
    if crawl_id and crawl_id in crawler.CRAWLS:
        crawl_ctx = crawler.crawl_context(crawl_id, max_pages=20, max_chars=6000)
    if crawl_ctx:
        ctx = (ctx + "\n\n" + crawl_ctx) if ctx else crawl_ctx
    # RAG grounding
    rag_ctx = ""
    if use_rag and messages:
        last_q = messages[-1].get("content", "") if isinstance(messages[-1], dict) else str(messages[-1])
        hits = rag_query(last_q, top_k=3)
        if hits:
            rag_ctx = "\n\nRAG local docs:\n" + "\n---\n".join(f"[{h['file']}] {h['text'][:1200]}" for h in hits)
    full_system = system + (f"\nCurrent scan findings:\n{ctx}" if ctx else "") + rag_ctx + (f"\nBrowser evidence:\n{browse_ctx}" if browse_ctx else "")
    try:
        _snap = super_ai.system_health(ai_engine.ensure_ollama_running, ai_engine.list_models, tools_status, list(SCANS.keys()))
        _ah = bool(j.get("anti_hallucinate", True))
        full_system = full_system + super_ai.awareness_prompt(_snap)
        if _ah:
            full_system = full_system + super_ai.anti_hallucinate_prompt(rag_ctx or ctx)
    except Exception as _e:
        super_ai.record_error("chat", str(_e), "")
    ai_engine.ensure_ollama_running()
    # temperature via options if lib available
    reply = ""
    try:
        import ollama as _ol
        msgs = [{"role": "system", "content": str(full_system)[:20000]}]
        for m in messages:
            if isinstance(m, dict) and "content" in m:
                try:
                    role = str(m.get("role", "user"))[:20] or "user"
                    content = str(m.get("content", ""))[:12000]
                except Exception:
                    continue
                msgs.append({"role": role, "content": content})
        opts = {}
        if temperature is not None:
            try:
                opts = {"temperature": float(temperature)}
            except Exception:
                pass
        resp = _ol.chat(model=model, messages=msgs, options=opts or None)
        reply = resp.get("message", {}).get("content", "")
    except Exception as e:
        reply = f"[chat lib error, CLI fallback] {e}\n" + ai_engine.chat(model,
            [{"role": str(m.get("role", "user"))[:20], "content": str(m.get("content", ""))[:12000]} for m in messages if isinstance(m, dict)], str(full_system)[:20000])
    if not reply:
        reply = "[empty response from model]"
    _verification = {}
    try:
        _verification = super_ai.verify_text(reply, rag_ctx or ctx)
        _last_u = str(messages[-1].get("content", "")) if messages and isinstance(messages[-1], dict) else ""
        super_ai.learn(session, _last_u, reply, model, "ok" if _verification.get("ok") else "unverified",
                       1 if _verification.get("ok") else -1, {"scan_id": scan_id})
        try:
            super_ai.system_health(ai_engine.ensure_ollama_running, ai_engine.list_models, tools_status, list(SCANS.keys()))
        except Exception:
            pass
    except Exception as _e:
        super_ai.record_error("chat.learn", str(_e), "")
    try:
        last_u = str(messages[-1].get("content", "")) if messages and isinstance(messages[-1], dict) else ""
    except Exception:
        last_u = ""
    mem_save(session, "user", last_u, model)
    mem_save(session, "assistant", reply, model)
    return jsonify({"reply": reply, "verification": _verification})

@app.route("/api/chat/history")
def chat_history():
    session = request.args.get("session", "default")
    return jsonify({"session": session, "messages": mem_load(session, 100)})

@app.route("/api/chat/clear", methods=["POST"])
def chat_clear():
    try:
        session = str(_req_json().get("session", "default"))[:80]
    except Exception:
        session = "default"
    try:
        con = sqlite3.connect(MEM_DB)
        con.execute("DELETE FROM chats WHERE session=?", (session,))
        con.commit(); con.close()
    except Exception:
        pass
    return jsonify({"cleared": session})

# ---------------- completion / research modes (PyGPT-style) ----------------
@app.route("/api/complete", methods=["POST"])
def complete():
    j = _req_json()
    try:
        model = str(j.get("model") or "").strip() or "dagbs/qwen2.5-coder-3b-instruct-abliterated:latest"
        prompt = str(j.get("prompt") or "")[:15000]
    except Exception:
        return jsonify({"error": "invalid prompt"}), 400
    if not prompt:
        return jsonify({"error": "prompt required"}), 400
    ai_engine.ensure_ollama_running()
    try:
        _snap = super_ai.system_health(ai_engine.ensure_ollama_running, ai_engine.list_models, tools_status, list(SCANS.keys()))
        prompt = super_ai.awareness_prompt(_snap) + "\n" + prompt
    except Exception:
        pass
    reply = ai_engine.generate(prompt, model)
    try:
        _v = super_ai.verify_text(reply, prompt)
    except Exception:
        _v = {}
    super_ai.learn("complete", prompt[:500], reply, model, "ok" if _v.get("ok") else "unverified", 1 if _v.get("ok") else -1, {})
    return jsonify({"reply": reply, "verification": _v})

@app.route("/api/research", methods=["POST"])
def research():
    """Free web research: DuckDuckGo-free summary + Ollama synthesis (PyGPT Research mode, local)."""
    j = _req_json()
    try:
        q = str(j.get("query") or "")[:500]
        model = str(j.get("model") or "").strip() or "dagbs/qwen2.5-coder-3b-instruct-abliterated:latest"
    except Exception:
        return jsonify({"error": "invalid query"}), 400
    if not q.strip():
        return jsonify({"error": "query required"}), 400
    evidence = ""
    try:
        # free: Wikipedia + crt.sh-style open sources, no keys
        wq = urllib.request.quote(q)
        req = urllib.request.Request(f"https://en.wikipedia.org/api/rest_v1/page/summary/{wq}",
                                     headers={"User-Agent": "GBLOXK-Ultimate"})
        with urllib.request.urlopen(req, timeout=12) as r:
            wd = json.loads(r.read().decode("utf-8", "ignore"))
            evidence += f"Wikipedia: {wd.get('title','')}\n{(wd.get('extract','') or '')[:3000]}\n"
    except Exception as e:
        evidence += f"(wikipedia unavailable: {e})\n"
    ai_engine.ensure_ollama_running()
    try:
        _snap = super_ai.system_health(ai_engine.ensure_ollama_running, ai_engine.list_models, tools_status, list(SCANS.keys()))
        _aw = super_ai.awareness_prompt(_snap)
    except Exception:
        _aw = ""
    prompt = (f"Research query: {q}\nFree evidence:\n{evidence[:4000]}\n\n"
              "Write a structured research brief: 1) direct answer, 2) key facts, 3) commands/tools if technical, 4) sources/limits.")
    prompt = _aw + "\n" + prompt + super_ai.anti_hallucinate_prompt(evidence)
    reply = ai_engine.generate(prompt, model)
    try:
        _v = super_ai.verify_text(reply, evidence)
    except Exception:
        _v = {}
    super_ai.learn("research", q, reply, model, "ok" if _v.get("ok") else "unverified", 1 if _v.get("ok") else -1, {})
    return jsonify({"evidence": evidence[:4000], "reply": reply, "verification": _v})

# ---------------- scans (Gbloxk core) ----------------
@app.route("/api/scan/start", methods=["POST"])
def scan_start():
    j = _req_json()
    target = _sanitize_target(j.get("target", ""))
    try:
        mode = str(j.get("mode", "auto"))[:40] or "auto"
    except Exception:
        mode = "auto"
    if mode not in ("auto", "reconftw-full", "reconftw-passive", "reconftw-subs",
                    "reconftw-web", "reconftw-vulns"):
        mode = "auto"
    if not target:
        return jsonify({"error": "target required (domain or IP)"}), 400
    sid = start_scan(target, mode)
    return jsonify({"scan_id": sid})

@app.route("/api/scan/list")
def scan_list():
    return jsonify([{"id": v["id"], "target": v["target"], "mode": v.get("mode"),
                     "status": v["status"], "started": v.get("started")} for v in SCANS.values()])

@app.route("/api/scan/<sid>/status")
def scan_status(sid):
    sc = SCANS.get(sid)
    if not sc:
        return jsonify({"error": "unknown scan"}), 404
    return jsonify({"id": sid, "status": sc["status"], "target": sc["target"], "log_lines": len(sc["log"])})

@app.route("/api/scan/<sid>/log")
def scan_log(sid):
    sc = SCANS.get(sid)
    if not sc:
        return jsonify({"error": "unknown scan"}), 404
    try:
        tail = int(request.args.get("tail", "400"))
    except Exception:
        tail = 400
    tail = max(1, min(tail, 2000))
    return jsonify({"log": "".join(sc["log"][-tail:])})

@app.route("/api/scan/<sid>/files")
def scan_files(sid):
    sc = SCANS.get(sid)
    if not sc:
        return jsonify({"error": "unknown scan"}), 404
    out = []
    for root, _, files in os.walk(sc["dir"]):
        for fn in files:
            fp = os.path.join(root, fn)
            rel = os.path.relpath(fp, sc["dir"])
            try:
                out.append({"path": rel, "size": os.path.getsize(fp)})
            except Exception:
                pass
    return jsonify({"files": sorted(out, key=lambda x: x["path"])[:2000]})

@app.route("/api/scan/<sid>/file")
def scan_file(sid):
    sc = SCANS.get(sid)
    if not sc:
        return jsonify({"error": "unknown scan"}), 404
    rel = request.args.get("path", "")
    fp = os.path.normpath(os.path.join(sc["dir"], rel))
    if not fp.startswith(sc["dir"]) or not os.path.isfile(fp):
        return jsonify({"error": "bad path"}), 400
    if os.path.getsize(fp) > 2_000_000:
        return jsonify({"error": "file too large to preview"}), 400
    return send_file(fp, mimetype="text/plain")

@app.route("/api/scan/<sid>/findings")
def scan_findings(sid):
    sc = SCANS.get(sid)
    if not sc:
        return jsonify({"error": "unknown scan"}), 404
    for cand in ("findings.json", "summary.json", "free_recon.json"):
        fp = os.path.join(sc["dir"], cand)
        if os.path.isfile(fp):
            try:
                return jsonify(json.load(open(fp, encoding="utf-8", errors="ignore")))
            except Exception:
                pass
    return jsonify({"target": sc["target"], "items": [], "note": "no findings.json yet"})

@app.route("/api/scan/<sid>/stop", methods=["POST"])
def scan_stop(sid):
    if scanner.stop_scan(sid):
        return jsonify({"stopped": sid})
    return jsonify({"error": "unknown scan"}), 404

# ---------------- AI pentest reports + chat ----------------
@app.route("/api/ai/analyze", methods=["POST"])
def ai_analyze():
    j = _req_json()
    sid = j.get("scan_id", "") if isinstance(j.get("scan_id", ""), str) else ""
    try:
        model = str(j.get("model", "") or "").strip() or "dagbs/qwen2.5-coder-3b-instruct-abliterated:latest"
        rtype = str(j.get("report_type", "pentest"))[:40] or "pentest"
        fmt = str(j.get("format", "md"))[:10] or "md"
    except Exception:
        return jsonify({"error": "invalid params"}), 400
    if fmt not in ("md", "txt"):
        fmt = "md"
    sc = SCANS.get(sid)
    if not sc:
        return jsonify({"error": "unknown scan"}), 404
    ai_engine.ensure_ollama_running()
    res = ai_engine.analyze(sc["dir"], model, rtype, AI_OUT)
    path = ai_engine.save(res, AI_OUT, model, rtype, fmt)
    return jsonify({"report": res, "file": os.path.basename(path)})

@app.route("/api/ai/chat", methods=["POST"])
def ai_chat():
    j = _req_json()
    try:
        model = str(j.get("model", "") or "").strip() or "dagbs/qwen2.5-coder-3b-instruct-abliterated:latest"
    except Exception:
        model = "dagbs/qwen2.5-coder-3b-instruct-abliterated:latest"
    messages = j.get("messages", [])
    if not isinstance(messages, list):
        return jsonify({"error": "messages must be a list"}), 400
    messages = [m for m in messages if isinstance(m, dict)][:12]
    sid = j.get("scan_id", "") if isinstance(j.get("scan_id", ""), str) else ""
    cid = j.get("crawl_id", "") if isinstance(j.get("crawl_id", ""), str) else ""
    ctx = ""
    if sid and sid in SCANS:
        fp = os.path.join(SCANS[sid]["dir"], "findings.json")
        if os.path.isfile(fp):
            try:
                ctx = open(fp, encoding="utf-8", errors="ignore").read()[:6000]
            except Exception:
                pass
    if cid and cid in crawler.CRAWLS:
        cctx = crawler.crawl_context(cid, max_pages=20, max_chars=6000)
        ctx = (ctx + "\n\n" + cctx) if ctx else cctx
    try:
        _snap = super_ai.system_health(ai_engine.ensure_ollama_running, ai_engine.list_models, tools_status, list(SCANS.keys()))
        _extra = super_ai.awareness_prompt(_snap) + super_ai.anti_hallucinate_prompt(ctx)
    except Exception:
        _extra = ""
    system = ("You are Gbloxk, senior pentest copilot. Authorized testing only. "
              "Prefer FREE local tools (nmap, nuclei, ffuf, dalfox, dig, curl). Concrete commands. "
              + (f"\nCurrent scan findings context:\n{ctx}" if ctx else "") + _extra)
    ai_engine.ensure_ollama_running()
    reply = ai_engine.chat(model, messages[-12:], system)
    try:
        _v = super_ai.verify_text(reply, ctx)
        super_ai.learn("ai_chat", (messages[-1].get("content","") if messages else ""), reply, model,
                       "ok" if _v.get("ok") else "unverified", 1 if _v.get("ok") else -1, {"scan_id": sid})
    except Exception as e:
        super_ai.record_error("ai_chat.learn", str(e), "")
        _v = {}
    return jsonify({"reply": reply, "verification": _v})

# ---------------- RAG endpoints ----------------
@app.route("/api/rag/upload", methods=["POST"])
def rag_upload():
    if "file" not in request.files:
        return jsonify({"error": "no file"}), 400
    f = request.files["file"]
    try:
        orig = str(getattr(f, "filename", "") or "")
    except Exception:
        orig = ""
    name = re.sub(r"[^a-zA-Z0-9._-]", "_", orig)[:120].strip("._")
    if not name or name in (".", ".."):
        return jsonify({"error": "bad filename"}), 400
    # 10MB upload cap
    try:
        f.seek(0, os.SEEK_END)
        sz = f.tell()
        f.seek(0)
        if sz > 10_000_000:
            return jsonify({"error": "file too large (>10MB)"}), 400
    except Exception:
        pass
    dest = os.path.join(RAG_DIR, name)
    try:
        f.save(dest)
    except Exception as e:
        return jsonify({"error": f"save failed: {e}"}), 500
    txt = rag_extract_text(dest)
    return jsonify({"saved": name, "chars": len(txt), "preview": txt[:800]})

@app.route("/api/rag/list")
def rag_list():
    out = []
    try:
        names = os.listdir(RAG_DIR)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    for fn in names:
        fp = os.path.join(RAG_DIR, fn)
        try:
            if os.path.isfile(fp):
                out.append({"name": fn, "size": os.path.getsize(fp)})
        except Exception:
            continue
    return jsonify(sorted(out, key=lambda x: x["name"]))

@app.route("/api/rag/delete", methods=["POST"])
def rag_delete():
    try:
        name = str(_req_json().get("name", ""))[:120]
    except Exception:
        return jsonify({"error": "bad name"}), 400
    if not name or "/" in name or name in (".", ".."):
        return jsonify({"error": "bad name"}), 400
    fp = os.path.normpath(os.path.join(RAG_DIR, name))
    if not fp.startswith(RAG_DIR) or not os.path.isfile(fp):
        return jsonify({"error": "bad name"}), 400
    os.remove(fp)
    return jsonify({"deleted": name})

@app.route("/api/rag/query", methods=["POST"])
def rag_q():
    j = _req_json()
    try:
        q = str(j.get("query", "") or "")[:2000]
        model = str(j.get("model") or "").strip() or "dagbs/qwen2.5-coder-3b-instruct-abliterated:latest"
    except Exception:
        return jsonify({"error": "invalid query"}), 400
    if not q.strip():
        return jsonify({"error": "query required"}), 400
    hits = rag_query(q, top_k=3)
    ctx = "\n---\n".join(f"[{h['file']}] {h['text']}" for h in hits) if hits else "(no local docs matched)"
    ai_engine.ensure_ollama_running()
    prompt = f"Question: {q}\nLocal documents:\n{ctx[:6000]}\n\nAnswer grounded in the documents. Cite filenames."
    try:
        prompt = super_ai.awareness_prompt(super_ai.system_health(ai_engine.ensure_ollama_running, ai_engine.list_models, tools_status, list(SCANS.keys()))) + "\n" + prompt + super_ai.anti_hallucinate_prompt(ctx)
    except Exception:
        pass
    reply = ai_engine.generate(prompt, model)
    try:
        _v = super_ai.verify_text(reply, ctx)
    except Exception:
        _v = {}
    super_ai.learn("rag", q, reply, model, "ok" if _v.get("ok") else "unverified", 1 if _v.get("ok") else -1, {})
    return jsonify({"hits": hits, "reply": reply, "verification": _v})

# ---------------- Agents / Autonomous (PyGPT Agents mode, local) ----------------
def _agent_loop(aid, goal, model):
    ag = AGENTS[aid]
    ag["log"].append(f"[{datetime.now().strftime('%H:%M:%S')}] agent started: {goal}\n")
    try:
        _ls = super_ai.lessons(8)
        _lesson_txt = "\n".join(f"- {l['lesson']}" for l in _ls)
    except Exception:
        _lesson_txt = ""
    steps = [
        f"Decompose this goal into 5 concrete steps (local tools only, no paid APIs). Goal: {goal}\nLessons:\n{_lesson_txt}",
        f"You are executing. Step 1: list exact commands for goal: {goal}. Only FREE local tools.\nLessons:\n{_lesson_txt}",
        f"Simulate reviewing outputs and give final actionable result for: {goal}. Include commands + fixes.\nLessons:\n{_lesson_txt}",
    ]
    try:
        for i, p in enumerate(steps, 1):
            if ag.get("stop"):
                ag["log"].append("agent STOPPED by user.\n")
                break
            ag["log"].append(f"\n--- step {i}/3 ---\n")
            out = ai_engine.generate(p, model)
            ag["log"].append(out + "\n")
        ag["status"] = "done" if not ag.get("stop") else "stopped"
        try:
            super_ai.learn("agent", goal, "".join(ag["log"])[-4000:], model, ag["status"], 0, {"agent_id": aid})
        except Exception:
            pass
    except Exception as e:
        super_ai.record_error("agent", str(e), goal)
        ag["log"].append(f"\n[agent error] {e}\n")
        ag["status"] = "error"
    ag["log"].append(f"\n[{datetime.now().strftime('%H:%M:%S')}] agent {ag['status']}.\n")

@app.route("/api/agent/run", methods=["POST"])
def agent_run():
    j = _req_json()
    try:
        goal = str(j.get("goal") or "").strip()[:2000]
        model = str(j.get("model") or "").strip()[:200] or "dagbs/qwen2.5-coder-3b-instruct-abliterated:latest"
    except Exception:
        return jsonify({"error": "invalid goal"}), 400
    if not goal:
        return jsonify({"error": "goal required"}), 400
    import random as _rnd
    aid = f"agent_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}_{_rnd.randint(100,999)}"
    AGENTS[aid] = {"id": aid, "goal": goal, "model": model, "status": "running", "log": [], "stop": False}
    t = threading.Thread(target=_agent_loop, args=(aid, goal, model), daemon=True)
    AGENTS[aid]["thread"] = t
    t.start()
    return jsonify({"agent_id": aid})

@app.route("/api/agent/<aid>/log")
def agent_log(aid):
    ag = AGENTS.get(aid)
    if not ag:
        return jsonify({"error": "unknown agent"}), 404
    return jsonify({"id": aid, "status": ag["status"], "log": "".join(ag["log"])[-20000:]})

@app.route("/api/agent/<aid>/stop", methods=["POST"])
def agent_stop(aid):
    ag = AGENTS.get(aid)
    if not ag:
        return jsonify({"error": "unknown agent"}), 404
    ag["stop"] = True
    ag["status"] = "stopped"
    return jsonify({"stopped": aid})

# ---------------- Python/OS tool (FULL SYSTEM ACCESS — user-authorized) ----------------
@app.route("/api/system/exec", methods=["POST"])
def sys_exec():
    """FULL SYSTEM ACCESS: run any shell/python the user asks for.
    - kind=shell: any command, any binary, pipes allowed. cwd/timeout supported.
    - kind=python: full exec with system access (os, sys, pathlib pre-imported).
    - sudo: if command starts with 'sudo ' and password file exists, auto-feed via sudo -S.
    Server runs as the logged-in user, so it already has the user's full rights."""
    j = _req_json()
    try:
        kind = str(j.get("kind", "shell"))[:20] or "shell"
        code = str(j.get("code") or "")[:30000]
        cwd = os.path.expanduser(str(j.get("cwd") or HERE)[:500])
    except Exception:
        return jsonify({"error": "invalid params"}), 400
    try:
        timeout = int(j.get("timeout", 120) or 120)
    except Exception:
        timeout = 120
    timeout = max(1, min(timeout, 1800))
    if not code:
        return jsonify({"error": "code required"}), 400
    if not os.path.isdir(cwd):
        cwd = HERE
    try:
        if kind == "python":
            import io, contextlib
            buf = io.StringIO()
            loc = {}
            g = {"__builtins__": __builtins__, "os": os, "sys": sys,
                 "subprocess": subprocess, "pathlib": Path, "json": json, "time": time}
            with contextlib.redirect_stdout(buf):
                exec(code, g, loc)
            return jsonify({"output": (buf.getvalue() or f"(ok, locals={list(loc)[:10]})")[:20000], "cwd": cwd})
        else:
            cmd = code
            if cmd.lstrip().startswith("sudo "):
                pw = _read_sudo_pass()
                # feed password via stdin if we have it; else try non-interactive (NOPASSWD sudoers)
                if pw:
                    # sudo -S reads from stdin; strip any -n/--non-interactive (conflicts with -S)
                    rest = cmd.lstrip()[5:]
                    rest = re.sub(r"(^|\s)(-n|--non-interactive)(\s|$)", " ", rest).strip()
                    full = f"sudo -S -p '' {rest}"
                    p = subprocess.Popen(full, shell=True, stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, text=True, cwd=cwd,
                                         stdin=subprocess.PIPE, start_new_session=True)
                    _track_proc(p)
                    try:
                        out, _ = p.communicate(input=pw + "\n", timeout=timeout)
                    except subprocess.TimeoutExpired:
                        _kill_proc_tree(p)
                        out, _ = p.communicate()
                    return jsonify({"output": (out or "")[:20000], "cwd": cwd, "returncode": p.returncode})
                # no stored password: let sudo prompt fail naturally with clear message
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, text=True, cwd=cwd, start_new_session=True)
            _track_proc(p)
            try:
                out, _ = p.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                _kill_proc_tree(p)
                out, _ = p.communicate()
                out = (out or "") + "\n[TIMEOUT killed after %ss]" % timeout
            return jsonify({"output": (out or "")[:20000], "cwd": cwd, "returncode": p.returncode})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/files/list", methods=["POST"])
def files_list():
    j = _req_json()
    try:
        path = os.path.expanduser(str(j.get("path") or "~")[:1000])
    except Exception:
        return jsonify({"error": "invalid path"}), 400
    try:
        if not os.path.exists(path):
            return jsonify({"error": "no such path"}), 404
        if os.path.isfile(path):
            return jsonify({"path": path, "files": [{"name": os.path.basename(path), "size": os.path.getsize(path)}]})
        items = []
        for fn in sorted(os.listdir(path))[:2000]:
            fp = os.path.join(path, fn)
            try:
                items.append({"name": fn, "dir": os.path.isdir(fp),
                              "size": os.path.getsize(fp) if os.path.isfile(fp) else 0})
            except Exception:
                items.append({"name": fn, "dir": False, "size": 0})
        return jsonify({"path": path, "files": items})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/files/read", methods=["POST"])
def files_read():
    j = _req_json()
    try:
        path = os.path.expanduser(str(j.get("path") or "")[:2000])
    except Exception:
        return jsonify({"error": "invalid path"}), 400
    if not path or not os.path.isfile(path):
        return jsonify({"error": "file not found"}), 404
    try:
        if os.path.getsize(path) > 2_000_000:
            return jsonify({"error": "file too large (>2MB)"}), 400
        with open(path, encoding="utf-8", errors="ignore") as f:
            return jsonify({"path": path, "content": f.read()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/files/write", methods=["POST"])
def files_write():
    j = _req_json()
    try:
        path = os.path.expanduser(str(j.get("path") or "")[:2000])
        content = str(j.get("content", "") or "")
    except Exception:
        return jsonify({"error": "invalid params"}), 400
    if not path:
        return jsonify({"error": "path required"}), 400
    try:
        parent = os.path.dirname(os.path.abspath(path)) or "/"
        os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content[:500000])
        return jsonify({"saved": path, "bytes": len(content)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/scan/stop-all", methods=["POST"])
def scan_stop_all():
    try:
        scanner.stop_all()
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"stopped_all": True})

@app.route("/api/agent/stop-all", methods=["POST"])
def agent_stop_all():
    for ag in AGENTS.values():
        try:
            ag["stop"] = True
            ag["status"] = "stopped"
        except Exception:
            pass
    return jsonify({"stopped_all": True, "count": len(AGENTS)})

@app.route("/api/system/kill-all", methods=["POST"])
def system_kill_all():
    """Stop EVERYTHING: scans + agents + exec procs (used on app close / QUIT)."""
    full_cleanup_temporary()
    return jsonify({"killed_all": True})

def full_cleanup_temporary():
    """Non-final kill-all (server keeps running): scans + agents + exec procs + detached tools."""
    try:
        scanner.stop_all()
        crawler.stop_all()
    except Exception:
        pass
    for ag in AGENTS.values():
        try:
            ag["stop"] = True
            ag["status"] = "stopped"
        except Exception:
            pass
    for proc in list(EXEC_PROCS):
        try:
            if proc.poll() is None:
                _kill_proc_tree(proc)
        except Exception:
            pass
    for pat in ("nuclei -l", "nmap -Pn --top-ports"):
        try:
            subprocess.run(["pkill", "-f", pat], capture_output=True, timeout=5)
        except Exception:
            pass

# ---------------- super AI endpoints ----------------
@app.route("/api/super/status")
def super_status():
    try:
        snap = super_ai.system_health(ai_engine.ensure_ollama_running, ai_engine.list_models, tools_status, list(SCANS.keys()))
        return jsonify({"health": snap, "watchdog": super_ai.watchdog_status(),
                        "lessons": super_ai.lessons(10), "recent_errors": super_ai.recent_errors(10)})
    except Exception as e:
        super_ai.record_error("super_status", str(e), "")
        return jsonify({"error": str(e)}), 500

@app.route("/api/super/lessons", methods=["POST"])
def super_lessons_add():
    try:
        txt = str(_req_json().get("lesson", "") or "")[:2000]
        super_ai.add_lesson(txt, source="user", weight=int(_req_json().get("weight", 1) or 1))
        return jsonify({"saved": bool(txt)})
    except Exception as e:
        super_ai.record_error("super_lessons_add", str(e), "")
        return jsonify({"error": str(e)}), 500

@app.route("/api/ai/verify", methods=["POST"])
def ai_verify():
    try:
        j = _req_json()
        text = str(j.get("text", "") or "")[:20000]
        evidence = str(j.get("evidence", "") or "")[:12000]
        return jsonify(super_ai.verify_text(text, evidence))
    except Exception as e:
        super_ai.record_error("ai_verify", str(e), "")
        return jsonify({"error": str(e)}), 500

@app.route("/api/ai/feedback", methods=["POST"])
def ai_feedback():
    try:
        j = _req_json()
        session = str(j.get("session", "default") or "default")[:80]
        rating = int(j.get("rating", 0) or 0)
        note = str(j.get("note", "") or "")[:2000]
        reply = str(j.get("reply", "") or "")[:4000]
        super_ai.feedback(session, rating, note, reply)
        return jsonify({"saved": True})
    except Exception as e:
        super_ai.record_error("ai_feedback", str(e), "")
        return jsonify({"error": str(e)}), 500

@app.route("/api/ai/memory", methods=["GET"])
def ai_memory():
    try:
        q = request.args.get("q", "")
        return jsonify({"items": super_ai.recall_similar(q, 8), "lessons": super_ai.lessons(20)})
    except Exception as e:
        super_ai.record_error("ai_memory", str(e), "")
        return jsonify({"error": str(e)}), 500

@app.route("/api/chat/stop", methods=["POST"])
def chat_stop():
    # Best-effort client notification; actual generation cancellation is cooperative.
    return jsonify({"stopped": True, "note": "client should abort the in-flight fetch"})

@app.route("/api/reports/clear", methods=["POST"])
def reports_clear():
    try:
        j = _req_json()
        all_flag = bool(j.get("all", False))
        days = j.get("older_than_days", None)
        import time as _t
        now = _t.time()
        cutoff = now - (int(days) * 86400) if days is not None else None
        removed = []
        for fp in __import__("glob").glob(os.path.join(AI_OUT, "*")):
            if not os.path.isfile(fp):
                continue
            try:
                if all_flag or (cutoff is not None and os.path.getmtime(fp) < cutoff):
                    os.remove(fp)
                    removed.append(os.path.basename(fp))
            except Exception as e:
                super_ai.record_error("reports_clear", str(e), fp)
        return jsonify({"removed": removed, "count": len(removed)})
    except Exception as e:
        super_ai.record_error("reports_clear", str(e), "")
        return jsonify({"error": str(e)}), 500


import urllib.parse as _up

def _valid_url(u):
    try:
        u = str(u or "").strip()
    except Exception:
        return ""
    if not u:
        return ""
    p = _up.urlparse(u)
    if p.scheme not in ("http", "https"):
        return ""
    if not p.netloc:
        return ""
    return u

def _waf_signatures(text, status):
    t = (text or "").lower()
    sigs = ["cf-challenge", "challenge-platform", "just a moment", "cloudflare", "access denied",
            "request blocked", "attention required", "captcha", "incapsula", "sucuri", "ddos protection"]
    return (status in (403, 429, 503)) or any(s in t for s in sigs)

_UAS = [
 "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
 "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
 "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
 "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
 "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
]

def _waf_headers(ua, url):
    from urllib.parse import urlparse
    p = urlparse(url)
    return {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Cache-Control": "max-age=0",
        "X-Forwarded-For": "127.0.0.1",
        "Referer": f"{p.scheme}://{p.netloc}/",
    }

def _try_requests(url, strategy):
    import requests
    ua = _UAS[strategy % len(_UAS)]
    sess = requests.Session()
    # warm-up homepage to collect cookies
    try:
        sess.get(url, headers=_waf_headers(ua, url), timeout=15, allow_redirects=True)
    except Exception:
        pass
    r = sess.get(url, headers=_waf_headers(ua, url), timeout=20, allow_redirects=True)
    return r.status_code, r.url, r.text, r.headers.get("Content-Type", ""), "requests"

def _try_curl(url, ua):
    import subprocess
    cmd = ["curl", "-sSL", "-L", "--max-time", "30", "-A", ua,
           "-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
           "-H", "Accept-Language: en-US,en;q=0.9", url]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=35)
    # extract http status from stderr not available; assume 200 if body
    body = p.stdout or ""
    return 200, url, body, "", "curl"

def _try_lynx(url):
    import subprocess
    p = subprocess.run(["lynx", "-dump", "-accept_all_cookies", url], capture_output=True, text=True, timeout=35)
    body = p.stdout or ""
    return 200, url, body, "text/plain", "lynx"

def _try_selenium(url, wait=8):
    from selenium import webdriver
    from selenium.webdriver.firefox.service import Service
    from selenium.webdriver.firefox.options import Options
    opts = Options(); opts.add_argument("--headless")
    svc_path = None
    for b in ("/snap/bin/geckodriver", "/usr/local/bin/geckodriver", "/usr/bin/geckodriver"):
        if os.path.isfile(b):
            svc_path = b; break
    if not svc_path:
        raise RuntimeError("geckodriver not found")
    drv = webdriver.Firefox(service=Service(svc_path), options=opts)
    try:
        drv.set_window_size(1280, 800)
        drv.get(url)
        import time as _t
        _t.sleep(wait)
        src = drv.page_source or ""
        # extra wait/retry if challenge
        if _waf_signatures(src, 200) and wait < 20:
            _t.sleep(10)
            src = drv.page_source or ""
        return 200, drv.current_url or url, src, "text/html", "selenium"
    finally:
        try: drv.quit()
        except Exception: pass

def browser_fetch(url, timeout=20, render=False, waf_bypass=True):
    url = _valid_url(url)
    if not url:
        return {"error": "valid http/https url required"}
    out = {"url": url, "fetched_at": __import__("datetime").datetime.now().isoformat(),
           "strategies_tried": [], "waf_bypassed": False}
    html = ""
    status = None
    final_url = url
    content_type = ""
    engine = None
    errors = []
    if render:
        try:
            status, final_url, html, content_type, engine = _try_selenium(url, wait=8)
            out["strategies_tried"].append(engine)
            if html and not _waf_signatures(html, status or 200):
                out["waf_bypassed"] = True
        except Exception as e:
            errors.append(f"selenium: {e}")
    else:
        # strategy sequence
        seq = []
        for i, ua in enumerate(_UAS):
            seq.append(("requests", i))
        seq.append(("curl", 0))
        seq.append(("lynx", 0))
        seq.append(("selenium", 0))
        for kind, idx in seq:
            try:
                out["strategies_tried"].append(kind)
                if kind == "requests":
                    st, fu, body, ct, eng = _try_requests(url, idx)
                elif kind == "curl":
                    st, fu, body, ct, eng = _try_curl(url, _UAS[0])
                elif kind == "lynx":
                    st, fu, body, ct, eng = _try_lynx(url)
                else:
                    st, fu, body, ct, eng = _try_selenium(url, wait=10)
                status, final_url, html, content_type, engine = st, fu, body, ct, eng
                if html and len(html) > 200 and not _waf_signatures(html, status or 200):
                    out["waf_bypassed"] = True
                    break
                # if not blocked but short, continue
                if html and len(html) > 500:
                    # accept even if ambiguous
                    if not _waf_signatures(html, status or 200):
                        out["waf_bypassed"] = True
                        break
            except Exception as e:
                errors.append(f"{kind}: {e}")
                continue
    out["status"] = status
    out["final_url"] = final_url
    out["content_type"] = content_type
    out["engine"] = engine
    out["html_excerpt"] = (html or "")[:8000]
    if errors:
        out["errors"] = errors[:8]
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html or "", "html.parser")
        out["title"] = (soup.title.string or "").strip() if soup.title and soup.title.string else ""
        text = soup.get_text(separator="\n", strip=True)
        out["text"] = (text or "")[:25000]
        links = []
        seen = set()
        for a in soup.find_all("a", href=True)[:300]:
            href = _up.urljoin(url, a.get("href", ""))
            label = (a.get_text(" ", strip=True) or "")[:80]
            if href not in seen:
                seen.add(href)
                links.append({"text": label, "href": href})
        out["links"] = links[:150]
    except Exception as e:
        out["parse_error"] = str(e)
        out["text"] = (html or "")[:25000]
    out["blocked"] = _waf_signatures(html or "", status or 200)
    out["anti_waf"] = {
        "engines": out["strategies_tried"],
        "bypassed": out["waf_bypassed"],
        "blocked_detected": out["blocked"],
        "tip": "If still blocked, use rendered mode or run from residential IP; self-healing retries enabled." if out["blocked"] else "ok"
    }
    try:
        # auto-learn WAF outcomes
        super_ai.learn("browser_waf", url + " blocked=" + str(out["blocked"]), html[:500] if html else "", "system",
                       "bypassed" if out["waf_bypassed"] else "blocked", 1 if out["waf_bypassed"] else -1, {"strategies": out["strategies_tried"]})
    except Exception:
        pass
    return out

@app.route("/api/browser/fetch", methods=["POST"])
def browser_fetch_ep():
    try:
        j = _req_json()
        url = _valid_url(j.get("url", ""))
        if not url:
            return jsonify({"error": "valid http/https url required"}), 400
        render = bool(j.get("render", False))
        data = browser_fetch(url, render=render, waf_bypass=True)
        return jsonify(data)
    except Exception as e:
        super_ai.record_error("browser.fetch", str(e), "")
        return jsonify({"error": str(e)}), 500

@app.route("/api/browser/screenshot", methods=["POST"])
def browser_screenshot_ep():
    try:
        j = _req_json()
        url = _valid_url(j.get("url", ""))
        if not url:
            return jsonify({"error": "valid http/https url required"}), 400
        import uuid as _uuid
        name = f"shot_{_uuid.uuid4().hex[:12]}.png"
        path = os.path.join(BROWSER_DIR, name)
        # headless browser via selenium + geckodriver + firefox snap (chromium snap unavailable)
        try:
            from selenium import webdriver
            from selenium.webdriver.firefox.service import Service
            from selenium.webdriver.firefox.options import Options
            opts = Options()
            opts.add_argument("--headless")
            for b in ("/snap/bin/geckodriver", "/usr/local/bin/geckodriver", "/usr/bin/geckodriver"):
                import os as _os
                if _os.path.isfile(b):
                    svc = Service(b); break
            else:
                raise RuntimeError("geckodriver not found")
            drv = webdriver.Firefox(service=svc, options=opts)
            try:
                drv.set_window_size(1280, 800)
                drv.get(url)
                import time as _t
                _t.sleep(2)
                drv.save_screenshot(path)
            finally:
                try: drv.quit()
                except Exception: pass
        except Exception as e:
            super_ai.record_error("browser.screenshot", str(e), url)
        if os.path.isfile(path):
            return jsonify({"image_url": f"/browser-shot/{name}", "path": path, "size": os.path.getsize(path)})
        return jsonify({"error": "screenshot failed (chromium headless)"}), 500
    except Exception as e:
        super_ai.record_error("browser.screenshot", str(e), "")
        return jsonify({"error": str(e)}), 500

@app.route("/browser-shot/<name>")
def browser_shot_serve(name):
    try:
        name = re.sub(r"[^a-zA-Z0-9._-]", "", str(name or ""))[:120]
        if not name:
            return jsonify({"error": "bad name"}), 400
        fp = os.path.normpath(os.path.join(BROWSER_DIR, name))
        if not fp.startswith(BROWSER_DIR) or not os.path.isfile(fp):
            return jsonify({"error": "not found"}), 404
        return send_file(fp, mimetype="image/png")
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/browser/analyze", methods=["POST"])
def browser_analyze_ep():
    try:
        j = _req_json()
        url = _valid_url(j.get("url", ""))
        if not url:
            return jsonify({"error": "valid http/https url required"}), 400
        model = str(j.get("model") or "").strip() or "dagbs/qwen2.5-coder-3b-instruct-abliterated:latest"
        question = str(j.get("prompt") or "Analyze this webpage for structure, technologies, security-relevant observations, and useful next steps.").strip()[:4000]
        data = browser_fetch(url, render=bool(j.get("render", False)))
        if data.get("error"):
            return jsonify(data), 500
        ctx = f"URL: {url}\nTITLE: {data.get('title','')}\nTEXT:\n{(data.get('text') or '')[:12000]}\nLINKS: {json.dumps((data.get('links') or [])[:40])}"
        ai_engine.ensure_ollama_running()
        try:
            _snap = super_ai.system_health(ai_engine.ensure_ollama_running, ai_engine.list_models, tools_status, list(SCANS.keys()))
            _aw = super_ai.awareness_prompt(_snap)
        except Exception:
            _aw = ""
        prompt = (_aw + "\n" + super_ai.anti_hallucinate_prompt(ctx) +
                  f"\nWeb analysis request: {question}\nPage context:\n{ctx[:16000]}\n"
                  "Return: 1) summary, 2) key observations, 3) technologies/stack hints, "
                  "4) security testing ideas (authorized, non-destructive), 5) suggested next commands.")
        reply = ai_engine.generate(prompt, model)
        try:
            _v = super_ai.verify_text(reply, ctx)
        except Exception:
            _v = {}
        super_ai.learn("browser_analyze", url + " | " + question, reply, model, "ok" if _v.get("ok") else "unverified",
                       1 if _v.get("ok") else -1, {"url": url})
        return jsonify({"url": url, "title": data.get("title", ""), "reply": reply, "verification": _v,
                        "text_excerpt": (data.get("text") or "")[:1500]})
    except Exception as e:
        super_ai.record_error("browser.analyze", str(e), "")
        return jsonify({"error": str(e)}), 500

# ---------------- vision (image -> Ollama vision if available) ----------------
@app.route("/api/vision", methods=["POST"])
def vision():
    try:
        model = str(request.form.get("model") or "").strip()[:200] or "dagbs/qwen2.5-coder-3b-instruct-abliterated:latest"
        prompt = str(request.form.get("prompt") or "Describe this image for a security/assistant review.")[:4000]
    except Exception:
        return jsonify({"error": "invalid params"}), 400
    if "image" not in request.files:
        return jsonify({"error": "no image"}), 400
    img = request.files["image"]
    try:
        img.seek(0, os.SEEK_END)
        _sz = img.tell()
        img.seek(0)
        if _sz > 10_000_000:
            return jsonify({"error": "image too large (>10MB)"}), 400
        if _sz == 0:
            return jsonify({"error": "empty image"}), 400
    except Exception:
        pass
    import uuid as _uuid
    tmp = os.path.join(HERE, "memory", f"_vision_{_uuid.uuid4().hex[:12]}.png")
    try:
        img.save(tmp)
    except Exception as e:
        return jsonify({"error": f"save failed: {e}"}), 500
    try:
        if os.path.getsize(tmp) > 10_000_000:
            try: os.remove(tmp)
            except Exception: pass
            return jsonify({"error": "image too large (>10MB)"}), 400
    except Exception:
        pass
    ai_engine.ensure_ollama_running()
    reply = ""
    try:
        import ollama as _ol
        with open(tmp, "rb") as f:
            import base64
            b64 = base64.b64encode(f.read()).decode()
        try:
            resp = _ol.chat(model=model, messages=[{"role": "user", "content": prompt, "images": [b64]}])
            reply = resp.get("message", {}).get("content", "") or "[empty vision response]"
        except Exception as e:
            try: _sz2 = os.path.getsize(tmp)
            except Exception: _sz2 = -1
            reply = f"[vision] model may not support images ({e}). File saved; describe manually. Size={_sz2} bytes."
    except Exception as e:
        reply = f"[vision error] {e}"
    try:
        os.remove(tmp)
    except Exception:
        pass
    return jsonify({"reply": reply})

# ---------------- notepad / scheduler / reports / tools / keys ----------------
@app.route("/api/notepad/load")
def notepad_load():
    try:
        txt = open(NOTEPAD, encoding="utf-8").read() if os.path.isfile(NOTEPAD) else ""
    except Exception:
        txt = ""
    return jsonify({"text": txt})

@app.route("/api/notepad/save", methods=["POST"])
def notepad_save():
    try:
        txt = str(_req_json().get("text", "") or "")
    except Exception:
        return jsonify({"error": "invalid text"}), 400
    try:
        with open(NOTEPAD, "w", encoding="utf-8") as f:
            f.write(txt[:200000])
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"saved": len(txt)})

@app.route("/api/schedule/add", methods=["POST"])
def sched_add():
    j = _req_json()
    try:
        name = str(j.get("name") or "scan")[:120]
        kind = str(j.get("kind", "scan"))[:20] or "scan"
        payload = str(j.get("payload", "") or "")[:500]
        run_at = str(j.get("run_at", "") or "")[:64]
    except Exception:
        return jsonify({"error": "invalid params"}), 400
    delay = 5
    if run_at:
        try:
            dt = datetime.fromisoformat(run_at)
            delay = (dt - datetime.now()).total_seconds()
        except Exception:
            return jsonify({"error": "bad run_at (use ISO datetime)"}), 400
        if delay < 1:
            delay = 1
        if delay > 86400:
            return jsonify({"error": "run_at too far in future (max 24h)"}), 400
    if kind == "scan" and not payload:
        return jsonify({"error": "payload (target) required for scan"}), 400
    try:
        con = sqlite3.connect(MEM_DB)
        con.execute("INSERT INTO schedules (name,kind,payload,run_at) VALUES (?,?,?,?)", (name, kind, payload, run_at))
        con.commit(); con.close()
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    # simple delayed executor (only spawned for real work)
    if kind == "scan" and payload:
        tgt = _sanitize_target(payload)
        if not tgt:
            return jsonify({"error": "invalid payload target"}), 400
        def _later(d=delay, t=tgt):
            try:
                time.sleep(min(d, 86400))
                start_scan(t, "auto")
            except Exception:
                pass
        threading.Thread(target=_later, daemon=True).start()
    return jsonify({"scheduled": name})

@app.route("/api/schedule/list")
def sched_list():
    try:
        con = sqlite3.connect(MEM_DB)
        rows = con.execute("SELECT id,name,kind,payload,run_at,done FROM schedules ORDER BY id DESC LIMIT 50").fetchall()
        con.close()
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify([{"id": r[0], "name": r[1], "kind": r[2], "payload": r[3], "run_at": r[4]} for r in rows])

@app.route("/api/reports")
def reports():
    try:
        files = sorted(glob.glob(os.path.join(AI_OUT, "*")), key=os.path.getmtime, reverse=True)[:100]
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    out = []
    for f in files:
        try:
            if os.path.isfile(f):
                out.append({"name": os.path.basename(f), "size": os.path.getsize(f)})
        except Exception:
            continue
    return jsonify(out)

@app.route("/api/reports/download")
def report_dl():
    try:
        name = str(request.args.get("name", "") or "")[:200]
    except Exception:
        return jsonify({"error": "bad name"}), 400
    if not name or "/" in name or name in (".", ".."):
        return jsonify({"error": "bad name"}), 400
    fp = os.path.normpath(os.path.join(AI_OUT, name))
    if not fp.startswith(AI_OUT) or not os.path.isfile(fp):
        return jsonify({"error": "bad name"}), 400
    return send_file(fp, as_attachment=True)

@app.route("/api/keys/status")
def keys():
    return jsonify(free_sources.keys_status())

@app.route("/api/tools/status")
def tools():
    base = tools_status()
    # extended desktop-tool detection (new tools menu)
    for b in ("docker", "git", "curl", "python3", "pip3", "node", "bun",
              "nmap", "masscan", "gobuster", "nikto", "sqlmap", "xterm", "gnome-terminal",
              "lynx", "wget", "firefox", "geckodriver"):
        try:
            if b not in base:
                base[b] = shutil.which(b) or ""
        except Exception:
            pass
    # full toolchain awareness: every executable in standard tool dirs (reconFTW + uv/go + local)
    _dirs = (os.path.join(HERE, "..", "Tools"), "/opt", "/usr/local/bin",
             os.path.expanduser("~/.local/bin"), "/snap/bin", os.path.expanduser("~/go/bin"))
    for d in _dirs:
        try:
            d = os.path.abspath(d)
            if not os.path.isdir(d):
                continue
            for fn in os.listdir(d):
                fp = os.path.join(d, fn)
                if os.path.isfile(fp) and os.access(fp, os.X_OK):
                    if fn not in base:
                        base[fn] = fp
        except Exception:
            pass
    # include all executables found on PATH that look like security/recon tools
    try:
        for pd in os.environ.get("PATH", "").split(os.pathsep):
            if not pd or not os.path.isdir(pd):
                continue
            for fn in os.listdir(pd):
                fp = os.path.join(pd, fn)
                if os.path.isfile(fp) and os.access(fp, os.X_OK) and fn not in base:
                    base[fn] = fp
    except Exception:
        pass
    try:
        base["tool_count"] = sum(1 for k, v in base.items() if v and k not in ("app_dir", "full_access", "tool_count", "waf_bypass", "os"))
    except Exception:
        base["tool_count"] = len(base)
    base["app_dir"] = HERE
    base["full_access"] = True
    base["os_profile"] = {
        "name": __import__("platform").platform(),
        "python": __import__("sys").version.split()[0],
        "user": os.environ.get("USER", ""),
    }
    return jsonify(base)

@app.route("/api/system/info")
def system_info():
    try:
        import platform as _pf
        info = {
            "os": {
                "system": _pf.system(),
                "release": _pf.release(),
                "version": _pf.version(),
                "machine": _pf.machine(),
                "platform": _pf.platform(),
                "distro": (open("/etc/os-release").read() if os.path.isfile("/etc/os-release") else ""),
            },
            "python": __import__("sys").version,
            "user": os.environ.get("USER", ""),
            "home": os.path.expanduser("~"),
            "cpu_count": __import__("os").cpu_count(),
            "disk": {},
            "memory": {},
        }
        try:
            usage = shutil.disk_usage(HERE)
            info["disk"] = {"total": usage.total, "used": usage.used, "free": usage.free}
        except Exception:
            pass
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    k, v = line.split(":", 1)
                    if k in ("MemTotal", "MemFree", "MemAvailable"):
                        info["memory"][k] = v.strip()
        except Exception:
            pass
        try:
            info["tools_total"] = len([x for x in tools_status().values() if x])
        except Exception:
            pass
        return jsonify(info)
    except Exception as e:
        super_ai.record_error("system_info", str(e), "")
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/install", methods=["POST"])
def tools_install():
    if install_state.get("running"):
        return jsonify({"already_running": True})
    install_state.update({"running": True, "done": False})
    recon_dir = HERE
    def _run():
        with open(INSTALL_LOG, "a", encoding="utf-8") as lf:
            lf.write("\n==== toolchain install started ====\n")
            try:
                if not os.path.isfile(os.path.join(HERE, "install.sh")):
                    lf.write("INSTALL ERROR: no install.sh found\n")
                    return
                script = os.path.join(HERE, "install.sh")
                p = subprocess.Popen(["bash", script, "--tools", "--verbose"],
                                     cwd=recon_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
                                     start_new_session=True)
                _track_proc(p)
                try:
                    for line in (p.stdout or []):
                        lf.write(line); lf.flush()
                except Exception as e:
                    lf.write(f"LOG STREAM ERROR: {e}\n")
                p.wait()
                lf.write(f"==== exit {p.returncode} ====\n")
            except Exception as e:
                lf.write(f"INSTALL ERROR: {e}\n")
            finally:
                install_state.update({"running": False, "done": True})
    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"started": True, "log": "toolchain_install.log"})

@app.route("/api/tools/install/log")
def tools_install_log():
    try:
        with open(INSTALL_LOG, encoding="utf-8", errors="ignore") as f:
            data = f.read()[-20000:]
    except FileNotFoundError:
        data = "(no install run yet)"
    return jsonify({"running": install_state.get("running", False), "done": install_state.get("done", False), "log": data})

@app.route("/api/shutdown", methods=["POST"])
def shutdown():
    """Stop ALL running jobs, then stop the server. Nothing keeps running after close."""
    try:
        full_cleanup(reason="api-shutdown")
    except Exception:
        try:
            full_cleanup_temporary()
        except Exception:
            pass
    func = request.environ.get("werkzeug.server.shutdown")
    if func:
        threading.Timer(0.5, func).start()
        return jsonify({"shutdown": True})
    threading.Timer(0.5, lambda: os._exit(0)).start()
    return jsonify({"shutdown": True})

@app.route("/api/client-disconnect", methods=["POST"])
def client_disconnect():
    """Browser tab closed — stop that session's polling only; server keeps running
    for other tabs. Real process cleanup happens on server exit (signal/atexit)
    or via /api/shutdown / /api/system/kill-all."""
    return jsonify({"ok": True})

def _graceful(signum, frame):
    print(f"\n[ultimate] signal {signum}: stopping jobs...", flush=True)
    try:
        full_cleanup(reason=f"signal {signum}")
    except Exception:
        pass
    # let atexit run once more harmlessly (guarded), then hard exit
    sys.exit(0)

atexit.register(full_cleanup, "atexit")


# ---------------- Website Crawler (advanced, own tab) ----------------
@app.route("/api/crawl/start", methods=["POST"])
def crawl_start():
    j = _req_json()
    url0 = j.get("url", "") if isinstance(j.get("url", ""), str) else ""
    try:
        max_pages = int(j.get("max_pages", 30) or 30)
    except Exception:
        max_pages = 30
    try:
        max_depth = int(j.get("max_depth", 2) or 2)
    except Exception:
        max_depth = 2
    same_domain = bool(j.get("same_domain", True))
    follow_external = bool(j.get("follow_external", False))
    render = bool(j.get("render", False))
    try:
        delay = float(j.get("delay", 0.2) or 0.2)
    except Exception:
        delay = 0.2
    try:
        timeout = int(j.get("timeout", 20) or 20)
    except Exception:
        timeout = 20
    respect_robots = bool(j.get("respect_robots", True))
    cid, err = crawler.start_crawl(url0, max_pages=max_pages, max_depth=max_depth,
                                   same_domain=same_domain, follow_external=follow_external,
                                   render=render, delay=delay, timeout=timeout,
                                   respect_robots=respect_robots)
    if err:
        return jsonify({"error": err}), 400
    return jsonify({"crawl_id": cid})

@app.route("/api/crawl/list")
def crawl_list():
    return jsonify(crawler.list_crawls())

@app.route("/api/crawl/<cid>/status")
def crawl_status(cid):
    cr = crawler.get_crawl(cid)
    if not cr:
        return jsonify({"error": "unknown crawl"}), 404
    return jsonify({"id": cid, "status": cr.get("status"), "seed": cr.get("seed"),
                    "pages": len(cr.get("pages", [])), "max_pages": cr.get("max_pages"),
                    "max_depth": cr.get("max_depth")})

@app.route("/api/crawl/<cid>/log")
def crawl_log(cid):
    cr = crawler.get_crawl(cid)
    if not cr:
        return jsonify({"error": "unknown crawl"}), 404
    try:
        tail = int(request.args.get("tail", "400"))
    except Exception:
        tail = 400
    tail = max(1, min(tail, 2000))
    log = cr.get("log", [])
    txt = "".join(log[-tail:]) if isinstance(log, list) else str(log)
    return jsonify({"log": txt})

@app.route("/api/crawl/<cid>/stop", methods=["POST"])
def crawl_stop(cid):
    if crawler.stop_crawl(cid):
        return jsonify({"stopped": cid})
    return jsonify({"error": "unknown crawl"}), 404

@app.route("/api/crawl/<cid>/pages")
def crawl_pages(cid):
    cr = crawler.get_crawl(cid)
    if not cr:
        return jsonify({"error": "unknown crawl"}), 404
    try:
        limit = int(request.args.get("limit", "200"))
    except Exception:
        limit = 200
    limit = max(1, min(limit, 2000))
    idx = [{"i": i, "url": p.get("url"), "final_url": p.get("final_url"),
            "status": p.get("status"), "ok": p.get("ok"), "title": p.get("title"),
            "tech": p.get("tech"), "forms": len(p.get("forms", [])),
            "links": len(p.get("links", [])), "text_len": p.get("text_len", 0),
            "blocked": p.get("blocked"), "time": p.get("time")}
           for i, p in enumerate(cr.get("pages", []))]
    return jsonify({"id": cid, "status": cr.get("status"), "count": len(idx),
                    "pages": idx[:limit]})

@app.route("/api/crawl/<cid>/page")
def crawl_page_detail(cid):
    cr = crawler.get_crawl(cid)
    if not cr:
        return jsonify({"error": "unknown crawl"}), 404
    url = request.args.get("url", "")
    i = None
    try:
        i = int(request.args.get("index", ""))
    except Exception:
        i = None
    page = None
    pages = cr.get("pages", [])
    if i is not None and 0 <= i < len(pages):
        page = pages[i]
    elif url:
        for p in pages:
            if p.get("url") == url or p.get("final_url") == url:
                page = p
                break
    if not page:
        return jsonify({"error": "page not found"}), 404
    return jsonify(page)

@app.route("/api/crawl/<cid>/analyze", methods=["POST"])
def crawl_analyze(cid):
    cr = crawler.get_crawl(cid)
    if not cr:
        return jsonify({"error": "unknown crawl"}), 404
    j = _req_json()
    model = str(j.get("model") or "").strip() or "dagbs/qwen2.5-coder-3b-instruct-abliterated:latest"
    ai_engine.ensure_ollama_running()
    prompt = crawler.analyze_prompt(cid)
    if not prompt:
        return jsonify({"error": "no crawl data"}), 400
    try:
        _snap = super_ai.system_health(ai_engine.ensure_ollama_running, ai_engine.list_models, tools_status, list(SCANS.keys()))
        prompt = super_ai.awareness_prompt(_snap) + "\n" + prompt
    except Exception:
        pass
    try:
        _ah = bool(j.get("anti_hallucinate", True))
        if _ah:
            prompt = prompt + super_ai.anti_hallucinate_prompt(crawler.crawl_context(cid, max_pages=15, max_chars=4000))
    except Exception:
        pass
    reply = ai_engine.generate(prompt, model)
    try:
        _v = super_ai.verify_text(reply, crawler.build_site_summary(cid))
    except Exception:
        _v = {}
    super_ai.learn("crawl_analyze", cr.get("seed", ""), reply, model, "ok" if _v.get("ok") else "unverified",
                   1 if _v.get("ok") else -1, {"crawl_id": cid})
    return jsonify({"reply": reply, "verification": _v, "summary": crawler.build_site_summary(cid)})

@app.route("/api/crawl/<cid>/analyze/page", methods=["POST"])
def crawl_analyze_page(cid):
    cr = crawler.get_crawl(cid)
    if not cr:
        return jsonify({"error": "unknown crawl"}), 404
    j = _req_json()
    model = str(j.get("model") or "").strip() or "dagbs/qwen2.5-coder-3b-instruct-abliterated:latest"
    url = j.get("url", "") if isinstance(j.get("url", ""), str) else ""
    i = j.get("index", None)
    page = None
    pages = cr.get("pages", [])
    try:
        if i is not None:
            i = int(i)
            if 0 <= i < len(pages):
                page = pages[i]
    except Exception:
        page = None
    if page is None and url:
        for p in pages:
            if p.get("url") == url or p.get("final_url") == url:
                page = p
                break
    if not page:
        return jsonify({"error": "page not found"}), 404
    ai_engine.ensure_ollama_running()
    ctx = (f"URL: {page.get('url')}\nTITLE: {page.get('title','')}\nTECH: {', '.join(page.get('tech',[]))}\n"
           f"FORMS: {len(page.get('forms',[]))}  LINKS: {len(page.get('links',[]))}\n"
           f"TEXT:\n{(page.get('text') or '')[:12000]}")
    prompt = ("Analyze this single crawled webpage thoroughly. Return: summary, purpose, technologies, "
              "key content/sections, forms & input surfaces, links of interest (internal/external), "
              "security-relevant observations with cited URLs, and suggested next steps/commands. "
              "Be honest, never fabricate. Page data:\n" + ctx)
    reply = ai_engine.generate(prompt, model)
    try:
        _v = super_ai.verify_text(reply, ctx)
    except Exception:
        _v = {}
    return jsonify({"url": page.get("url"), "reply": reply, "verification": _v})

@app.route("/api/crawl/<cid>/summary")
def crawl_summary(cid):
    cr = crawler.get_crawl(cid)
    if not cr:
        return jsonify({"error": "unknown crawl"}), 404
    return jsonify({"id": cid, "seed": cr.get("seed"), "status": cr.get("status"),
                    "pages": len(cr.get("pages", [])), "summary": crawler.build_site_summary(cid),
                    "tech": sorted(set(t for p in cr.get("pages", []) for t in (p.get("tech") or []))),
                    "page_index": [{"i": i, "url": p.get("url"), "title": p.get("title"),
                                    "status": p.get("status"), "ok": p.get("ok"),
                                    "tech": p.get("tech"), "links": len(p.get("links", [])),
                                    "forms": len(p.get("forms", [])), "text_len": p.get("text_len", 0)}
                                   for i, p in enumerate(cr.get("pages", []))]})


if __name__ == "__main__":
    for _sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(_sig, _graceful)
        except Exception:
            pass
    try:
        signal.signal(signal.SIGHUP, _graceful)
    except Exception:
        pass
    try:
        super_ai.start_watchdog(ollama_ensure_fn=ai_engine.ensure_ollama_running, interval=30)
    except Exception as e:
        super_ai.record_error("startup.watchdog", str(e), "")
    ai_engine.ensure_ollama_running()
    print("GBLOXKOS on http://127.0.0.1:5050  (free-mode, ollama local)")
    print(" GBLOXKOS ready")
    _host = os.environ.get("HOST", os.environ.get("GBLOXK_HOST", "127.0.0.1"))
    try:
        _port = int(os.environ.get("PORT", os.environ.get("GBLOXK_PORT", "5050")))
    except Exception:
        _port = 5050
    print(f" app ready on http://{_host}:{_port}")
    app.run(host=_host, port=_port, threaded=True)
