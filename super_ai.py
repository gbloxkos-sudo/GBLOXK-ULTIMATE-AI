"""Super AI subsystem: self-learning, self-healing, self-awareness, anti-hallucination.

Designed to be imported by app_ultimate. Keeps its own SQLite tables and a
background watchdog. Every function degrades gracefully and never raises to
callers.
"""
import json
import os
import re
import shutil
import sqlite3
import threading
import time
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
MEM_DB = os.path.join(HERE, "memory", "chats.db")

_state_lock = threading.RLock()
_watchdog = {"thread": None, "running": False, "last": None, "errors": []}
_tools_cache = {"ts": 0, "data": {}}

# ---------------- db helpers ----------------
def _conn():
    os.makedirs(os.path.dirname(MEM_DB), exist_ok=True)
    con = sqlite3.connect(MEM_DB, timeout=30)
    con.execute("PRAGMA journal_mode=WAL")
    return con

def init_tables():
    try:
        con = _conn()
        con.execute("""CREATE TABLE IF NOT EXISTS ai_memory
            (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, session TEXT, kind TEXT,
             prompt TEXT, reply TEXT, model TEXT, outcome TEXT, score INTEGER DEFAULT 0, meta TEXT)""")
        con.execute("""CREATE TABLE IF NOT EXISTS ai_errors
            (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, component TEXT, error TEXT, context TEXT)""")
        con.execute("""CREATE TABLE IF NOT EXISTS ai_feedback
            (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, session TEXT, rating INTEGER, note TEXT, reply TEXT)""")
        con.execute("""CREATE TABLE IF NOT EXISTS ai_lessons
            (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, lesson TEXT, source TEXT, weight INTEGER DEFAULT 1)""")
        con.commit()
        con.close()
    except Exception as e:
        _record_error_now("super_ai.init_tables", str(e), "")

def _record_error_now(component, error, context):
    try:
        con = _conn()
        con.execute("INSERT INTO ai_errors(ts,component,error,context) VALUES (?,?,?,?)",
                    (datetime.now().isoformat(), str(component)[:200], str(error)[:2000], str(context)[:4000]))
        con.commit(); con.close()
    except Exception:
        pass
    try:
        _watchdog["errors"].append({"ts": datetime.now().isoformat(), "component": component, "error": str(error)[:300]})
        _watchdog["errors"] = _watchdog["errors"][-50:]
    except Exception:
        pass

def record_error(component, error, context=""):
    try:
        _record_error_now(component, error, context)
    except Exception:
        pass

# ---------------- self-learning memory ----------------
def learn(session, prompt, reply, model, outcome="unknown", score=0, meta=None):
    try:
        con = _conn()
        con.execute("""INSERT INTO ai_memory(ts,session,kind,prompt,reply,model,outcome,score,meta)
            VALUES (?,?,?,?,?,?,?,?,?)""",
                    (datetime.now().isoformat(), str(session or "default")[:80], "interaction",
                     str(prompt or "")[:8000], str(reply or "")[:12000], str(model or "")[:200],
                     str(outcome or "unknown")[:40], int(score or 0), json.dumps(meta or {})))
        con.commit(); con.close()
    except Exception as e:
        record_error("super_ai.learn", str(e), "")

def add_lesson(lesson, source="auto", weight=1):
    try:
        if not lesson or not str(lesson).strip():
            return
        con = _conn()
        con.execute("INSERT INTO ai_lessons(ts,lesson,source,weight) VALUES (?,?,?,?)",
                    (datetime.now().isoformat(), str(lesson)[:2000], str(source)[:80], int(weight or 1)))
        con.commit(); con.close()
    except Exception as e:
        record_error("super_ai.add_lesson", str(e), "")

def recent_errors(n=20):
    try:
        con = _conn()
        rows = con.execute("SELECT ts,component,error FROM ai_errors ORDER BY id DESC LIMIT ?", (int(n),)).fetchall()
        con.close()
        return [{"ts": r[0], "component": r[1], "error": r[2]} for r in rows]
    except Exception:
        return []

def lessons(n=20):
    try:
        con = _conn()
        rows = con.execute("SELECT lesson,weight,source FROM ai_lessons ORDER BY id DESC LIMIT ?", (int(n),)).fetchall()
        con.close()
        return [{"lesson": r[0], "weight": r[1], "source": r[2]} for r in rows]
    except Exception:
        return []

def recall_similar(query, k=4):
    """Cheap keyword recall over past interactions and lessons."""
    out = []
    try:
        terms = [w.lower() for w in re.findall(r"\w+", str(query or "")) if len(w) > 3][:12]
        if not terms:
            return out
        con = _conn()
        rows = con.execute("SELECT prompt,reply,outcome,score FROM ai_memory ORDER BY id DESC LIMIT 500").fetchall()
        scored = []
        for prompt, reply, outcome, score in rows:
            text = (prompt or "") + " " + (reply or "")
            tl = text.lower()
            sc = sum(tl.count(t) for t in set(terms))
            if sc > 0:
                scored.append((sc + (score or 0), prompt, reply, outcome))
        scored.sort(reverse=True)
        for sc, p, r, o in scored[:k]:
            out.append({"prompt": (p or "")[:300], "reply": (r or "")[:600], "outcome": o, "score": sc})
        lrows = con.execute("SELECT lesson,weight FROM ai_lessons ORDER BY id DESC LIMIT 200").fetchall()
        con.close()
        for lesson, weight in lrows:
            ll = (lesson or "").lower()
            if any(t in ll for t in terms):
                out.append({"lesson": lesson, "weight": weight})
    except Exception as e:
        record_error("super_ai.recall_similar", str(e), "")
    return out[:k + 3]

def feedback(session, rating, note, reply):
    try:
        con = _conn()
        con.execute("INSERT INTO ai_feedback(ts,session,rating,note,reply) VALUES (?,?,?,?,?)",
                    (datetime.now().isoformat(), str(session or "default")[:80], int(rating or 0),
                     str(note or "")[:2000], str(reply or "")[:4000]))
        con.commit()
        # auto-learn: bad rating becomes a lesson
        if int(rating or 0) < 0:
            add_lesson(f"Avoid previous unhelpful pattern: {str(note or '')[:400]}", source="feedback", weight=2)
        elif int(rating or 0) > 0:
            add_lesson(f"Repeat successful pattern: {str(note or '')[:400]}", source="feedback", weight=1)
        con.close()
    except Exception as e:
        record_error("super_ai.feedback", str(e), "")

# ---------------- self-awareness snapshot ----------------
def system_health(ollama_fn=None, list_models_fn=None, tools_status_fn=None, scans=None):
    snap = {"ts": datetime.now().isoformat(), "app": "GBLOXK Ultimate AI", "ollama": False, "models": [],
            "tools_installed": 0, "tools_total": 0, "recent_errors": [], "scans": 0, "memory_items": 0}
    try:
        if ollama_fn:
            snap["ollama"] = bool(ollama_fn())
    except Exception as e:
        snap["ollama_error"] = str(e)
    try:
        if list_models_fn:
            ms = list_models_fn() or []
            snap["models"] = [m.get("name") if isinstance(m, dict) else str(m) for m in ms][:20]
    except Exception:
        pass
    try:
        if tools_status_fn:
            ts = tools_status_fn() or {}
            vals = [v for k, v in ts.items() if k not in ("app_dir", "full_access")]
            snap["tools_installed"] = sum(1 for v in vals if v)
            snap["tools_total"] = len(vals)
    except Exception:
        pass
    try:
        if scans is not None:
            snap["scans"] = len(scans)
    except Exception:
        pass
    try:
        snap["recent_errors"] = [e.get("error", "")[:120] for e in recent_errors(5)]
        con = _conn()
        snap["memory_items"] = (con.execute("SELECT COUNT(*) FROM ai_memory").fetchone() or [0])[0]
        con.close()
    except Exception:
        pass
    return snap

def awareness_prompt(snap):
    errs = "; ".join(snap.get("recent_errors") or []) or "none"
    models = ", ".join(snap.get("models") or []) or "(none)"
    return (
        f"\n[SELF-AWARENESS SNAPSHOT]\n"
        f"ollama_running={snap.get('ollama')} installed_models=[{models}]\n"
        f"tools_installed={snap.get('tools_installed')}/{snap.get('tools_total')} scans={snap.get('scans')} "
        f"memory_items={snap.get('memory_items')}\n"
        f"recent_errors={errs}\n"
        f"You are the GBLOXK Ultimate AI system. Be honest about capabilities and installed tools above. "
        f"Never invent tools, files, findings, or results not present. Cite local evidence when possible.\n"
    )

# ---------------- anti-hallucination ----------------
_CMD_RE = re.compile(r"`([^`\n]{1,120})`")
_PATH_RE = re.compile(r"(?:^|[\s(])(/(?:[A-Za-z0-9._\-/]+))")
_TOOL_NAMES = ("nmap", "nuclei", "ffuf", "dalfox", "sqlmap", "curl", "dig", "whois", "subfinder",
               "httpx", "dnsx", "katana", "naabu", "amass", "gobuster", "nikto", "masscan")

def verify_text(text, evidence=""):
    res = {"tools": {}, "paths": {}, "risk": 0.0, "notes": []}
    try:
        txt = str(text or "")
        # tools mentioned
        mentioned_tools = set()
        for t in _TOOL_NAMES:
            if re.search(r"(?<![A-Za-z])" + re.escape(t) + r"(?![A-Za-z])", txt):
                mentioned_tools.add(t)
        for t in mentioned_tools:
            res["tools"][t] = bool(shutil.which(t))
        missing_tools = [t for t in mentioned_tools if not res["tools"][t]]
        if missing_tools:
            res["risk"] += 0.15 * len(missing_tools)
            res["notes"].append("tools not installed: " + ", ".join(missing_tools))
        # paths mentioned
        paths = set(_PATH_RE.findall(txt))
        for p in paths:
            if len(p) < 3:
                continue
            res["paths"][p] = os.path.exists(p)
        bad_paths = [p for p, ok in res["paths"].items() if not ok]
        if bad_paths:
            res["risk"] += 0.1 * min(len(bad_paths), 5)
            res["notes"].append("paths not found: " + ", ".join(bad_paths[:5]))
        # backtick commands: check leading binary exists
        for cmd in set(_CMD_RE.findall(txt)):
            cmd = cmd.strip()
            if not cmd or " " not in cmd and "/" not in cmd:
                continue
            first = cmd.split()[0].split("/")[-1]
            if first in _TOOL_NAMES or first in ("python3", "bash", "sh", "ollama"):
                if not shutil.which(first):
                    res["risk"] += 0.1
                    res["notes"].append(f"command binary missing: {first}")
        # evidence grounding: if evidence provided, require overlap
        if evidence:
            q_terms = set(w.lower() for w in re.findall(r"\w+", evidence) if len(w) > 4)
            txt_terms = set(w.lower() for w in re.findall(r"\w+", txt) if len(w) > 4)
            if q_terms and txt_terms:
                overlap = len(q_terms & txt_terms) / max(1, len(txt_terms))
                if overlap < 0.05:
                    res["risk"] += 0.2
                    res["notes"].append("low overlap with evidence (possible hallucination)")
        res["risk"] = min(1.0, round(res["risk"], 3))
        res["ok"] = res["risk"] < 0.4
    except Exception as e:
        res["error"] = str(e)
        record_error("super_ai.verify_text", str(e), text[:500])
    return res

def anti_hallucinate_prompt(evidence):
    return (
        "\n[ANTI-HALLUCINATION RULES]\n"
        "1. Use ONLY tools that are installed and listed in the self-awareness snapshot.\n"
        "2. Never fabricate scan results, file paths, CVEs, hosts, or findings; say 'no data' when unknown.\n"
        "3. Every technical claim must cite evidence (file path, command output, or memory entry) in brackets.\n"
        "4. If unsure, state uncertainty and propose verification commands.\n"
        "5. Prefer local Ollama + free tools; mention model limitations honestly.\n"
        + (f"\nEVIDENCE:\n{str(evidence)[:6000]}\n" if evidence else "")
    )

# ---------------- self-healing watchdog ----------------
def _ollama_ok():
    try:
        import subprocess
        subprocess.run(["ollama", "list"], stdout=__import__("subprocess").DEVNULL, stderr=__import__("subprocess").DEVNULL, timeout=10, check=True)
        return True
    except Exception:
        return False

def ensure_ollama():
    if _ollama_ok():
        return True
    # attempt restart
    try:
        import subprocess, shutil
        if shutil.which("ollama"):
            subprocess.Popen(["ollama", "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(3)
            return _ollama_ok()
    except Exception as e:
        record_error("super_ai.ensure_ollama", str(e), "")
    return False

def watchdog_loop(interval=30, ollama_ensure_fn=None):
    _watchdog["running"] = True
    ensure = ollama_ensure_fn or ensure_ollama
    while _watchdog["running"]:
        try:
            _watchdog["last"] = datetime.now().isoformat()
            if not ensure():
                record_error("watchdog", "ollama not running", "")
            # prune errors memory
            _watchdog["errors"] = _watchdog["errors"][-50:]
        except Exception as e:
            record_error("watchdog.loop", str(e), "")
        time.sleep(interval)

def start_watchdog(ollama_ensure_fn=None, interval=30):
    try:
        if _watchdog["thread"] and _watchdog["thread"].is_alive():
            return _watchdog["thread"]
        t = threading.Thread(target=watchdog_loop, args=(interval, ollama_ensure_fn), daemon=True)
        _watchdog["thread"] = t
        t.start()
        return t
    except Exception as e:
        record_error("super_ai.start_watchdog", str(e), "")
        return None

def stop_watchdog():
    _watchdog["running"] = False

def watchdog_status():
    return {"running": _watchdog["running"],
            "thread_alive": bool(_watchdog["thread"] and _watchdog["thread"].is_alive()),
            "last": _watchdog["last"],
            "recent_errors": _watchdog["errors"][-10:]}

init_tables()
