#!/usr/bin/env python3
"""Ollama AI engine — ported from reconftw_ai.py and extended for full auto-pentest.
Uses ONLY local Ollama models installed on system. No cloud APIs, no keys.
"""
import glob
import json
import os
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

try:
    import ollama
    HAS_OLLAMA_LIB = True
except ImportError:
    HAS_OLLAMA_LIB = False

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PROMPTS = os.path.join(HERE, "prompts.json")
CATEGORIES = ["osint", "subdomains", "hosts", "webs"]
REPORT_TYPES = ["executive", "brief", "bughunter", "pentest", "exploit", "remediation"]

def load_prompts(path=DEFAULT_PROMPTS):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def ensure_ollama_running():
    for _ in range(3):
        try:
            subprocess.run(["ollama", "list"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=15)
            return True
        except Exception:
            if shutil.which("ollama") is None:
                return False
            try:
                subprocess.Popen(["ollama", "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
            import time as _t
            _t.sleep(2)
    return False

def list_models():
    """Models actually installed on system (ollama list)."""
    try:
        out = subprocess.check_output(["ollama", "list"], text=True, timeout=15)
        models = []
        for line in out.splitlines()[1:]:
            parts = line.split()
            if parts:
                models.append({"name": parts[0], "raw": line.strip()})
        return models
    except Exception as e:
        return [{"name": "", "error": str(e)}]

def ensure_model_available(model):
    try:
        if not model or not isinstance(model, str):
            return "invalid model name"
        out = subprocess.check_output(["ollama", "list"], text=True, timeout=15)
        names = set()
        for line in out.splitlines()[1:]:
            parts = line.split()
            if parts:
                names.add(parts[0])
        if model not in names:
            subprocess.run(["ollama", "pull", model], check=True, timeout=1800)
        return True
    except Exception as e:
        return f"model check/pull failed: {e}"

def generate(prompt, model, timeout=600, retries=2):
    try:
        prompt = str(prompt or "")
        model = str(model or "").strip()
    except Exception:
        return "[Error] invalid prompt/model"
    if not model:
        return "[Error] model required"
    if not prompt.strip():
        return "[Error] prompt required"
    last_err = ""
    for _ in range(max(1, retries + 1)):
        if HAS_OLLAMA_LIB:
            try:
                resp = ollama.generate(model=model, prompt=prompt)
                txt = resp.get("response", "")
                if txt:
                    return txt
            except Exception as e:
                last_err = str(e)
        # CLI fallback (works even without python ollama lib)
        try:
            p = subprocess.run(["ollama", "run", model, prompt], capture_output=True, text=True, timeout=timeout)
            out = (p.stdout or p.stderr or "").strip()
            if out:
                return out
        except Exception as e:
            last_err = str(e)
        try:
            import time as _t
            _t.sleep(1)
        except Exception:
            pass
    return f"[Error] ollama generate failed: {last_err or 'empty response'}"

def read_files(category, results_dir, max_files=200, max_chars_per_file=50000):
    combined = ""
    cat_dir = os.path.join(results_dir, category)
    if not os.path.isdir(cat_dir):
        # also support flat scan dirs (native scanner) — look for files prefixed with category
        pats = glob.glob(os.path.join(results_dir, f"{category}*"), recursive=False)
        files = [p for p in pats if os.path.isfile(p)]
        if not files:
            return f"[Info] No '{category}' data (dir {cat_dir} missing)."
    else:
        files = [p for p in glob.glob(os.path.join(cat_dir, "**/*"), recursive=True) if os.path.isfile(p)]
    files = files[:max_files]
    for fp in files:
        rel = os.path.relpath(fp, results_dir)
        try:
            with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read().strip()[:max_chars_per_file]
            combined += f"--- {rel} ---\n{content}\n"
        except Exception as e:
            combined += f"[skip binary/unreadable {rel}: {e}]\n"
    # also include summary files at root
    for extra in ("summary.json", "findings.json", "free_recon.json"):
        ep = os.path.join(results_dir, extra)
        if os.path.isfile(ep):
            try:
                with open(ep, encoding="utf-8", errors="ignore") as f:
                    combined += f"--- {extra} ---\n{f.read()[:20000]}\n"
            except Exception:
                pass
    return combined.strip() or f"[Info] No readable files for {category}."

def process_category(category, data, model, report_type, prompts):
    tmpl = prompts.get(report_type, {}).get(category) or prompts.get(report_type, {}).get("overview", "Analyze:\n{data}")
    prompt = tmpl.format(data=data[:30000])
    return generate(prompt, model)

def analyze(results_dir, model, report_type="pentest", output_dir=None, prompts_path=DEFAULT_PROMPTS):
    prompts = load_prompts(prompts_path)
    if report_type not in prompts:
        report_type = "pentest"
    raw = {}
    with ThreadPoolExecutor(max_workers=4) as ex:
        futs = {ex.submit(read_files, c, results_dir): c for c in CATEGORIES}
        for fu in as_completed(futs):
            raw[futs[fu]] = fu.result()
    results = {}
    with ThreadPoolExecutor(max_workers=5) as ex:
        futs = {ex.submit(process_category, c, raw[c], model, report_type, prompts): c for c in CATEGORIES}
        for fu in as_completed(futs):
            results[futs[fu]] = fu.result()
    all_data = "\n\n".join(f"{c.upper()}:\n{raw[c][:8000]}" for c in CATEGORIES)
    results["overview"] = process_category("overview", all_data, model, report_type, prompts)
    if output_dir:
        save(results, output_dir, model, report_type)
    return results

def save(results, output_dir, model, report_type, fmt="md"):
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ext = "md" if fmt == "md" else "txt"
    path = os.path.join(output_dir, f"gbloxk_ai_{report_type}_{ts}.{ext}")
    with open(path, "w", encoding="utf-8") as f:
        if fmt == "md":
            f.write(f"# Gbloxk AI Pentest Report\n\n- Model: `{model}`\n- Profile: `{report_type}`\n- Date: `{ts}`\n\n")
            for cat, body in results.items():
                f.write(f"## {cat.upper()}\n\n{body}\n\n")
        else:
            f.write(f"Gbloxk AI Pentest Report | model={model} profile={report_type} date={ts}\n" + "=" * 60 + "\n\n")
            for cat, body in results.items():
                f.write(f"=== {cat.upper()} ===\n{body}\n\n")
    return path

def chat(model, messages, system="You are Gbloxk, a senior pentest copilot. Authorized testing only. Prefer free local tools (nmap, nuclei, ffuf, dalfox, dig, curl). Be concrete with commands."):
    """messages: [{'role':'user'|'assistant','content':str}]"""
    try:
        model = str(model or "").strip()
        system = str(system or "")[:20000]
    except Exception:
        return "[Error] invalid model/system"
    if not model:
        return "[Error] model required"
    if not isinstance(messages, list):
        return "[Error] messages must be a list"
    clean = []
    for m in messages[-12:]:
        if isinstance(m, dict) and "content" in m:
            try:
                clean.append({"role": str(m.get("role", "user"))[:20] or "user",
                              "content": str(m.get("content", ""))[:12000]})
            except Exception:
                continue
    messages = clean
    if HAS_OLLAMA_LIB:
        for _ in range(3):
            try:
                resp = ollama.chat(model=model, messages=[{"role": "system", "content": system}] + messages)
                txt = resp.get("message", {}).get("content", "")
                if txt:
                    return txt
            except Exception as e:
                last_e = e
                try:
                    import time as _t; _t.sleep(1)
                except Exception:
                    pass
        try:
            return f"[Error] chat failed: {last_e}"
        except Exception:
            pass
    # CLI fallback: concat into one prompt
    convo = system + "\n\n" + "\n".join(f"{m.get('role', 'user')}: {m.get('content', '')}" for m in messages[-10:]) + "\nassistant:"
    return generate(convo, model)
