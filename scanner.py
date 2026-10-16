#!/usr/bin/env python3
"""Scan orchestration: 100% FREE native scanners. No paid keys, no reconFTW dependency."""
import json
import atexit
import os
import shutil
import signal
import socket
import ssl
import subprocess
import threading
import urllib.request
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
SCANS_ROOT = os.path.join(HERE, "scans")
os.makedirs(SCANS_ROOT, exist_ok=True)

SCANS = {}

def _stopped(scan_id):
    sc = SCANS.get(scan_id)
    return bool(sc and sc.get("stop_event") and sc["stop_event"].is_set())

def _run_tracked(scan_id, cmd, timeout=1200, **kw):
    sc = SCANS.get(scan_id)
    kw.setdefault("start_new_session", True)
    proc = subprocess.Popen(cmd, **kw)
    if sc is not None:
        sc.setdefault("procs", []).append(proc)
    try:
        return proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_proc(proc)
        return proc.communicate()
    finally:
        if sc is not None and proc in sc.get("procs", []):
            try:
                sc["procs"].remove(proc)
            except ValueError:
                pass

def _kill_proc(proc):
    try:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except Exception:
            proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                proc.kill()
    except Exception:
        pass

def stop_scan(scan_id):
    sc = SCANS.get(scan_id)
    if not sc:
        return False
    try:
        ev = sc.get("stop_event")
        if ev is None:
            ev = threading.Event()
            sc["stop_event"] = ev
        ev.set()
    except Exception:
        pass
    for proc in list(sc.get("procs", [])):
        _kill_proc(proc)
    if sc.get("status") == "running":
        sc["status"] = "stopped"
        _log(scan_id, "scan STOPPED by user — all jobs killed.")
    return True

def stop_all():
    for sid, sc in list(SCANS.items()):
        if sc.get("status") in ("running", "queued"):
            try:
                stop_scan(sid)
            except Exception:
                pass

atexit.register(stop_all)

TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8000, 8001, 8888, 9000, 9090, 27017, 6379, 9200, 11211, 8081, 8444, 3000, 5000, 8008, 8880]
COMMON_SUBS = ["www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "cpanel", "whm", "webdisk", "admin", "blog", "dev", "test", "staging", "api", "app", "vpn", "m", "mobile", "shop", "portal", "secure", "owa", "exchange", "intranet", "extranet", "beta", "demo"]

def _log(scan_id, msg):
    sc = SCANS.get(scan_id)
    line = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n"
    if sc is not None:
        sc["log"].append(line)
        try:
            with open(os.path.join(sc["dir"], "scan.log"), "a", encoding="utf-8") as f:
                f.write(line)
        except Exception:
            pass
    print(line, end="")

def _write(scan_dir, name, content):
    try:
        os.makedirs(scan_dir, exist_ok=True)
    except Exception:
        pass
    if isinstance(content, (dict, list)):
        content = json.dumps(content, indent=2)
    with open(os.path.join(scan_dir, name), "w", encoding="utf-8", errors="ignore") as f:
        f.write(str(content))

def native_free_scan(scan_id, target):
    sc = SCANS[scan_id]
    d = sc["dir"]
    os.makedirs(os.path.join(d, "osint"), exist_ok=True)
    os.makedirs(os.path.join(d, "subdomains"), exist_ok=True)
    os.makedirs(os.path.join(d, "hosts"), exist_ok=True)
    os.makedirs(os.path.join(d, "webs"), exist_ok=True)
    findings = {"target": target, "started": datetime.now().isoformat(), "free_mode": True, "items": []}

    from free_sources import free_subdomains, free_asn_ip, free_whois, free_dns_records
    _log(scan_id, "[free] subdomain enum via crt.sh + certspotter + hackertarget (no keys)...")
    try:
        subs, srcs = free_subdomains(target)
        _write(d + "/subdomains", "free_subdomains.txt", "\n".join(subs) or "(none found)")
        _write(d + "/subdomains", "free_sources.json", srcs)
        _log(scan_id, f"[free] subdomains: {len(subs)} ({srcs})")
        findings["items"].append({"type": "subdomains", "count": len(subs), "severity": "info"})
    except Exception as e:
        _log(scan_id, f"[free] subdomain error: {e}")
        subs = []

    _log(scan_id, "[free] DNS brute (common names, local resolver)...")
    brute = []
    try:
        for sub in COMMON_SUBS:
            fq = f"{sub}.{target}"
            if fq in (subs or []):
                continue
            try:
                socket.gethostbyname(fq)
                brute.append(fq)
            except Exception:
                pass
        if brute:
            _write(d + "/subdomains", "brute.txt", "\n".join(brute))
        _log(scan_id, f"[free] brute found: {len(brute)}")
    except Exception as e:
        _log(scan_id, f"[free] brute error: {e}")
    all_hosts = sorted(set(subs) | set(brute) | {target})

    _log(scan_id, "[free] WHOIS/RDAP + ASN/Geo (free sources)...")
    try:
        w = free_whois(target)
        _write(d + "/osint", "whois_free.txt", f"method: {w['method']}\n\n{w['data'][:5000]}")
        a = free_asn_ip(target)
        _write(d + "/osint", "asn_geo_free.json", a)
        dnsr = free_dns_records(target)
        _write(d + "/osint", "dns_records_free.json", dnsr)
        _log(scan_id, f"[free] ASN: {a.get('asn')} {a.get('asn_desc','')}")
    except Exception as e:
        _log(scan_id, f"[free] osint error: {e}")

    _log(scan_id, "[free] port scan (nmap if present, else socket)...")
    open_ports = {}
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        ip = None
    if ip and shutil.which("nmap") and not _stopped(scan_id):
        try:
            out, _ = _run_tracked(scan_id, ["nmap", "-Pn", "--top-ports", "100", "-sV", "-n", "--open", "-T4", ip],
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=600)
            _write(d + "/hosts", "nmap_top100.txt", out or "(no output)")
            _log(scan_id, "[free] nmap top-100 done")
            open_ports["nmap"] = "see nmap_top100.txt"
        except Exception as e:
            _log(scan_id, f"[free] nmap error: {e}")
    if ip:
        sock_open = []
        for port in TOP_PORTS:
            if _stopped(scan_id):
                _log(scan_id, "[free] socket scan stopped.")
                break
            try:
                s = socket.socket()
                s.settimeout(1.2)
                if s.connect_ex((ip, port)) == 0:
                    sock_open.append(port)
                    try:
                        s.settimeout(2)
                        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = s.recv(256).decode("ignore").strip().split("\n")[0][:120]
                    except Exception:
                        banner = ""
                    findings["items"].append({"type": "open-port", "port": port, "banner": banner,
                                             "severity": "medium" if port in (21, 23, 445, 3306, 3389, 5900, 6379, 27017) else "info"})
                s.close()
            except Exception:
                pass
        open_ports["socket"] = sock_open
        _write(d + "/hosts", "open_ports.json", {"ip": ip, "open": sock_open})
        _log(scan_id, f"[free] socket scan open: {sock_open}")
    else:
        _log(scan_id, "[free] target did not resolve; skipping port scan")

    _log(scan_id, "[free] web probe + header/CORS/SSL checks...")
    web_targets = []
    for h in all_hosts[:40]:
        for scheme in ("https", "http"):
            web_targets.append(f"{scheme}://{h}")
    alive = []
    for urlw in web_targets:
        if _stopped(scan_id):
            _log(scan_id, "[free] web probe stopped.")
            break
        try:
            req = urllib.request.Request(urlw, headers={"User-Agent": "Gbloxk-Pentest-AI"}, method="HEAD")
            with urllib.request.urlopen(req, timeout=8) as r:
                alive.append({"url": urlw, "status": r.status, "server": r.headers.get("Server", ""),
                              "powered": r.headers.get("X-Powered-By", "")})
                break
        except Exception:
            continue
    for a in alive[:20]:
        try:
            u = a["url"]
            req = urllib.request.Request(u, headers={"User-Agent": "Gbloxk-Pentest-AI", "Origin": "https://evil.example"})
            with urllib.request.urlopen(req, timeout=8) as r:
                h = dict(r.headers)
                a["missing_headers"] = [x for x in ("Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security", "X-Content-Type-Options") if x not in h]
                a["cors_wildcard"] = h.get("Access-Control-Allow-Origin", "") in ("*", "https://evil.example")
                if a["missing_headers"]:
                    findings["items"].append({"type": "missing-sec-headers", "url": u, "headers": a["missing_headers"], "severity": "low"})
                if a["cors_wildcard"]:
                    findings["items"].append({"type": "cors-misconfig", "url": u, "severity": "medium"})
        except Exception:
            pass
        try:
            host = u.split("://")[1].split("/")[0]
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.settimeout(6)
                s.connect((host, 443))
                cert = s.getpeercert()
                a["ssl_issuer"] = str(cert.get("issuer", ""))[:150]
                a["ssl_exp"] = str(cert.get("notAfter", ""))
        except Exception:
            pass
    _write(d + "/webs", "alive.json", alive)
    _log(scan_id, f"[free] web alive: {len(alive)}")

    if shutil.which("nuclei") and not _stopped(scan_id):
        _log(scan_id, "[free] nuclei quick scan (free templates)...")
        try:
            targets_file = os.path.join(d, "webs", "alive_urls.txt")
            with open(targets_file, "w") as f:
                f.write("\n".join(a["url"] for a in alive[:30]))
            out, _ = _run_tracked(scan_id, ["nuclei", "-l", targets_file, "-severity", "critical,high,medium", "-silent", "-nc"],
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=1200)
            _write(d + "/webs", "nuclei_free.txt", out or "(no findings)")
            _log(scan_id, "[free] nuclei done")
        except Exception as e:
            _log(scan_id, f"[free] nuclei error: {e}")
    elif _stopped(scan_id):
        _log(scan_id, "[free] nuclei skipped (scan stopped).")
    else:
        _log(scan_id, "[free] nuclei not installed — skipping (install nmap/nuclei via setup.sh)")

    _write(d, "findings.json", findings)
    return findings

def run_scan(scan_id):
    sc = SCANS[scan_id]
    target = sc["target"]
    try:
        sc["status"] = "running"
        _log(scan_id, f"scan started: target={target} (100% free, no reconFTW needed)")
        native_free_scan(scan_id, target)
        if _stopped(scan_id):
            sc["status"] = "stopped"
            _log(scan_id, "scan STOPPED. Partial results kept on disk.")
        else:
            sc["status"] = "done"
            _log(scan_id, "scan DONE. Open AI Analysis tab to generate report.")
    except Exception as e:
        sc["status"] = "error"
        _log(scan_id, f"scan ERROR: {e}")

def start_scan(target, mode="auto"):
    _ = mode  # native-only in GBLOXKOS edition
    try:
        safe = str(target or "unknown")[:200]
    except Exception:
        safe = "unknown"
    safe = "".join(c if (c.isalnum() or c in ".-_") else "_" for c in safe)[:120] or "unknown"
    scan_id = f"{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}_{safe}"
    sdir = os.path.join(SCANS_ROOT, scan_id)
    os.makedirs(sdir, exist_ok=True)
    SCANS[scan_id] = {"id": scan_id, "target": target, "mode": "auto", "status": "queued",
                      "log": [], "dir": sdir, "started": datetime.now().isoformat(),
                      "procs": [], "stop_event": threading.Event()}
    t = threading.Thread(target=run_scan, args=(scan_id,), daemon=True)
    SCANS[scan_id]["thread"] = t
    t.start()
    return scan_id

def tools_status():
    bins = ["nmap", "nuclei", "ffuf", "dalfox", "sqlmap", "curl", "dig", "whois",
            "subfinder", "httpx", "dnsx", "katana", "naabu", "amass", "gobuster",
            "nikto", "masscan", "docker", "git", "python3", "ollama", "geckodriver",
            "firefox", "chromium-browser", "lynx", "wget", "go", "pip3"]
    st = {}
    for b in bins:
        st[b] = shutil.which(b) or ""
    return st
