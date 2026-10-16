#!/usr/bin/env python3
"""Free workaround data sources — zero paid API keys required.

Maps every paid reconFTW secret to a 100% free alternative:
  SHODAN_API_KEY  -> nmap active scan + socket fallback + HackTarget reverse-IP (free tier, no key)
  WHOISXML_API    -> system `whois` + free RDAP (Verisign/ARIN/RIPE) + HackTarget whois (no key)
  PDCP_API_KEY    -> BGPView API (no key) + RIPEstat (no key) + crt.sh (no key)
  COLLAB/XSS srv  -> public interactsh oast.fun (free) or local HTTP listener
  GitHub tokens   -> unauthenticated GitHub API (60/h, free) + crt.sh + certspotter + Wayback (no key)
  subfinder paid providers (VT, SecurityTrails...) -> skipped; free sources only
"""
import json
import os
import shutil
import socket
import subprocess
import urllib.request
import urllib.parse

TIMEOUT = 15
UA = {"User-Agent": "Gbloxk-Pentest-AI (free-mode, authorized-testing-only)"}

def _get_json(url):
    req = urllib.request.Request(url, headers=UA)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8", "ignore"))
    except Exception as e:
        return {"_error": str(e)}

def _get_text(url):
    req = urllib.request.Request(url, headers=UA)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.read().decode("utf-8", "ignore")
    except Exception as e:
        return f"[free-source error] {url}: {e}"

# ---------- free subdomains (replaces paid APIs) ----------
def free_subdomains(domain):
    """crt.sh + certspotter + hackertarget + anubis (all free, no key)."""
    found = set()
    sources = {}
    # crt.sh (free, no key)
    try:
        data = _get_json(f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json")
        if isinstance(data, list):
            for e in data:
                nv = e.get("name_value", "")
                for s in nv.split("\n"):
                    s = s.strip().lower()
                    if s.startswith("*."):
                        s = s[2:]
                    if s and (s == domain or s.endswith("." + domain)):
                        found.add(s)
            sources["crt.sh"] = f"{len(found)} hosts"
        else:
            sources["crt.sh"] = "unavailable"
    except Exception as e:
        sources["crt.sh"] = f"error: {e}"
    # certspotter (free, no key)
    try:
        data = _get_json(f"https://api.certspotter.com/v1/issuances?domain={urllib.parse.quote(domain)}&include_subdomains=true&expand=dns_names")
        n0 = len(found)
        if isinstance(data, list):
            for e in data:
                for s in e.get("dns_names", []):
                    s = str(s or "").strip().lower()
                    if s.startswith("*."):
                        s = s[2:]
                    if s and (s == domain or s.endswith("." + domain)):
                        found.add(s)
        sources["certspotter"] = f"+{len(found)-n0} new"
    except Exception as e:
        sources["certspotter"] = f"error: {e}"
    # hackertarget hostsearch (free tier, no key)
    try:
        txt = _get_text(f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(domain)}")
        n0 = len(found)
        for line in txt.splitlines():
            if "," in line:
                h = line.split(",")[0].strip().lower()
                if h and (h == domain or h.endswith("." + domain)):
                    found.add(h)
        sources["hackertarget"] = f"+{len(found)-n0} new" if "error" not in txt[:60] else "rate-limited (free tier)"
    except Exception as e:
        sources["hackertarget"] = f"error: {e}"
    return sorted(found), sources

# ---------- free ASN / IP info (replaces PDCP_API_KEY + IPINFO paid) ----------
def free_asn_ip(target):
    out = {}
    try:
        ip = socket.gethostbyname(target) if not _is_ip(target) else target
        out["resolved_ip"] = ip
    except Exception as e:
        out["resolved_ip"] = f"unresolvable: {e}"
        return out
    ip = out["resolved_ip"]
    # BGPView (free, no key)
    bv = _get_json(f"https://api.bgpview.io/ip/{ip}")
    try:
        d = bv.get("data", {})
        out["asn"] = d.get("asn", {}).get("asn")
        out["asn_desc"] = d.get("asn", {}).get("description")
        out["prefixes"] = [p.get("prefix") for p in d.get("prefixes", [])][:5]
    except Exception:
        out["bgpview"] = "unavailable"
    # RIPEstat Geo (free, no key)
    rs = _get_json(f"https://stat.ripe.net/data/rpki-validation/data.json?resource={ip}")
    out["ripestat_status"] = rs.get("status", "unknown") if isinstance(rs, dict) else "unavailable"
    # ip-api.com free tier (no key, 45 req/min)
    geo = _get_json(f"http://ip-api.com/json/{ip}?fields=status,country,city,org,isp,query")
    if isinstance(geo, dict) and geo.get("status") == "success":
        out["geo"] = {k: geo.get(k) for k in ("country", "city", "org", "isp", "query")}
    return out

def _is_ip(s):
    try:
        import ipaddress as _ip
        _ip.ip_address(str(s or "").strip())
        return True
    except Exception:
        return False

# ---------- free WHOIS (replaces WHOISXML_API paid) ----------
def free_whois(domain):
    out = {"method": None, "data": ""}
    # 1. system whois (free)
    if shutil.which("whois"):
        try:
            p = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=25)
            txt = (p.stdout or "")[:6000]
            if txt and "No match" not in txt[:200]:
                out["method"] = "system-whois (free)"
                out["data"] = txt
                return out
        except Exception:
            pass
    # 2. free RDAP Verisign (no key)
    try:
        tld = domain.rsplit(".", 1)[-1]
        if tld in ("com", "net"):
            data = _get_text(f"https://rdap.verisign.com/{tld}/v1/domain/{urllib.parse.quote(domain)}")
            if "handle" in data[:2000] or "lamos" in data.lower()[:500] or len(data) > 200:
                out["method"] = "rdap.verisign.com (free)"
                out["data"] = data[:6000]
                return out
    except Exception:
        pass
    # 3. hackertarget whois (free tier, no key)
    txt = _get_text(f"https://api.hackertarget.com/whois/?q={urllib.parse.quote(domain)}")
    out["method"] = "hackertarget-whois (free tier)"
    out["data"] = txt[:6000]
    return out

# ---------- free DNS / reverse (helps replace Shodan passive) ----------
def free_dns_records(domain):
    recs = {}
    try:
        domain = str(domain or "").strip()
    except Exception:
        return {"error": "invalid domain"}
    if not domain:
        return {"error": "empty domain"}
    # A + AAAA via getaddrinfo (no early break)
    try:
        ans = socket.getaddrinfo(domain, None)
        v4 = sorted(set(a[4][0] for a in ans if "." in str(a[4][0]) and ":" not in str(a[4][0])))
        v6 = sorted(set(a[4][0] for a in ans if ":" in str(a[4][0])))
        if v4:
            recs["A"] = v4
        if v6:
            recs["AAAA"] = v6
        if not v4 and not v6:
            recs["A"] = []
    except Exception as e:
        recs["A"] = [f"error: {e}"]
    for rtype, cmd in (("MX", ["nslookup", "-type=mx", domain]),
                       ("TXT", ["nslookup", "-type=txt", domain]),
                       ("NS", ["nslookup", "-type=ns", domain])):
        if shutil.which("nslookup"):
            try:
                pr = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                recs[rtype] = (pr.stdout or "")[:2000] or "(no records)"
            except Exception as e:
                recs[rtype] = f"error: {e}"
        else:
            recs[rtype] = "(nslookup not installed)"
    return recs


def _probe_free_sources():
    out = {}
    try:
        txt = _get_text("https://crt.sh/?q=%25.example.com&output=json")[:4000].lower()
        out["crt.sh"] = "ok" if ("certificate" in txt or "example" in txt) and "error" not in txt[:60] else "unreachable"
    except Exception as e:
        out["crt.sh"] = f"error: {e}"
    return out


# ---------- status: which paid keys are missing and what free fallback covers them ----------
def keys_status():
    env = os.environ
    def has(k):
        return bool(env.get(k))
    gh_tokens = os.path.expanduser("~/Tools/.github_tokens")
    has_gh = os.path.exists(gh_tokens)
    return {
        "paid_keys": {
            "SHODAN_API_KEY": {"present": has("SHODAN_API_KEY"), "free_fallback": "nmap/naabu active scan + socket scan (built-in, free). Passive Shodan auto-disabled."},
            "WHOISXML_API": {"present": has("WHOISXML_API"), "free_fallback": "system whois + RDAP (verisign/arin/ripe) + hackertarget whois (all free)."},
            "PDCP_API_KEY": {"present": has("PDCP_API_KEY"), "free_fallback": "BGPView + RIPEstat + crt.sh ASN pivoting (free, no key). asnmap auto-skipped."},
            "COLLAB_SERVER": {"present": has("COLLAB_SERVER"), "free_fallback": "public interactsh oast.fun (free) or local listener on :8080."},
            "XSS_SERVER": {"present": has("XSS_SERVER"), "free_fallback": "dalfox non-callback mode + local listener (free)."},
            "GITHUB_TOKENS": {"present": has_gh, "free_fallback": "unauthenticated GitHub API 60/hr + crt.sh + certspotter + Wayback (free). Create free tokens: github.com/settings/tokens (no payment)."},
        },
        "free_sources_reachable": _probe_free_sources(),
        "mode": "FREE-MODE (no paid keys required)",
        "how_to_stay_free": [
            "GitHub token (free, raises 60->5000 req/h): github.com/settings/tokens -> Generate new token (classic), no scopes needed. Append to ~/Tools/.github_tokens (one per line).",
            "Shodan: NOT needed. App uses nmap active scan fallback automatically.",
            "WHOISXML: NOT needed. App uses system whois + RDAP automatically.",
            "ProjectDiscovery Cloud: NOT needed for basic scans. ASN via BGPView/RIPEstat free.",
            "Interactsh (SSRF/XSS callbacks, free): run 'interactsh-client -s oast.fun' or use local listener; set COLLAB_SERVER only if you want callbacks.",
            "Notify (Slack/Discord/Telegram): optional, free webhooks. Skipped if unconfigured.",
        ],
    }
