"""Advanced local website crawler (no cloud keys).

BFS crawl with requests + optional Selenium rendering, tech detection,
WAF detection, form/link extraction, persisted results, AI-ready summaries.
"""
import json
import os
import re
import threading
import time
import urllib.parse
import urllib.robotparser
from collections import deque
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
CRAWL_ROOT = os.path.join(HERE, "memory", "crawls")
os.makedirs(CRAWL_ROOT, exist_ok=True)

CRAWLS = {}          # id -> state dict (in-memory, rehydrated from disk on import)
_CRAWL_LOCK = threading.RLock()

_STOP_WORDS_DEFAULT = 0

_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
]

_TECH_SIGNATURES = [
    ("WordPress", ["wp-content", "wp-includes", "wp-json"], ["x-generator:wordpress", "link:wp"]),
    ("Drupal", ["/sites/default/files", "drupal.js"], []),
    ("Joomla", ["/components/com_", "joomla.js"], []),
    ("Django", ["csrfmiddlewaretoken"], ["server:WSGIServer"]),
    ("Flask", ["werkzeug"], ["server:Werkzeug"]),
    ("Laravel", ["csrf-token"], ["x-powered-by:PHP"]),
    ("React", ["react", "__react", "data-reactroot", "_next/static"], []),
    ("Next.js", ["_next/static", "__NEXT_DATA__", "next/dist"], []),
    ("Vue.js", ["__vue__", "vue.runtime", "v-cloak", "data-v-"], []),
    ("Angular", ["ng-version", "angular.js", "zone.js"], []),
    ("jQuery", ["jquery.min.js", "jquery.js", "jQuery("], []),
    ("Bootstrap", ["bootstrap.min.css", "bootstrap.min.js", "bootstrap.css"], []),
    ("Tailwind CSS", ["tailwindcss", "tailwind.min"], []),
    ("Cloudflare", [], ["server:cloudflare", "cf-ray"]),
    ("Nginx", [], ["server:nginx"]),
    ("Apache", [], ["server:apache"]),
    ("IIS", [], ["server:microsoft-iis", "x-powered-by:ASP.NET"]),
    ("Varnish", [], ["x-varnish", "via:varnish"]),
    ("Google Analytics", ["google-analytics.com/analytics.js", "gtag(", "googletagmanager.com"], []),
    ("reCAPTCHA", ["recaptcha", "g-recaptcha"], []),
    ("Stripe", ["js.stripe.com"], []),
    ("WebSocket", ["socket.io", "ws://", "wss://"], []),
]


def _log(cid, msg):
    cr = CRAWLS.get(cid)
    line = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n"
    if cr is not None:
        cr.setdefault("log", []).append(line)
        try:
            with open(os.path.join(cr["dir"], "crawl.log"), "a", encoding="utf-8") as f:
                f.write(line)
        except Exception:
            pass
    print(line, end="")


def _new_id(url):
    import random as _r
    safe = re.sub(r"[^a-zA-Z0-9]+", "_", (urllib.parse.urlparse(url).netloc or "site"))[:60] or "site"
    return f"crawl_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}_{_r.randint(100,999)}_{safe}"


def _norm_url(u, base=None):
    if not u:
        return ""
    try:
        u = str(u).strip()
    except Exception:
        return ""
    if base:
        try:
            u = urllib.parse.urljoin(base, u)
        except Exception:
            pass
    try:
        p = urllib.parse.urlsplit(u)
    except Exception:
        return ""
    if p.scheme not in ("http", "https"):
        return ""
    if not p.netloc:
        return ""
    # drop fragment, normalize path
    path = p.path or "/"
    url = urllib.parse.urlunsplit((p.scheme, p.netloc, path, p.query, ""))
    return url


def _same_domain(a, b):
    try:
        return urllib.parse.urlsplit(a).netloc.lower() == urllib.parse.urlsplit(b).netloc.lower()
    except Exception:
        return False


def _is_blocked(status, text):
    t = (text or "").lower()
    sigs = ["cf-challenge", "challenge-platform", "just a moment", "cloudflare", "access denied",
            "request blocked", "attention required", "captcha", "incapsula", "sucuri", "ddos protection"]
    return (status in (403, 429, 503)) or any(s in t for s in sigs)


def _tech_detect(headers, html):
    techs = set()
    hl = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    lowhtml = (html or "").lower()
    # attribute-only corpus reduces false positives from article body text
    attr_bits = []
    for rx in (r'<script[^>]*src=["\']([^"\']+)["\']', r'<link[^>]*href=["\']([^"\']+)["\']',
               r'<meta[^>]*content=["\']([^"\']+)["\']', r'<meta[^>]*name=["\']([^"\']+)["\']'):
        try:
            for m in __import__("re").finditer(rx, html or "", __import__("re").I):
                attr_bits.append(m.group(1))
        except Exception:
            pass
    attr_corpus = " ".join(attr_bits).lower()
    alltxt = attr_corpus + " " + " ".join(f"{k}:{v}" for k, v in hl.items()).lower()
    for name, html_sigs, hdr_sigs in _TECH_SIGNATURES:
        hit = False
        for sg in html_sigs:
            sg_l = sg.lower()
            # unique markers can be searched across full html
            if sg_l in lowhtml:
                hit = True
                break
        if not hit:
            for sg in hdr_sigs:
                sg_l = sg.lower()
                if ":" in sg_l:
                    hk, hv = sg_l.split(":", 1)
                    if hk in hl and hv.strip() in hl[hk].lower():
                        hit = True
                        break
                else:
                    if sg_l in alltxt:
                        hit = True
                        break
        if hit:
            techs.add(name)
    # generator meta
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', html or "", re.I)
    if m:
        techs.add(m.group(1).strip()[:60])
    m = re.search(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']', html or "", re.I)
    if m:
        techs.add(m.group(1).strip()[:60])
    # x-powered-by / server
    if hl.get("x-powered-by"):
        techs.add("X-Powered-By: " + hl["x-powered-by"][:60])
    if hl.get("server"):
        techs.add("Server: " + hl["server"][:60])
    return sorted(techs)


def _extract_bs4(html, base_url):
    out = {"title": "", "text": "", "links": [], "forms": [], "scripts": [],
           "images": 0, "headings": []}
    if not html:
        return out
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            return out
    try:
        if soup.title and soup.title.string:
            out["title"] = soup.title.string.strip()[:200]
    except Exception:
        pass
    try:
        out["text"] = soup.get_text(separator="\n", strip=True)[:50000]
    except Exception:
        out["text"] = ""
    try:
        for tag in soup.find_all(["h1", "h2", "h3"])[:40]:
            t = tag.get_text(" ", strip=True)
            if t:
                out["headings"].append({"level": tag.name, "text": t[:120]})
    except Exception:
        pass
    links = []
    seen = set()
    try:
        for a in soup.find_all("a", href=True):
            href = _norm_url(a.get("href", ""), base_url)
            if not href:
                continue
            if href in seen:
                continue
            seen.add(href)
            label = (a.get_text(" ", strip=True) or "")[:80]
            links.append({"href": href, "text": label})
            if len(links) >= 200:
                break
    except Exception:
        pass
    out["links"] = links
    forms = []
    try:
        for f in soup.find_all("form"):
            try:
                action = _norm_url(f.get("action") or base_url, base_url)
            except Exception:
                action = f.get("action")
            inputs = []
            for inp in f.find_all(["input", "textarea", "select"]):
                inputs.append({"name": inp.get("name"), "type": inp.get("type", "text")})
            forms.append({"action": action, "method": (f.get("method") or "GET").upper(),
                          "inputs": inputs[:30]})
    except Exception:
        pass
    out["forms"] = forms
    scripts = []
    try:
        for s in soup.find_all("script", src=True):
            scripts.append(s.get("src"))
        out["scripts"] = [str(s)[:200] for s in scripts[:50] if s]
    except Exception:
        pass
    try:
        out["images"] = len(soup.find_all("img"))
    except Exception:
        pass
    return out


def _fetch_requests(url, session, timeout):
    ua = _UAS[0]
    t0 = time.time()
    try:
        r = session.get(url, headers={
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }, timeout=timeout, allow_redirects=True)
        ctype = r.headers.get("Content-Type", "")
        text = r.text if "text" in ctype.lower() or "html" in ctype.lower() or "xml" in ctype.lower() or "json" in ctype.lower() else ""
        dt = round(time.time() - t0, 2)
        return {
            "status": r.status_code, "final_url": r.url, "content_type": ctype,
            "headers": dict(r.headers), "html": text if "html" in ctype.lower() else "",
            "text_raw": text, "bytes": len(r.content or b""), "time": dt,
            "error": None, "engine": "requests",
        }
    except Exception as e:
        return {"status": None, "final_url": url, "content_type": "", "headers": {},
                "html": "", "text_raw": "", "bytes": 0, "time": round(time.time() - t0, 2),
                "error": str(e)[:300], "engine": "requests"}


def _fetch_selenium(url, wait=6):
    t0 = time.time()
    path = None
    for b in ("/snap/bin/geckodriver", "/usr/local/bin/geckodriver", "/usr/bin/geckodriver"):
        if os.path.isfile(b):
            path = b
            break
    if not path:
        return {"status": None, "final_url": url, "content_type": "text/html", "headers": {},
                "html": "", "text_raw": "", "bytes": 0, "time": round(time.time() - t0, 2),
                "error": "geckodriver not found", "engine": "selenium"}
    try:
        from selenium import webdriver
        from selenium.webdriver.firefox.service import Service
        from selenium.webdriver.firefox.options import Options
        opts = Options()
        opts.add_argument("--headless")
        drv = webdriver.Firefox(service=Service(path), options=opts)
        try:
            drv.set_window_size(1280, 800)
            drv.get(url)
            time.sleep(wait)
            html = drv.page_source or ""
            final_url = drv.current_url or url
            title = drv.title or ""
        finally:
            try:
                drv.quit()
            except Exception:
                pass
        return {"status": 200, "final_url": final_url, "content_type": "text/html", "headers": {},
                "html": html, "text_raw": html, "bytes": len(html), "time": round(time.time() - t0, 2),
                "error": None, "engine": "selenium", "title_hint": title}
    except Exception as e:
        return {"status": None, "final_url": url, "content_type": "text/html", "headers": {},
                "html": "", "text_raw": "", "bytes": 0, "time": round(time.time() - t0, 2),
                "error": str(e)[:300], "engine": "selenium"}


def _fetch_page(url, timeout, render, session):
    res = _fetch_requests(url, session, timeout)
    html = res.get("html") or ""
    blocked = _is_blocked(res.get("status"), html or res.get("text_raw", ""))
    # If HTML but no text, or render requested, or blocked and render allowed -> selenium
    use_selenium = bool(render) or (blocked and render) or (not html and (res.get("status") == 200))
    if use_selenium and not (render is False and blocked):
        pass
    # Render always when explicitly requested
    if render:
        sr = _fetch_selenium(url, wait=6)
        if not sr.get("error"):
            res = sr
            html = res.get("html") or ""
    elif blocked and render:
        sr = _fetch_selenium(url, wait=10)
        if not sr.get("error"):
            res = sr
            html = res.get("html") or ""
    # If requests got a non-html body but status 200, keep text
    if not html and res.get("text_raw"):
        html = ""
    bs = _extract_bs4(html, res.get("final_url") or url)
    if not bs.get("text") and res.get("text_raw"):
        bs["text"] = str(res["text_raw"])[:50000]
    if res.get("title_hint") and not bs.get("title"):
        bs["title"] = res["title_hint"][:200]
    status = res.get("status")
    text = bs.get("text", "") or ""
    headers = res.get("headers") or {}
    techs = _tech_detect(headers, html or res.get("text_raw", ""))
    page = {
        "url": url,
        "final_url": res.get("final_url") or url,
        "status": status,
        "ok": bool(status and 200 <= status < 400),
        "content_type": res.get("content_type", ""),
        "size": res.get("bytes", 0),
        "time": res.get("time", 0),
        "engine": res.get("engine", ""),
        "error": res.get("error"),
        "blocked": _is_blocked(status, html or text),
        "title": bs.get("title", "") or "",
        "text": text[:30000],
        "text_len": len(text),
        "headings": bs.get("headings", []),
        "links": bs.get("links", []),
        "forms": bs.get("forms", []),
        "scripts": bs.get("scripts", []),
        "images": bs.get("images", 0),
        "tech": techs,
        "fetched_at": datetime.now().isoformat(),
    }
    return page


def _robots_allowed(rp, url):
    if rp is None:
        return True
    try:
        return rp.can_fetch("*", url)
    except Exception:
        return True


def run_crawl(cid):
    cr = CRAWLS.get(cid)
    if not cr:
        return
    try:
        cr["status"] = "running"
        _log(cid, f"crawl started: {cr['seed']} (max_pages={cr['max_pages']}, depth={cr['max_depth']}, same_domain={cr['same_domain']})")
        import requests
        session = requests.Session()
        # robots.txt
        rp = None
        try:
            r = session.get(_norm_url("/robots.txt", cr["seed"]), timeout=8, headers={"User-Agent": _UAS[0]})
            if r.status_code == 200 and r.text:
                rp = urllib.robotparser.RobotFileParser()
                rp.parse(r.text.splitlines())
                _log(cid, "robots.txt loaded")
        except Exception as e:
            _log(cid, f"robots.txt unavailable: {e}")
        # sitemap seeds
        sitemap_urls = []
        try:
            sm = session.get(_norm_url("/sitemap.xml", cr["seed"]), timeout=8, headers={"User-Agent": _UAS[0]})
            if sm.status_code == 200:
                for m in re.finditer(r"<loc>\s*(https?://[^<]+)\s*</loc>", sm.text or "", re.I):
                    u = _norm_url(m.group(1).strip())
                    if u:
                        sitemap_urls.append(u)
                _log(cid, f"sitemap.xml: {len(sitemap_urls)} urls")
        except Exception:
            pass
        # BFS
        frontier = deque()
        frontier.append((cr["seed"], 0))
        for u in sitemap_urls[: cr["max_pages"]]:
            if u not in (x[0] for x in frontier):
                frontier.append((u, 1))
        visited = set()
        while frontier and not cr.get("stop"):
            if len(cr["pages"]) >= cr["max_pages"]:
                _log(cid, f"reached max_pages={cr['max_pages']}; stopping.")
                break
            url, depth = frontier.popleft()
            if url in visited:
                continue
            if depth > cr["max_depth"]:
                continue
            visited.add(url)
            if not cr.get("respect_robots", True) is False:
                if not _robots_allowed(rp, url):
                    _log(cid, f"[robots] disallowed: {url}")
                    continue
            if cr.get("same_domain") and not _same_domain(url, cr["seed"]):
                continue
            # delay
            if cr.get("delay", 0):
                try:
                    time.sleep(float(cr["delay"]))
                except Exception:
                    pass
            # skip non-html-ish by extension
            low = url.lower()
            if any(low.endswith(ext) for ext in (".jpg", ".jpeg", ".png", ".gif", ".webp", ".ico",
                                                ".pdf", ".zip", ".tar", ".gz", ".mp4", ".mp3",
                                                ".css", ".js", ".svg", ".woff", ".woff2", ".ttf")):
                _log(cid, f"skip binary/asset: {url}")
                continue
            _log(cid, f"[{len(cr['pages'])+1}/{cr['max_pages']}] depth={depth} GET {url}")
            page = _fetch_page(url, cr.get("timeout", 20), cr.get("render", False), session)
            cr["pages"].append(page)
            if not page.get("ok"):
                _log(cid, f"   -> status={page.get('status')} err={page.get('error') or ''[:120]}")
            else:
                _log(cid, f"   -> {page.get('status')} title={page.get('title','')[:60]} links={len(page.get('links',[]))} forms={len(page.get('forms',[]))} tech={','.join(page.get('tech',[])[:6])}")
            # prune text store memory cap
            if len(cr["pages"]) > 200:
                for pg in cr["pages"][:-200]:
                    pg["text"] = (pg.get("text") or "")[:2000]
            # enqueue links
            if depth < cr["max_depth"] and page.get("ok"):
                for lk in page.get("links", []):
                    u = lk.get("href") if isinstance(lk, dict) else lk
                    nu = _norm_url(u)
                    if not nu or nu in visited:
                        continue
                    if cr.get("same_domain") and not _same_domain(nu, cr["seed"]):
                        if not cr.get("follow_external"):
                            continue
                    if nu not in (x[0] for x in frontier):
                        frontier.append((nu, depth + 1))
            # persist incremental
            _persist(cid)
        if cr.get("stop"):
            cr["status"] = "stopped"
            _log(cid, "crawl STOPPED by user.")
        else:
            cr["status"] = "done"
            _log(cid, f"crawl DONE. pages={len(cr['pages'])}")
    except Exception as e:
        try:
            cr["status"] = "error"
            _log(cid, f"crawl ERROR: {e}")
        except Exception:
            pass
    finally:
        try:
            _persist(cid, final=True)
        except Exception:
            pass
        try:
            cr.setdefault("finished_at", datetime.now().isoformat())
        except Exception:
            pass


def _persist(cid, final=False):
    cr = CRAWLS.get(cid)
    if not cr:
        return
    try:
        os.makedirs(cr["dir"], exist_ok=True)
        # pages.json (full pages incl text)
        with open(os.path.join(cr["dir"], "pages.json"), "w", encoding="utf-8") as f:
            json.dump(cr["pages"], f, indent=2, ensure_ascii=False)
        # summary
        summary = {
            "id": cid, "seed": cr.get("seed"), "status": cr.get("status"),
            "started": cr.get("started"), "finished": cr.get("finished_at"),
            "max_pages": cr.get("max_pages"), "max_depth": cr.get("max_depth"),
            "same_domain": cr.get("same_domain"), "render": cr.get("render"),
            "pages_crawled": len(cr.get("pages", [])),
            "page_index": [{"i": i, "url": p.get("url"), "status": p.get("status"),
                            "title": p.get("title"), "tech": p.get("tech"),
                            "forms": len(p.get("forms", [])), "links": len(p.get("links", [])),
                            "text_len": p.get("text_len", 0), "blocked": p.get("blocked")}
                           for i, p in enumerate(cr.get("pages", []))],
            "all_tech": sorted(set(t for p in cr.get("pages", []) for t in (p.get("tech") or []))),
            "errors": [p.get("url") for p in cr.get("pages", []) if not p.get("ok")],
        }
        with open(os.path.join(cr["dir"], "summary.json"), "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
    except Exception as e:
        try:
            _log(cid, f"persist warn: {e}")
        except Exception:
            pass


def _rehydrate():
    try:
        import glob as _g
        for cdir in sorted(_g.glob(os.path.join(CRAWL_ROOT, "*"))):
            cid = os.path.basename(cdir)
            if os.path.isfile(os.path.join(cdir, "summary.json")) and cid not in CRAWLS:
                try:
                    summ = json.load(open(os.path.join(cdir, "summary.json"), encoding="utf-8"))
                    pages = []
                    pp = os.path.join(cdir, "pages.json")
                    if os.path.isfile(pp):
                        pages = json.load(open(pp, encoding="utf-8"))
                    CRAWLS[cid] = {
                        "id": cid, "seed": summ.get("seed") or "",
                        "status": "done", "max_pages": summ.get("max_pages", 30),
                        "max_depth": summ.get("max_depth", 2), "same_domain": summ.get("same_domain", True),
                        "render": summ.get("render", False), "delay": 0, "respect_robots": True,
                        "follow_external": False, "timeout": 20, "started": summ.get("started", ""),
                        "finished_at": summ.get("finished", ""), "dir": cdir, "pages": pages,
                        "log": [], "stop": False, "stop_event": threading.Event(),
                        "thread": None, "rehydrated": True,
                    }
                    # load log tail
                    lp = os.path.join(cdir, "crawl.log")
                    if os.path.isfile(lp):
                        try:
                            txt = open(lp, encoding="utf-8", errors="ignore").read()
                            CRAWLS[cid]["log"] = [txt[-15000:]]
                        except Exception:
                            pass
                except Exception:
                    pass
    except Exception:
        pass

try:
    _rehydrate()
except Exception:
    pass


def start_crawl(seed_url, max_pages=30, max_depth=2, same_domain=True,
                follow_external=False, render=False, delay=0.2,
                timeout=20, respect_robots=True):
    url = _norm_url(seed_url)
    if not url:
        return None, "valid http/https url required"
    try:
        max_pages = int(max_pages)
    except Exception:
        max_pages = 30
    max_pages = max(1, min(max_pages, 500))
    try:
        max_depth = int(max_depth)
    except Exception:
        max_depth = 2
    max_depth = max(0, min(max_depth, 6))
    try:
        delay = float(delay)
    except Exception:
        delay = 0.2
    delay = max(0, min(delay, 10))
    cid = _new_id(url)
    cdir = os.path.join(CRAWL_ROOT, cid)
    os.makedirs(cdir, exist_ok=True)
    with _CRAWL_LOCK:
        CRAWLS[cid] = {
            "id": cid, "seed": url, "status": "queued", "max_pages": max_pages,
            "max_depth": max_depth, "same_domain": bool(same_domain),
            "follow_external": bool(follow_external), "render": bool(render),
            "delay": delay, "respect_robots": bool(respect_robots), "timeout": timeout,
            "started": datetime.now().isoformat(), "finished_at": "", "dir": cdir,
            "pages": [], "log": [], "stop": False, "stop_event": threading.Event(),
            "thread": None,
        }
    t = threading.Thread(target=run_crawl, args=(cid,), daemon=True)
    CRAWLS[cid]["thread"] = t
    t.start()
    return cid, None


def stop_crawl(cid):
    cr = CRAWLS.get(cid)
    if not cr:
        return False
    try:
        cr["stop"] = True
        ev = cr.get("stop_event")
        if ev is not None:
            ev.set()
    except Exception:
        pass
    return True


def stop_all():
    for cid in list(CRAWLS.keys()):
        try:
            stop_crawl(cid)
        except Exception:
            pass


def get_crawl(cid):
    return CRAWLS.get(cid)


def list_crawls():
    with _CRAWL_LOCK:
        out = []
        for cr in CRAWLS.values():
            out.append({
                "id": cr["id"], "seed": cr.get("seed"), "status": cr.get("status"),
                "started": cr.get("started"), "pages": len(cr.get("pages", [])),
                "max_pages": cr.get("max_pages"), "max_depth": cr.get("max_depth"),
            })
        return sorted(out, key=lambda x: x.get("started", ""), reverse=True)


def crawl_context(cid, max_pages=20, max_chars=8000):
    cr = CRAWLS.get(cid)
    if not cr:
        return ""
    lines = [f"Crawl seed: {cr.get('seed')}", f"Status: {cr.get('status')}", f"Pages: {len(cr.get('pages', []))}"]
    for p in (cr.get("pages") or [])[:max_pages]:
        lines.append(f"- {p.get('url')} | status={p.get('status')} title={p.get('title','')[:80]} tech={','.join((p.get('tech') or [])[:6])} forms={len(p.get('forms',[]))} links={len(p.get('links',[]))}")
        txt = (p.get("text") or "")[:400]
        if txt:
            lines.append(f"  text: {txt.replace(chr(10),' ')[:400]}")
    ctx = "\n".join(lines)
    return ctx[:max_chars]


def build_site_summary(cid):
    cr = CRAWLS.get(cid)
    if not cr:
        return ""
    pages = cr.get("pages", [])
    techs = sorted(set(t for p in pages for t in (p.get("tech") or [])))
    forms = sum(len(p.get("forms", [])) for p in pages)
    links = sum(len(p.get("links", [])) for p in pages)
    errors = [p.get("url") for p in pages if not p.get("ok")]
    lines = [
        f"Site: {cr.get('seed')}",
        f"Pages crawled: {len(pages)} (status {cr.get('status')})",
        f"Technologies: {', '.join(techs) if techs else '(unknown)'}",
        f"Total forms: {forms}, total links: {links}",
        f"Failed/blocked: {len(errors)}",
    ]
    if errors:
        lines.append("Failed URLs: " + ", ".join(errors[:20]))
    # top pages by text
    pages_sorted = sorted(pages, key=lambda p: p.get("text_len", 0), reverse=True)[:10]
    lines.append("Top content pages:")
    for p in pages_sorted:
        lines.append(f"  - {p.get('url')} ({p.get('text_len',0)} chars) {p.get('title','')[:60]}")
    return "\n".join(lines)


def analyze_prompt(cid):
    cr = CRAWLS.get(cid)
    if not cr:
        return ""
    ctx = build_site_summary(cid) + "\n\nPage details:\n" + crawl_context(cid, max_pages=25, max_chars=12000)
    return (
        "You are an advanced web reconnaissance and analysis assistant. Analyze this crawled website comprehensively.\n"
        "Return:\n"
        "1. Site overview & purpose (inferred).\n"
        "2. Technology stack (frontend/backend/CMS/infra/CDN/WAF/analytics).\n"
        "3. Information architecture: key sections, nav, content types.\n"
        "4. Forms & input surfaces (potential testing targets, authorized & non-destructive).\n"
        "5. Security-relevant observations (headers, cookies mentioned, exposed paths, error pages, sensitive files) — cite URLs.\n"
        "6. Endpoints/API hints discovered (from links/scripts).\n"
        "7. Auth/area detection (login, register, admin, dashboards).\n"
        "8. Recommended next steps/commands for deeper authorized recon (free local tools: nuclei, ffuf, dalfox, curl), each with exact command.\n"
        "9. Limitations and gaps in crawl (JS-rendered content, blocked pages, depth limits).\n"
        "Be honest; never fabricate. Cite crawled URLs. Data:\n" + ctx
    )


import atexit as _atexit
_atexit.register(stop_all)


# rehydrate trigger for glob import already; ensure glob available
