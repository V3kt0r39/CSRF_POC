#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced CSRF Assessment Tool for TMG/OWA and Modern Web Applications
Version 2.1 - Modular architecture

Modules:
  csrf_engine.py    - Core testing logic, HTTP requests, payload building
  csrf_analyzer.py  - Cookie analysis, CSP/CORS checks, vulnerability scoring
  csrf_templates.py - HTML page generation
  csrf_poc_server.py - This file: config, HTTP handler, server startup
"""

import http.server
import socketserver
import ssl
import urllib.parse
import sys
import os
import logging
from typing import Dict, Any

try:
    import requests
except ImportError:
    requests = None

from csrf_engine import (
    absolute_url, detect_endpoints, extract_hidden_inputs,
    extract_csrf_tokens, extract_csp, extract_page_title, build_payload,
    UA,
)
from csrf_analyzer import (
    parse_set_cookie_flags, analyze_cookie_security, pretty_cookie_report,
    calc_vulnerability_score,
)
from csrf_templates import (
    page_index, page_config, page_poc, page_verify,
    page_suite, page_export_json,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_FILE = os.environ.get("LOG_FILE", "csrf_assessment.log")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("csrf_assessment")

# ---------------------------------------------------------------------------
# Colored output
# ---------------------------------------------------------------------------
class Colors:
    RESET = "\033[0m"; RED = "\033[91m"; GREEN = "\033[92m"
    YELLOW = "\033[93m"; BLUE = "\033[94m"; MAGENTA = "\033[95m"; CYAN = "\033[96m"


def cprint(text: str, color: str = Colors.RESET):
    print(f"{color}{text}{Colors.RESET}")


def env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def prompt(text: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        val = input(f"{text}{suffix}: ").strip()
        return val if val else default
    except EOFError:
        return default


# ---------------------------------------------------------------------------
# Configuration (mutable dict shared with all modules)
# ---------------------------------------------------------------------------
def _load_config() -> Dict[str, Any]:
    return {
        "target_base":    env("TARGET_BASE", "https://example.com"),
        "public_host":    env("PUBLIC_HOST", "127.0.0.1"),
        "listen_port":    int(env("LISTEN_PORT", "4444")),
        "public_port":    int(env("PUBLIC_PORT", env("LISTEN_PORT", "4444"))),
        "listen_host":    env("LISTEN_HOST", "0.0.0.0"),
        "cookieauth_path":      env("COOKIEAUTH_PATH", "/CookieAuth.dll?Logon"),
        "get_logon_path":       env("GET_LOGON_PATH", "/CookieAuth.dll?GetLogon?curl=Z2FowaZ2F&reason=0&formdir=1"),
        "authowa_path":         env("AUTHOWA_PATH", "/owa/auth.owa"),
        "published_safe_path":  env("PUBLISHED_SAFE_PATH", "/owa/"),
        "csrf_username":  env("CSRF_USERNAME", "test.user"),
        "csrf_password":  env("CSRF_PASSWORD", "NotARealPass123"),
        "csrf_submit_name":  env("CSRF_SUBMIT_NAME", "SubmitCreds"),
        "csrf_submit_value": env("CSRF_SUBMIT_VALUE", "Sign in"),
        "csrf_flags":         env("CSRF_FLAGS", "0"),
        "csrf_forcedownlevel":env("CSRF_FORCEDOWNLEVEL", "0"),
        "csrf_formdir":       env("CSRF_FORMDIR", "1"),
        "csrf_trusted":       env("CSRF_TRUSTED", "0"),
        "csrf_isutf8":        env("CSRF_ISUTF8", "1"),
        "csrf_curl":          env("CSRF_CURL", "Z2FowaZ2F"),
        "csrf_destination":   env("CSRF_DESTINATION", "/owa/"),
        "cert_file":  env("CERT_FILE", ""),
        "key_file":   env("KEY_FILE", ""),
        "fake_origin":  env("FAKE_ORIGIN", ""),
        "fake_referer": env("FAKE_REFERER", ""),
    }


# ---------------------------------------------------------------------------
# State (mutable, shared with templates)
# ---------------------------------------------------------------------------
STATE: Dict[str, Any] = {
    "target_base": "", "cookieauth_url": "", "authowa_url": "",
    "get_logon_url": "", "safe_url": "",
    "cookie_report": "", "auto_hidden": {}, "csrf_tokens": {},
    "warnings": [], "detected_endpoints": [],
    "vulnerability_score": 0, "protection_mechanisms": [],
    "cookie_risk_level": "LOW", "csp_detected": False, "cors_wildcard": False,
}


def _rebuild_urls(cfg: Dict[str, Any]):
    STATE["target_base"] = cfg["target_base"]
    STATE["cookieauth_url"] = absolute_url(cfg["target_base"], cfg["cookieauth_path"])
    STATE["authowa_url"]     = absolute_url(cfg["target_base"], cfg["authowa_path"])
    STATE["get_logon_url"]   = absolute_url(cfg["target_base"], cfg["get_logon_path"])
    STATE["safe_url"]        = absolute_url(cfg["target_base"], cfg["published_safe_path"])


def _warm_up(cfg: Dict[str, Any]):
    if requests is None:
        STATE["warnings"].append("requests module not installed - warm-up skipped")
        cprint("[-] requests module not installed", Colors.RED)
        return

    logger.info("Starting warm-up for target: %s", cfg["target_base"])
    cprint("\n[+] Performing warm-up analysis...", Colors.YELLOW)

    try:
        cprint("[*] Auto-detecting authentication endpoints...", Colors.CYAN)
        detected = detect_endpoints(cfg["target_base"])
        STATE["detected_endpoints"] = detected
        if detected:
            cprint(f"[+] Found {len(detected)} endpoints:", Colors.GREEN)
            for ep in detected:
                cprint(f"    - {ep['path']} (Status: {ep['status']})", Colors.GREEN)
        else:
            cprint("[-] No additional endpoints detected", Colors.YELLOW)

        _rebuild_urls(cfg)

        cprint(f"[*] Fetching login page: {STATE['get_logon_url']}", Colors.CYAN)
        s = requests.Session()
        s.headers.update({"User-Agent": UA})
        r = s.get(STATE["get_logon_url"], timeout=15, verify=False, allow_redirects=True)

        set_cookie = r.headers.get("Set-Cookie")
        all_sc = []
        if set_cookie:
            raw = getattr(getattr(r, "raw", None), "headers", None)
            all_sc = raw.get_all("Set-Cookie") if raw and hasattr(raw, "get_all") else [set_cookie]

        cookies = parse_set_cookie_flags(all_sc)
        cookie_analysis = analyze_cookie_security(cookies)
        STATE["cookie_report"] = pretty_cookie_report(cookies, cookie_analysis)
        STATE["cookie_risk_level"] = cookie_analysis["csrf_risk_level"]
        cprint("[+] Cookie analysis complete:", Colors.GREEN)
        cprint(STATE["cookie_report"], Colors.CYAN)

        cprint("[*] Extracting hidden form fields...", Colors.CYAN)
        STATE["auto_hidden"] = extract_hidden_inputs(r.text)
        if STATE["auto_hidden"]:
            cprint(f"[+] Found {len(STATE['auto_hidden'])} hidden fields:", Colors.GREEN)
            for k, v in list(STATE["auto_hidden"].items())[:5]:
                cprint(f"    {k}: {v[:30]}", Colors.GREEN)
        else:
            cprint("[-] No hidden fields found", Colors.YELLOW)

        cprint("[*] Searching for CSRF tokens...", Colors.CYAN)
        STATE["csrf_tokens"] = extract_csrf_tokens(r.text)
        if STATE["csrf_tokens"]:
            cprint(f"[+] Found {len(STATE['csrf_tokens'])} potential CSRF tokens", Colors.GREEN)
            STATE["protection_mechanisms"].append("CSRF tokens detected")
        else:
            cprint("[!] No CSRF tokens found - potential vulnerability", Colors.RED)

        if cookie_analysis["csrf_risk_level"] == "HIGH":
            cprint("[!] HIGH CSRF risk due to missing SameSite attributes", Colors.RED)
        elif cookie_analysis["csrf_risk_level"] == "MEDIUM":
            cprint("[!] MEDIUM CSRF risk - SameSite=Lax may not be sufficient", Colors.YELLOW)

        csp = extract_csp(r.text)
        if csp:
            cprint("[+] Found Content Security Policy", Colors.GREEN)
            STATE["protection_mechanisms"].append("CSP detected")
            STATE["csp_detected"] = True
        else:
            cprint("[!] No CSP detected", Colors.YELLOW)

        cors_origin = r.headers.get("Access-Control-Allow-Origin")
        if cors_origin:
            cprint(f"[+] CORS header found: {cors_origin}", Colors.GREEN)
            if cors_origin == "*":
                cprint("[!] WARNING: CORS allows any origin (*):", Colors.RED)
                STATE["cors_wildcard"] = True

        STATE["vulnerability_score"] = calc_vulnerability_score(STATE)
        cprint(f"\n[+] Warm-up complete!", Colors.GREEN)
        cprint(f"[i] Current vulnerability score: {STATE['vulnerability_score']}/100", Colors.CYAN)
        logger.info("Warm-up complete. Score: %d/100", STATE["vulnerability_score"])

    except Exception as e:
        STATE["warnings"].append(f"Warm-up failed: {e}")
        cprint(f"[-] Warm-up failed: {e}", Colors.RED)
        logger.error("Warm-up failed: %s", e)


# ---------------------------------------------------------------------------
# HTTP Handler
# ---------------------------------------------------------------------------
class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, cfg=None, **kwargs):
        self._cfg = cfg or {}
        super().__init__(*args, **kwargs)

    def do_GET(self):
        q = urllib.parse.urlsplit(self.path).query
        params = {k: v[-1] for k, v in urllib.parse.parse_qs(q, keep_blank_values=True).items()}

        if self.path == "/":
            return self._send_html(200, page_index(self._cfg, STATE))
        elif self.path.startswith("/config"):
            return self._send_html(200, page_config(self._cfg, STATE, params))
        elif self.path.startswith("/poc-no-token"):
            return self._send_html(200, page_poc(self._cfg, STATE, include_tokens=False))
        elif self.path.startswith("/poc"):
            return self._send_html(200, page_poc(self._cfg, STATE, include_tokens=True))
        elif self.path.startswith("/verify-deep"):
            return self._send_html(200, page_verify(self._cfg, STATE, params, deep=True))
        elif self.path.startswith("/verify"):
            return self._send_html(200, page_verify(self._cfg, STATE, params, deep=False))
        elif self.path.startswith("/suite"):
            return self._send_html(200, page_suite(self._cfg, STATE, params))
        elif self.path.startswith("/export/json"):
            return self._send_html(200, page_export_json(self._cfg, STATE, params))
        return self.send_error(404, "Not Found")

    def do_POST(self):
        return self.send_error(405, "Method Not Allowed")

    def log_message(self, fmt, *items):
        sys.stdout.write(f"[HTTP] {fmt % items}\n")

    def _send_html(self, code: int, html: str):
        data = html.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    cfg = _load_config()

    cprint("\n=== Enhanced CSRF Assessment Tool v2.1 ===", Colors.CYAN)
    cprint("Interactive Configuration", Colors.YELLOW)

    cfg["target_base"] = prompt("Enter target base URL (TARGET_BASE)", cfg["target_base"])
    cfg["public_host"] = prompt("Enter your public IP/host for PoC access (PUBLIC_HOST)", cfg["public_host"])
    cfg["listen_port"] = int(prompt("Enter listen port (LISTEN_PORT)", str(cfg["listen_port"])))
    cfg["public_port"] = cfg["listen_port"]
    cfg["fake_origin"] = cfg["fake_origin"] or f"http://{cfg['public_host']}:{cfg['public_port']}"

    nu = prompt("Enter test username (CSRF_USERNAME)", cfg["csrf_username"])
    np = prompt("Enter test password (CSRF_PASSWORD)", "********")
    if nu:
        cfg["csrf_username"] = nu
    if np and np != "********":
        cfg["csrf_password"] = np

    _rebuild_urls(cfg)

    if requests:
        from urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    _warm_up(cfg)

    handler = lambda *a, **kw: Handler(*a, cfg=cfg, **kw)
    httpd = socketserver.TCPServer((cfg["listen_host"], cfg["listen_port"]), handler)

    scheme = "http"
    if cfg["cert_file"] and cfg["key_file"]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=cfg["cert_file"], keyfile=cfg["key_file"])
            httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
            scheme = "https"
            cprint("[+] HTTPS enabled", Colors.GREEN)
        except Exception as e:
            cprint(f"[-] Failed to load SSL: {e}", Colors.RED)
            cprint("[i] Falling back to HTTP", Colors.YELLOW)

    pp = "" if (scheme == "https" and cfg["public_port"] == 443) or (scheme == "http" and cfg["public_port"] == 80) else f":{cfg['public_port']}"
    public_url = f"{scheme}://{cfg['public_host']}{pp}"

    cprint("\n" + "=" * 60, Colors.CYAN)
    cprint("Enhanced CSRF Assessment Tool - Ready", Colors.GREEN)
    cprint("=" * 60, Colors.CYAN)
    cprint(f"[+] Listening on {scheme}://{cfg['listen_host']}:{cfg['listen_port']}", Colors.GREEN)
    cprint(f"[i] Public URL: {public_url}", Colors.CYAN)
    cprint(f"[i] Target: {cfg['target_base']}", Colors.CYAN)
    cprint(f"[i] Test User: {cfg['csrf_username']}", Colors.CYAN)
    cprint("\nOpen your browser and navigate to:", Colors.YELLOW)
    cprint(f"  {public_url}/", Colors.GREEN)
    cprint("\nAvailable endpoints:", Colors.YELLOW)
    cprint(f"  {public_url}/poc          - CSRF PoC with tokens", Colors.GREEN)
    cprint(f"  {public_url}/poc-no-token - CSRF PoC without tokens", Colors.GREEN)
    cprint(f"  {public_url}/verify       - Verify CSRF protection", Colors.GREEN)
    cprint(f"  {public_url}/suite        - Run full security suite", Colors.GREEN)
    cprint(f"  {public_url}/export/json  - Export results as JSON", Colors.GREEN)
    cprint(f"  {public_url}/config       - Configuration", Colors.GREEN)
    cprint("\nPress Ctrl+C to stop the server", Colors.YELLOW)
    cprint("=" * 60 + "\n", Colors.CYAN)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        cprint("\n\n[+] Shutting down...", Colors.YELLOW)
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
