#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CSRF Assessment Templates — HTML page generation.
"""

import json
import time
from html import escape
from typing import Dict, Any

from csrf_engine import build_payload


_LAYOUT_HEAD = """<!doctype html>
<html>
<head>
  <meta charset='utf-8'>
  <meta name='viewport' content='width=device-width, initial-scale=1'>
  <title>%(title)s</title>
  <style>
    :root{--bg:#fff;--fg:#111827;--card:#f6f8fa;--btn-bg:#111827;--btn-fg:#fff;
      --border:#e5e7eb;--link:#2563eb;--success:#10b981;--warning:#f59e0b;--danger:#ef4444;
      --info:#3b82f6;--high:#ef4444;--medium:#f59e0b;--low:#10b981}
    :root[data-theme="dark"]{--bg:#0b0f14;--fg:#e5e7eb;--card:#0f1620;--btn-bg:#2563eb;--btn-fg:#fff;
      --border:#1f2937;--link:#60a5fa;--success:#10b981;--warning:#f59e0b;--danger:#ef4444;
      --info:#3b82f6;--high:#ef4444;--medium:#f59e0b;--low:#10b981}
    html,body{height:100%}
    body{margin:2rem;max-width:1200px;font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;background:var(--bg);color:var(--fg);line-height:1.6}
    a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}
    a.btn{display:inline-block;background:var(--btn-bg);color:var(--btn-fg);padding:.5rem 1rem;border-radius:6px;margin-right:8px;text-decoration:none}
    a.btn:hover{opacity:.9}
    code,pre{background:var(--card);padding:.25rem .5rem;border-radius:4px;overflow-x:auto}
    pre{white-space:pre-wrap;word-wrap:break-word}
    .card{border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:16px}
    .card-header{font-size:1.1em;font-weight:bold;margin-bottom:12px;border-bottom:1px solid var(--border);padding-bottom:8px}
    table{border-collapse:collapse;width:100%;margin:8px 0}
    th,td{border:1px solid var(--border);padding:8px 12px;text-align:left}
    th{background:var(--card);font-weight:bold}
    tr:hover td{background:var(--card)}
    .badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.85em;font-weight:bold}
    .badge-high{background:var(--high);color:#fff}
    .badge-medium{background:var(--medium);color:#fff}
    .badge-low{background:var(--low);color:#fff}
    .badge-info{background:var(--info);color:#fff}
    .badge-success{background:var(--success);color:#fff}
    .badge-danger{background:var(--danger);color:#fff}
    .progress-bar{width:100%;background:var(--card);border-radius:4px;overflow:hidden;margin:8px 0}
    .progress-fill{height:20px;background:linear-gradient(90deg,var(--low),var(--medium),var(--high));display:flex;align-items:center;justify-content:center;color:#fff;font-weight:bold}
    nav{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;padding-bottom:12px;border-bottom:2px solid var(--border)}
    #themeToggle{background:var(--btn-bg);color:var(--btn-fg);border:none;padding:.4rem .8rem;border-radius:6px;cursor:pointer}
    .indicator{margin:4px 0;padding:8px;background:var(--card);border-left:4px solid var(--info)}
    .indicator.success{border-left-color:var(--success)}
    .indicator.warning{border-left-color:var(--warning)}
    .indicator.danger{border-left-color:var(--danger)}
  </style>
  <script>
    (function(){try{var t=localStorage.getItem('theme')||'light';document.documentElement.setAttribute('data-theme',t)}catch(e){}})();
    function toggleTheme(){
      var c=document.documentElement.getAttribute('data-theme')||'light';
      var n=(c==='dark')?'light':'dark';
      document.documentElement.setAttribute('data-theme',n);
      try{localStorage.setItem('theme',n)}catch(e){}
      var b=document.getElementById('themeToggle');if(b)b.textContent='Theme: '+(n==='dark'?'Dark':'Light');
    }
    window.addEventListener('DOMContentLoaded',function(){
      var c=document.documentElement.getAttribute('data-theme')||'light';
      var b=document.getElementById('themeToggle');if(b)b.textContent='Theme: '+(c==='dark'?'Dark':'Light');
    });
  </script>
</head>
<body>
  <nav>
    <div><strong>CSRF Assessment Tool v2.1</strong></div>
    <div><button id='themeToggle' onclick='toggleTheme()'>Theme</button></div>
  </nav>
"""
_LAYOUT_TAIL = """</body>
</html>"""


def html_layout(title: str, body_html: str) -> str:
    return (_LAYOUT_HEAD % {"title": escape(title)}) + body_html + _LAYOUT_TAIL


def _build_payload_kv(payload: Dict[str, str]) -> str:
    return "\n".join(f"{k}={v}" for k, v in payload.items())


def _suite_rows(items, vulnerable_col=False) -> str:
    out = ""
    for i in items:
        out += "<tr>"
        out += f"<td>{escape(i['case'])}</td>"
        if "url" in i:
            out += f"<td><code>{escape(str(i.get('url','')))}</code></td>"
        if "method" in i:
            out += f"<td>{escape(i['method'])}</td>"
        out += f"<td>{escape(str(i['status']))}</td>"
        out += f"<td><code>{escape(i.get('location') or '')}</code></td>"
        out += f"<td><code>{escape((i.get('cookie') or '')[:80])}</code></td>"
        if vulnerable_col:
            v = i.get("vulnerable", i.get("allowed", False))
            badge = "badge-danger" if v else "badge-success"
            text = "VULNERABLE" if v else "Protected"
            out += f"<td><span class='badge {badge}'>{text}</span></td>"
        elif "blocked" in i:
            badge = "badge-success" if i["blocked"] else "badge-danger"
            text = "Blocked" if i["blocked"] else "Accepted"
            out += f"<td><span class='badge {badge}'>{text}</span></td>"
        elif "success" in i:
            badge = "badge-danger" if i["success"] else "badge-success"
            text = "VULNERABLE" if i["success"] else "Protected"
            out += f"<td><span class='badge {badge}'>{text}</span></td>"
            out += f"<td>{escape(i.get('indicators',''))}</td>"
        out += "</tr>\n"
    return out


# ---------------------------------------------------------------------------
# Page generators
# ---------------------------------------------------------------------------

def page_index(cfg: dict, state: dict) -> str:
    vuln = state.get("vulnerability_score", 0)
    rl = "HIGH" if vuln >= 70 else "MEDIUM" if vuln >= 40 else "LOW"
    rc = "high" if rl == "HIGH" else "medium" if rl == "MEDIUM" else "low"
    origin_default = cfg["fake_origin"]

    procs = "".join(f"<li>{escape(m)}</li>" for m in state.get("protection_mechanisms", [])) or "<li><em>None detected</em></li>"
    eps = ""
    if state.get("detected_endpoints"):
        eps = "<table><thead><tr><th>Path</th><th>Status</th><th>Title</th></tr></thead><tbody>"
        for ep in state["detected_endpoints"]:
            eps += f"<tr><td><code>{escape(ep.get('path',''))}</code></td><td>{ep.get('status','')}</td><td>{escape(ep.get('title',''))}</td></tr>"
        eps += "</tbody></table>"
    else:
        eps = "<p><em>No endpoints detected</em></p>"

    tokens_html = ""
    if state.get("csrf_tokens"):
        tokens_html = "<ul>" + "".join(f"<li><code>{escape(k)}</code>: <code>{escape(v[:50])}...</code></li>" for k, v in state["csrf_tokens"].items()) + "</ul>"
    else:
        tokens_html = "<p class='indicator warning'><strong>Warning:</strong> No CSRF tokens detected - potential vulnerability!</p>"

    warns = ""
    if state.get("warnings"):
        warns = "<div class='card'><div class='card-header'>Warnings</div><ul>" + "".join(f"<li>{escape(w)}</li>" for w in state["warnings"]) + "</ul></div>"

    body = f"""
<h1>Security Assessment Overview</h1>
<div class='card'>
  <div class='card-header'>Target Information</div>
  <p><strong>Target:</strong> <code>{escape(cfg['target_base'])}</code></p>
  <p><strong>Warm-up URL:</strong> <code>{escape(state.get('get_logon_url',''))}</code></p>
  <p><strong>CSRF Test URL:</strong> <code>{escape(state.get('cookieauth_url',''))}</code></p>
</div>
<div class='card'>
  <div class='card-header'>Vulnerability Assessment</div>
  <p><strong>Risk Level:</strong> <span class='badge badge-{rc}'>{rl}</span></p>
  <p><strong>Score:</strong> {vuln}/100</p>
  <div class='progress-bar'><div class='progress-fill' style='width:{vuln}%'>{vuln}%</div></div>
  <h4>Detected Protection Mechanisms:</h4><ul>{procs}</ul>
</div>
<div class='card'>
  <div class='card-header'>Quick Actions</div>
  <p>
    <a class='btn' href='/config'>Configuration</a>
    <a class='btn' href='/poc'>Browser CSRF PoC</a>
    <a class='btn' href='/poc-no-token'>PoC (No Tokens)</a>
    <a class='btn' href='/verify?origin={escape(origin_default)}'>Verify CSRF</a>
    <a class='btn' href='/verify-deep?origin={escape(origin_default)}'>Deep Verify</a>
    <a class='btn' href='/suite?origin={escape(origin_default)}'>Run Full Suite</a>
    <a class='btn' href='/export/json?origin={escape(origin_default)}'>Export JSON</a>
  </p>
</div>
<div class='card'><div class='card-header'>Cookie Security Report</div><pre>{escape(state.get('cookie_report','(no data)'))}</pre></div>
<div class='card'><div class='card-header'>Detected Endpoints</div>{eps}</div>
<div class='card'><div class='card-header'>CSRF Tokens Found</div>{tokens_html}</div>
{warns}"""
    return html_layout("CSRF Assessment Tool - Overview", body)


def page_config(cfg: dict, state: dict, query: Dict[str, str]) -> str:
    from csrf_engine import absolute_url
    from csrf_analyzer import calc_vulnerability_score

    if query.get("save") == "1":
        cfg["target_base"] = query.get("target_base", cfg["target_base"]).strip()
        cfg["public_host"] = query.get("public_host", cfg["public_host"]).strip()
        try:
            cfg["public_port"] = int(query.get("public_port", str(cfg["public_port"])))
        except ValueError:
            pass
        cfg["fake_origin"] = query.get("fake_origin", cfg["fake_origin"]).strip() or cfg["fake_origin"]
        cfg["fake_referer"] = query.get("fake_referer", cfg["fake_referer"]).strip()
        nu = query.get("csrf_username", "").strip()
        np = query.get("csrf_password", "")
        if nu:
            cfg["csrf_username"] = nu
        if np:
            cfg["csrf_password"] = np
        state["target_base"] = cfg["target_base"]
        state["cookieauth_url"] = absolute_url(cfg["target_base"], cfg["cookieauth_path"])
        state["authowa_url"] = absolute_url(cfg["target_base"], cfg["authowa_path"])
        state["get_logon_url"] = absolute_url(cfg["target_base"], cfg["get_logon_path"])
        state["safe_url"] = absolute_url(cfg["target_base"], cfg["published_safe_path"])

    masked = "••••••••" if cfg["csrf_password"] else ""
    body = f"""
<h1>Configuration</h1>
<form method='get' action='/config'>
  <input type='hidden' name='save' value='1'>
  <h3>Target Configuration</h3>
  <label>Target Base URL</label>
  <input name='target_base' value='{escape(cfg["target_base"])}' style='width:100%;padding:8px;margin-bottom:12px'>
  <label>Public Host (your external IP/hostname)</label>
  <input name='public_host' value='{escape(cfg["public_host"])}' style='width:100%;padding:8px;margin-bottom:12px'>
  <label>Public Port</label>
  <input name='public_port' value='{escape(str(cfg["public_port"]))}' style='width:100%;padding:8px;margin-bottom:12px'>
  <h3>Origin/Referer Spoofing</h3>
  <label>Fake Origin</label>
  <input name='fake_origin' value='{escape(cfg["fake_origin"])}' style='width:100%;padding:8px;margin-bottom:12px'>
  <label>Fake Referer</label>
  <input name='fake_referer' value='{escape(cfg["fake_referer"])}' style='width:100%;padding:8px;margin-bottom:12px'>
  <h3>CSRF Test Credentials</h3>
  <label>Test Username</label>
  <input name='csrf_username' value='{escape(cfg["csrf_username"])}' style='width:100%;padding:8px;margin-bottom:12px'>
  <label>Test Password (current: <code>{escape(masked)}</code>)</label>
  <input name='csrf_password' type='password' value='' placeholder='Leave blank to keep unchanged' style='width:100%;padding:8px;margin-bottom:12px'>
  <div style='margin-top:20px'>
    <button type='submit' class='btn' style='background:var(--success)'>Save Configuration</button>
    <a class='btn' href='/'>Back to Overview</a>
  </div>
</form>
<div class='card' style='margin-top:20px'>
  <div class='card-header'>Security Tips</div>
  <ul>
    <li>Use valid test credentials for accurate results</li>
    <li>Ensure your public host is accessible from the target network</li>
    <li>Test both with and without CSRF tokens to verify protection</li>
    <li>Check cookie SameSite attributes for CSRF vulnerability</li>
  </ul>
</div>"""
    return html_layout("Configuration", body)


def page_poc(cfg: dict, state: dict, include_tokens: bool = True) -> str:
    action = state.get("cookieauth_url", "")
    payload = build_payload(cfg, include_tokens=include_tokens)
    inputs = "\n".join(f"    <input type='hidden' name='{escape(k)}' value='{escape(v)}'>" for k, v in payload.items())
    pretty = _build_payload_kv(payload)
    mode = "WITH CSRF Tokens" if include_tokens else "WITHOUT CSRF Tokens"
    warning = "" if include_tokens else """<div class='indicator warning'><strong>Warning:</strong> This PoC excludes detected CSRF tokens. Use this to test if the application properly validates tokens.</div>"""

    body = f"""
<h1>CSRF Browser PoC &rarr; <code>{escape(action)}</code></h1>
<p><strong>Mode:</strong> {mode}</p>
{warning}
<div class='card'>
  <div class='card-header'>Auto-Submitting Form</div>
  <p>Make sure you're authenticated to the target!</p>
  <form id='csrf' method='POST' action='{escape(action)}' enctype='application/x-www-form-urlencoded'>
{inputs}
    <button type='submit' class='btn' style='background:var(--danger)'>Submit Manually</button>
  </form>
</div>
<div class='card'><div class='card-header'>Payload Details</div><pre>{escape(pretty)}</pre></div>
<p><a class='btn' href='/'>Back</a><a class='btn' href='/poc-no-token'>Test Without Tokens</a></p>"""
    return html_layout("CSRF Browser PoC", body)


def page_verify(cfg: dict, state: dict, query: Dict[str, str], deep: bool = False) -> str:
    from csrf_engine import test_csrf_protection

    origin = query.get("origin")
    referer = query.get("referer")
    include_tokens = query.get("include_tokens") == "1"

    result = test_csrf_protection(cfg, origin, referer, include_tokens=include_tokens)
    sc = "success" if result["success"] else "danger"
    token_info = "with CSRF tokens" if include_tokens else "without CSRF tokens"
    indicators = "".join(f"<li>{escape(ind)}</li>" for ind in result["indicators"])
    if indicators:
        indicators = f"<ul>{indicators}</ul>"

    if result["success"]:
        state["vulnerability_score"] = min(100, state.get("vulnerability_score", 0) + 50)
        recs = """<div class='indicator danger'><strong>CRITICAL:</strong> CSRF vulnerability confirmed!
    <ul><li>Implement proper CSRF token validation</li><li>Set SameSite=Strict or SameSite=Lax on all cookies</li>
    <li>Validate Origin and Referer headers strictly</li><li>Consider using double-submit cookie pattern</li>
    <li>Implement Fetch Metadata (Sec-Fetch-*) validation</li></ul></div>"""
    else:
        recs = """<div class='indicator success'><strong>Protected:</strong> The application rejected the forged request.
    <ul><li>CSRF protection is working correctly</li><li>Continue monitoring for bypass opportunities</li>
    <li>Test with different payload variations</li></ul></div>"""

    body = f"""
<h1>{'Deep ' if deep else ''}CSRF Verification</h1>
<div class='card'>
  <div class='card-header'>Test Results</div>
  <p><strong>Status:</strong> <span class='badge badge-{sc}'>{'VULNERABLE' if result['success'] else 'PROTECTED'}</span></p>
  <p><strong>HTTP Status Code:</strong> {result['status_code']}</p>
  <p><strong>Final URL:</strong> <code>{escape(result['final_url'])}</code></p>
  <p><strong>Test Mode:</strong> {token_info}</p>
  <h4>Indicators:</h4>{indicators}
  <h4>Response Preview:</h4>
  <pre style='max-height:200px;overflow-y:auto'>{escape(result['response_preview'])}</pre>
</div>
<div class='card'><div class='card-header'>Recommendations</div>{recs}</div>
<p><a class='btn' href='/'>Back</a><a class='btn' href='/suite?origin={escape(origin or cfg["fake_origin"])}'>Run Full Suite</a></p>"""
    return html_layout("CSRF Verification Result", body)


def page_suite(cfg: dict, state: dict, query: Dict[str, str]) -> str:
    from csrf_engine import run_suite

    res = run_suite(cfg, query.get("origin"), query.get("referer"))
    s = res.get("summary", {})
    vr = f"{s.get('bypass_success',0)}/{s.get('total_tests',0)}"
    rl = "HIGH" if s.get("bypass_success",0) > 5 else "MEDIUM" if s.get("bypass_success",0) > 0 else "LOW"
    rb = "badge-high" if rl == "HIGH" else "badge-medium" if rl == "MEDIUM" else "badge-low"

    recs = ""
    if s.get("bypass_success", 0) > 0:
        recs = f"""<div class='indicator danger'><strong>Vulnerabilities Found:</strong> {s['bypass_success']} bypass techniques succeeded.
    <ul><li>Implement strict input validation and normalization</li><li>Whitelist allowed HTTP methods</li>
    <li>Validate Content-Type headers strictly</li><li>Implement proper CSRF token validation</li>
    <li>Set SameSite attributes on all cookies</li></ul></div>"""
    else:
        recs = """<div class='indicator success'><strong>Good Security Posture:</strong> No bypass techniques succeeded.
    <ul><li>Continue monitoring for new bypass techniques</li><li>Regular security assessments recommended</li>
    <li>Keep security mechanisms up to date</li></ul></div>"""

    body = f"""
<h1>Comprehensive Security Assessment Suite</h1>
<div class='card'>
  <div class='card-header'>Test Summary</div>
  <p><strong>Origin:</strong> {escape(res['origin'])}</p>
  <p><strong>Referer:</strong> {escape(res['referer'])}</p>
  <p><strong>Risk Level:</strong> <span class='badge {rb}'>{rl}</span></p>
  <p><strong>Bypass Success Rate:</strong> {vr} tests successful</p>
</div>
<h3>URL Encoding Bypass Tests</h3>
<table><thead><tr><th>Test Case</th><th>URL</th><th>Status</th><th>Location</th><th>Cookie</th><th>Result</th></tr></thead>
<tbody>{_suite_rows(res['encoding'], vulnerable_col=True)}</tbody></table>
<h3>Path Manipulation Tests</h3>
<table><thead><tr><th>Test Case</th><th>URL</th><th>Status</th><th>Location</th><th>Cookie</th><th>Result</th></tr></thead>
<tbody>{_suite_rows(res['path'], vulnerable_col=True)}</tbody></table>
<h3>Header Manipulation Tests</h3>
<table><thead><tr><th>Test Case</th><th>Status</th><th>Location</th><th>Cookie</th><th>Result</th></tr></thead>
<tbody>{_suite_rows(res['headers'])}</tbody></table>
<h3>Fetch Metadata Tests (Sec-Fetch-*)</h3>
<table><thead><tr><th>Test Case</th><th>Status</th><th>Location</th><th>Cookie</th><th>Result</th></tr></thead>
<tbody>{_suite_rows(res['fetch_metadata'])}</tbody></table>
<h3>HTTP Method Tests</h3>
<table><thead><tr><th>Test Case</th><th>Method</th><th>Status</th><th>Location</th><th>Cookie</th><th>Allowed</th></tr></thead>
<tbody>{_suite_rows(res['methods'])}</tbody></table>
<h3>Payload Variation Tests</h3>
<table><thead><tr><th>Test Case</th><th>Content-Type</th><th>Status</th><th>Result</th><th>Location</th><th>Cookie</th></tr></thead>
<tbody>{_suite_rows(res['payloads'])}</tbody></table>
<div class='card'><div class='card-header'>Recommendations</div>{recs}</div>
<p><a class='btn' href='/'>Back to Overview</a></p>"""
    return html_layout("Security Assessment Suite", body)


def page_export_json(cfg: dict, state: dict, query: Dict[str, str]) -> str:
    from csrf_engine import run_suite

    res = run_suite(cfg, query.get("origin"), query.get("referer"))
    export = {
        "tool": "Enhanced CSRF Assessment Tool v2.1",
        "target": cfg["target_base"],
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": res["summary"],
        "vulnerability_score": state.get("vulnerability_score", 0),
        "protection_mechanisms": state.get("protection_mechanisms", []),
        "csrf_tokens_found": list(state.get("csrf_tokens", {}).keys()),
        "cookie_analysis": state.get("cookie_report", ""),
        "results": {k: res[k] for k in ("encoding","path","headers","fetch_metadata","methods","payloads")},
    }
    js = json.dumps(export, indent=2, ensure_ascii=False)
    body = f"""
<h1>JSON Export</h1>
<div class='card'>
  <div class='card-header'>Assessment Results (JSON)</div>
  <pre style='max-height:600px;overflow-y:auto'>{escape(js)}</pre>
</div>
<p><a class='btn' href='/'>Back</a><a class='btn' href='/suite?origin={escape(query.get("origin") or cfg["fake_origin"])}'>Run Full Suite</a></p>"""
    return html_layout("JSON Export", body)
