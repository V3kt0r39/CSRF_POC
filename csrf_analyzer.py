#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CSRF Assessment Analyzer — cookie analysis, CSP/CORS checks, vulnerability scoring.
"""

from typing import Dict, List, Optional


def parse_set_cookie_flags(set_cookie_headers: List[str]) -> List[Dict]:
    res = []
    for sc in set_cookie_headers:
        parts = [p.strip() for p in sc.split(";")]
        kv = {
            "raw": sc, "secure": False, "httponly": False, "samesite": None,
            "expires": None, "domain": None, "path": None,
            "cookie_name": "(unknown)", "cookie_val_preview": "",
        }
        if parts and "=" in parts[0]:
            k, v = parts[0].split("=", 1)
            kv["cookie_name"] = k
            kv["cookie_val_preview"] = (v[:20] + "...") if len(v) > 20 else v

        for p in parts[1:]:
            pl = p.lower()
            if pl == "secure":
                kv["secure"] = True
            elif pl == "httponly":
                kv["httponly"] = True
            elif pl.startswith("samesite="):
                kv["samesite"] = pl.split("=", 1)[1].capitalize()
            elif pl.startswith("expires="):
                kv["expires"] = p.split("=", 1)[1][:30]
            elif pl.startswith("domain="):
                kv["domain"] = p.split("=", 1)[1]
            elif pl.startswith("path="):
                kv["path"] = p.split("=", 1)[1]
        res.append(kv)
    return res


def analyze_cookie_security(cookies: List[Dict]) -> Dict:
    analysis = {
        "total_cookies": len(cookies),
        "samesite_missing": 0, "samesite_none": 0,
        "samesite_lax": 0, "samesite_strict": 0,
        "secure_missing": 0, "httponly_missing": 0,
        "csrf_risk_level": "LOW", "recommendations": [],
    }

    for cookie in cookies:
        ss = cookie.get("samesite")
        if not ss:
            analysis["samesite_missing"] += 1
        elif ss.lower() == "none":
            analysis["samesite_none"] += 1
        elif ss.lower() == "lax":
            analysis["samesite_lax"] += 1
        elif ss.lower() == "strict":
            analysis["samesite_strict"] += 1
        if not cookie.get("secure"):
            analysis["secure_missing"] += 1
        if not cookie.get("httponly"):
            analysis["httponly_missing"] += 1

    if analysis["samesite_missing"] > 0 or analysis["samesite_none"] > 0:
        analysis["csrf_risk_level"] = "HIGH"
        analysis["recommendations"].append("Set SameSite=Strict or SameSite=Lax on all cookies")
    elif analysis["samesite_lax"] > 0:
        analysis["csrf_risk_level"] = "MEDIUM"
        analysis["recommendations"].append("Consider SameSite=Strict for sensitive operations")

    if analysis["secure_missing"] > 0:
        analysis["recommendations"].append("Set Secure flag on all cookies")
    if analysis["httponly_missing"] > 0:
        analysis["recommendations"].append("Set HttpOnly flag on session cookies")
    return analysis


def pretty_cookie_report(items: List[Dict], analysis: Optional[Dict] = None) -> str:
    if not items:
        return "(no Set-Cookie headers observed)"
    output = []
    for i in items:
        flags = []
        if i.get("secure"):
            flags.append("Secure")
        if i.get("httponly"):
            flags.append("HttpOnly")
        if i.get("samesite"):
            flags.append(f"SameSite={i['samesite']}")
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
        if analysis["recommendations"]:
            output.append("\nRecommendations:")
            for rec in analysis["recommendations"]:
                output.append(f"  - {rec}")
    return "\n".join(output)


def calc_vulnerability_score(state: dict) -> int:
    score = 0
    if not state.get("csrf_tokens"):
        score += 30
    risk = state.get("cookie_risk_level", "LOW")
    if risk == "HIGH":
        score += 40
    elif risk == "MEDIUM":
        score += 20
    if state.get("cors_wildcard"):
        score += 15
    if not state.get("csp_detected"):
        score += 5
    return min(score, 100)
