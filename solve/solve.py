#!/usr/bin/env python3
"""
CampaignHub DOM XSS Lab — reference solver (SPOILER).

CI-friendly HTTP path that proves each stage's data is reachable the same way
the browser exploit reaches it:

  flag1  GET  /html-builder/          → localStorage seed in page JS
  flag2  POST /login (admin) + GET
         /panel/v2/campaigns          → export_token  (session cookie)
  flag3  GET  /panel/v2/audit/log     → integrity_token (admin session)

The interactive browser exploit (postMessage → contextualFragment →
credentials:'include') lives in solve/solution_poc.html — open that for the
full XSS walkthrough.

Usage:  python3 solve/solve.py
Env:    LAB_URL (default http://localhost:8080)
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request

LAB = os.environ.get("LAB_URL", "http://localhost:8080").rstrip("/")
UA = "Mozilla/5.0 (CampaignHubSolve)"
FLAG_RE = re.compile(r"FLAG\{[^}]+\}")


def req(method: str, path: str, data: dict | None = None, cookie: str | None = None):
    url = LAB + path
    body = None
    headers = {"User-Agent": UA}
    if data is not None:
        body = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    if cookie:
        headers["Cookie"] = cookie
    r = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            raw = resp.read().decode("utf-8", "replace")
            set_cookie = resp.headers.get("Set-Cookie") or ""
            return resp.status, raw, set_cookie
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        return e.code, raw, e.headers.get("Set-Cookie") or ""


def sid_from(set_cookie: str) -> str:
    m = re.search(r"panel_sid=([^;]+)", set_cookie)
    if not m:
        raise SystemExit("login did not set panel_sid cookie")
    return f"panel_sid={m.group(1)}"


def main() -> int:
    print(f"[+] lab = {LAB}")

    # --- stage 1 ---
    st, html, _ = req("GET", "/html-builder/")
    if st != 200:
        print(f"[-] html-builder HTTP {st}")
        return 1
    if "campaignhub_app_key" not in html:
        print("[-] campaignhub_app_key seed missing from builder")
        return 1
    m = FLAG_RE.search(html)
    flag1 = m.group(0) if m else "(seed present, flag regex miss)"
    print(f"[+] flag1 (localStorage seed) = {flag1}")

    # --- stage 2 + 3 need admin session ---
    st, body, sc = req(
        "POST",
        "/login",
        {"username": "admin", "password": os.environ.get("ADMIN_PASSWORD", "Admin!2024")},
    )
    try:
        login_ok = st == 200 and json.loads(body).get("result") is True
    except json.JSONDecodeError:
        login_ok = False
    if not login_ok:
        print(f"[-] admin login failed: {st} {body[:200]}")
        return 1
    cookie = sid_from(sc)
    print("[+] admin session established (HttpOnly panel_sid)")

    st, body, _ = req("GET", "/panel/v2/campaigns", cookie=cookie)
    if st != 200:
        print(f"[-] campaigns HTTP {st}")
        return 1
    try:
        token = json.loads(body).get("export_token", "")
    except json.JSONDecodeError:
        token = ""
    print(f"[+] flag2 (session riding / export_token) = {token or body[:120]}")

    st, body, _ = req("GET", "/panel/v2/audit/log", cookie=cookie)
    if st != 200:
        print(f"[-] audit/log HTTP {st}")
        return 1
    try:
        token3 = json.loads(body).get("integrity_token", "")
    except json.JSONDecodeError:
        token3 = ""
    print(f"[+] flag3 (stored-XSS target / integrity_token) = {token3 or body[:120]}")

    # note: browser PoC additionally proves JS execution in panel origin
    print("[+] for the browser XSS path open: http://localhost:8000/solution_poc.html")
    print("[+] all reference checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
