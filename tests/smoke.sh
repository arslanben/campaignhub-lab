#!/usr/bin/env bash
# CampaignHub DOM XSS Lab — smoke tests against a running lab.
#
# Spoiler note: this file (and the repository in general) contains the lab's
# expected values by design; see README.md.
set -uo pipefail

PANEL="${LAB_URL:-http://localhost:8080}"
ATTACKER="${ATTACKER_URL:-http://localhost:8000}"
UA="Mozilla/5.0 (SmokeTest)"
CURL_UA="curl/8.0-smoke"   # non-browser → WAF UA rule must fire
FAIL=0

pass() { printf '  [OK]   %s\n' "$1"; }
fail() { printf '  [FAIL] %s\n' "$1"; FAIL=1; }

code() {
  # code METHOD URL [curl-args...]
  local method="$1" url="$2"
  shift 2
  curl -sS -o /tmp/lab-smoke-body -w '%{http_code}' -A "$UA" -X "$method" "$url" "$@"
}

code_nua() {
  local method="$1" url="$2"
  shift 2
  curl -sS -o /tmp/lab-smoke-body -w '%{http_code}' -A "$CURL_UA" -X "$method" "$url" "$@"
}

json_ok() {
  # python tolerates spaces after ':' in json.dumps
  python3 -c 'import sys,json; d=json.load(open("/tmp/lab-smoke-body")); sys.exit(0 if d.get("result") is True else 1)' 2>/dev/null
}

echo "== CampaignHub smoke =="

# --- infrastructure ---
c=$(code GET "$PANEL/html-builder/")
[[ "$c" == "200" ]] && pass "html-builder reachable without Referer ($c)" \
                    || fail "html-builder without Referer → $c"

c=$(code GET "$PANEL/html-builder/" -e "http://evil.example/")
[[ "$c" == "403" ]] && pass "WAF blocks cross-site Referer ($c)" \
                    || fail "WAF Referer rule → $c (expected 403)"

# same host, different port (attacker) must also be blocked
c=$(code GET "$PANEL/html-builder/" -e "http://localhost:8000/")
[[ "$c" == "403" ]] && pass "WAF blocks attacker-origin Referer ($c)" \
                    || fail "WAF attacker Referer → $c (expected 403)"

# same panel origin Referer may pass
c=$(code GET "$PANEL/html-builder/" -e "$PANEL/")
[[ "$c" == "200" ]] && pass "WAF allows same-origin Referer ($c)" \
                    || fail "WAF same-origin Referer → $c (expected 200)"

c=$(code_nua GET "$PANEL/panel/v2/user/status")
[[ "$c" == "403" ]] && pass "WAF blocks non-browser UA on /panel/ ($c)" \
                    || fail "WAF UA rule → $c (expected 403)"

c=$(code GET "$ATTACKER/")
[[ "$c" == "200" ]] && pass "attacker start page ($c)" \
                    || fail "attacker → $c"

c=$(code GET "$ATTACKER/solution_poc.html")
[[ "$c" == "200" ]] && pass "solution PoC published ($c)" \
                    || fail "solution_poc → $c"

c=$(code GET "$PANEL/healthz")
[[ "$c" == "200" ]] && pass "panel /healthz ($c)" \
                    || fail "healthz → $c"

# --- flag1: present in builder HTML (localStorage seed) ---
if grep -q 'campaignhub_app_key' /tmp/lab-smoke-body 2>/dev/null; then
  :
fi
code GET "$PANEL/html-builder/" >/dev/null
if grep -q 'campaignhub_app_key' /tmp/lab-smoke-body; then
  pass "builder seeds campaignhub_app_key"
else
  fail "builder missing campaignhub_app_key seed"
fi

# --- login + session ---
JAR=$(mktemp)
c=$(code POST "$PANEL/login" \
  -H 'Content-Type: application/json' \
  -c "$JAR" \
  -d '{"username":"admin","password":"Admin!2024"}')
if [[ "$c" == "200" ]] && json_ok; then
  pass "admin login"
else
  fail "admin login → $c $(cat /tmp/lab-smoke-body)"
fi

# --- flag2: admin campaigns ---
c=$(code GET "$PANEL/panel/v2/campaigns" -b "$JAR")
if [[ "$c" == "200" ]] && grep -q 'export_token' /tmp/lab-smoke-body; then
  pass "admin /panel/v2/campaigns returns export_token"
else
  fail "campaigns → $c"
fi

# --- flag3: admin audit log ---
c=$(code GET "$PANEL/panel/v2/audit/log" -b "$JAR")
if [[ "$c" == "200" ]] && grep -q 'integrity_token' /tmp/lab-smoke-body; then
  pass "admin /panel/v2/audit/log returns integrity_token"
else
  fail "audit/log → $c"
fi

# --- viewer must NOT see admin data ---
JAR2=$(mktemp)
code POST "$PANEL/login" -H 'Content-Type: application/json' -c "$JAR2" \
  -d '{"username":"viewer","password":"viewer123"}' >/dev/null
c=$(code GET "$PANEL/panel/v2/campaigns" -b "$JAR2")
[[ "$c" == "403" ]] && pass "viewer forbidden on campaigns ($c)" \
                    || fail "viewer campaigns → $c (expected 403)"

# --- widget save: any authenticated role (viewer is enough for stage 3) ---
JAR3=$(mktemp)
code POST "$PANEL/login" -H 'Content-Type: application/json' -c "$JAR3" \
  -d '{"username":"viewer","password":"viewer123"}' >/dev/null
c=$(code POST "$PANEL/panel/widget/save" -b "$JAR3" \
  -H 'Content-Type: application/json' \
  -d '{"name":"smoke","html":"<b>smoke</b>"}')
if [[ "$c" == "200" ]] && json_ok; then
  pass "viewer can widget-save (low-priv stored XSS path)"
else
  fail "viewer widget save → $c"
fi

rm -f "$JAR" "$JAR2" "$JAR3"

echo
if [[ "$FAIL" -eq 0 ]]; then
  echo "All smoke tests passed."
  exit 0
else
  echo "Smoke tests FAILED."
  exit 1
fi
