#!/usr/bin/env python3
"""
Lab panel — CampaignHub (fictional admin console).

The vulnerability is preserved one-to-one:
  - html-builder messages: NO event.origin check
  - view.html is rendered with createContextualFragment (scripts run)
  - no X-Frame-Options / CSP headers
  - containerStyles is required (same as the scenario; without it the
    builder threw before render)
"""

import http.server
import json
import os
import socketserver
import time
import urllib.parse
from http.cookies import SimpleCookie

WWW = os.path.join(os.path.dirname(os.path.abspath(__file__)), "www")

FLAG1 = os.environ.get("FLAG1", "FLAG{postmessage_without_origin_check}")
FLAG2 = os.environ.get("FLAG2", "FLAG{session_riding_via_dom_xss}")
FLAG3 = os.environ.get("FLAG3", "FLAG{stored_xss_widget_preview}")

# --- fixed lab accounts ---
USERS = {
    "viewer": {
        "password": os.environ.get("VIEWER_PASSWORD", "viewer123"),
        "role": "viewer",
        "name": "Deniz Kaya",
        "title": "Marketing Specialist",
    },
    "admin": {
        "password": os.environ.get("ADMIN_PASSWORD", "Admin!2024"),
        "role": "admin",
        "name": "Selin Arslan",
        "title": "Campaign Manager",
    },
}

# sid -> {user, created}
SESSIONS = {}
# widget id -> html (stored, rendered later)
WIDGETS = {}
_widget_seq = 0

MIME = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
}


def new_sid():
    return os.urandom(16).hex()


def session_from_headers(headers):
    cookie = SimpleCookie()
    raw = headers.get("Cookie", "")
    if raw:
        cookie.load(raw)
    sid = cookie.get("panel_sid")
    if not sid:
        return None
    return SESSIONS.get(sid.value)


def json_response(handler, code, obj):
    data = json.dumps(obj).encode()
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    # Lab note: reflect Origin so credentialed cross-port fetch works
    # ('*' + credentials is rejected by browsers).
    origin = handler.headers.get("Origin")
    handler.send_header("Access-Control-Allow-Origin", origin or "*")
    if origin:
        handler.send_header("Access-Control-Allow-Credentials", "true")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type")
    handler.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
    # Note: no XFO/CSP on purpose — the builder must stay frame-able.
    handler.end_headers()
    handler.wfile.write(data)


def redirect(handler, location, extra_headers=None):
    handler.send_response(302)
    handler.send_header("Location", location)
    handler.send_header("Content-Length", "0")
    for k, v in (extra_headers or {}).items():
        handler.send_header(k, v)
    handler.end_headers()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return b""
        return self.rfile.read(length)

    def _serve_file(self, rel_path):
        path = os.path.normpath(os.path.join(WWW, rel_path))
        if not path.startswith(WWW) or not os.path.isfile(path):
            self.send_response(404)
            body = b"not found"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        ext = os.path.splitext(path)[1].lower()
        with open(path, "rb") as f:
            data = f.read()
        # flag1 lives in the panel origin's localStorage (product app key);
        # only readable from that origin.
        data = data.replace(b"__FLAG1__", FLAG1.encode())
        self.send_response(200)
        self.send_header("Content-Type", MIME.get(ext, "application/octet-stream"))
        self.send_header("Content-Length", str(len(data)))
        # builder (and the rest) left frame-friendly; same as the original
        self.end_headers()
        self.wfile.write(data)

    # ---------------- routes ----------------

    def do_OPTIONS(self):
        # CORS preflight
        origin = self.headers.get("Origin")
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", origin or "*")
        if origin:
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)

        if path == "/healthz":
            json_response(self, 200, {"ok": True, "service": "panel"})
            return

        if path == "/":
            redirect(self, "/dashboard/")
            return

        # --- login form ---
        if path == "/login":
            self._serve_file("login.html")
            return

        if path == "/logout":
            cookie = SimpleCookie()
            raw = self.headers.get("Cookie", "")
            if raw:
                cookie.load(raw)
            sid = cookie.get("panel_sid")
            if sid and sid.value in SESSIONS:
                del SESSIONS[sid.value]
            redirect(self, "/login", {
                "Set-Cookie": "panel_sid=; Path=/; Max-Age=0; HttpOnly"
            })
            return

        # --- dashboard (must be authenticated) ---
        if path.startswith("/dashboard"):
            sess = session_from_headers(self.headers)
            if not sess:
                redirect(self, "/login")
                return
            self._serve_file("dashboard.html")
            return

        # --- APIs ---
        if path == "/panel/v2/user/status":
            sess = session_from_headers(self.headers)
            if not sess:
                json_response(self, 200, {"result": False})
                return
            u = USERS[sess["user"]]
            json_response(self, 200, {
                "result": True,
                "user": sess["user"],
                "name": u["name"],
                "role": u["role"],
            })
            return

        if path == "/panel/v2/campaigns":
            # flag2: returned only for an admin session
            sess = session_from_headers(self.headers)
            if not sess:
                json_response(self, 401, {"error": "unauthorized"})
                return
            if USERS[sess["user"]]["role"] != "admin":
                json_response(self, 403, {"error": "forbidden"})
                return
            json_response(self, 200, {
                "result": True,
                "campaigns": [
                    {"id": 101, "name": "Holiday Campaign", "status": "active"},
                    {"id": 102, "name": "New Customer Welcome", "status": "paused"},
                ],
                # the real flag — treated as a core record from the "db"
                "export_token": FLAG2,
            })
            return

        if path == "/panel/v2/audit/log":
            # flag3: admin only; read by the stored payload that runs
            # inside the widget preview
            sess = session_from_headers(self.headers)
            if not sess:
                json_response(self, 401, {"error": "unauthorized"})
                return
            if USERS[sess["user"]]["role"] != "admin":
                json_response(self, 403, {"error": "forbidden"})
                return
            json_response(self, 200, {
                "result": True,
                "entries": [
                    {"ts": 1727080000, "actor": "system", "event": "deploy"},
                    {"ts": 1727080100, "actor": "admin", "event": "widget.save"},
                ],
                "integrity_token": FLAG3,
            })
            return

        if path == "/panel/v2/widgets":
            sess = session_from_headers(self.headers)
            if not sess:
                json_response(self, 401, {"error": "unauthorized"})
                return
            out = [{"id": k, "name": v.get("name", "untitled"),
                    "savedAt": v.get("savedAt")} for k, v in WIDGETS.items()]
            json_response(self, 200, {"result": True, "widgets": out})
            return

        if path.startswith("/panel/widget/preview"):
            # GET /panel/widget/preview?id=... — renders stored HTML
            wid = (qs.get("id") or [None])[0]
            if not wid or wid not in WIDGETS:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            w = WIDGETS[wid]
            page = f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Widget Preview — {w.get('name','')}</title>
<style>body{{font-family:Arial;margin:24px}}.ph{{color:#666;font-size:13px}}</style>
</head>
<body>
<p class="ph">Preview · widget id: {wid} · saved by: {w.get('author','?')}</p>
<div id="widget-root"></div>
<script>
// SAME sink as the builder: HTML injected as-is, no sanitization
(function () {{
  var html = {json.dumps(w.get('html', ''))};
  var range = document.createRange();
  document.getElementById('widget-root').appendChild(
    range.createContextualFragment(html)
  );
}})();
</script>
</body></html>""".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)
            return

        # --- static ---
        if path.startswith("/html-builder"):
            rel = "html-builder/index.html"
        else:
            rel = path.lstrip("/")
            if path.endswith("/"):
                rel = path.lstrip("/") + "index.html"
        self._serve_file(rel)

    def do_POST(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        body = self._read_body()

        if path == "/panel/widget/save":
            sess = session_from_headers(self.headers)
            if not sess:
                json_response(self, 401, {"error": "unauthorized"})
                return
            try:
                data = json.loads(body or b"{}")
            except json.JSONDecodeError:
                json_response(self, 400, {"error": "bad json"})
                return
            html = data.get("html") or ""
            name = data.get("name") or "untitled"
            global _widget_seq
            _widget_seq += 1
            wid = f"w{_widget_seq}"
            WIDGETS[wid] = {
                "html": html,
                "name": name,
                "author": sess["user"],
                "savedAt": int(time.time()),
            }
            # scenario: no sanitization here — save as-is
            json_response(self, 200, {"result": True, "id": wid})
            return

        json_response(self, 404, {"error": "not found"})

    def log_message(self, fmt, *args):
        pass


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# Login needs Set-Cookie after headers are decided — handled here.
_orig_post = Handler.do_POST


def do_POST_with_cookie(self):
    parsed = urllib.parse.urlsplit(self.path)
    if parsed.path != "/login":
        _orig_post(self)
        return

    body = self._read_body()
    ctype = self.headers.get("Content-Type", "")
    if "application/json" in ctype:
        try:
            data = json.loads(body or b"{}")
        except json.JSONDecodeError:
            json_response(self, 400, {"error": "bad json"})
            return
    else:
        data = {k: v[0] for k, v in
                urllib.parse.parse_qs(body.decode("utf-8", "replace")).items()}

    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    user = USERS.get(username)
    if not user or user["password"] != password:
        json_response(self, 401, {"error": "Invalid username or password."})
        return

    sid = new_sid()
    SESSIONS[sid] = {"user": username, "created": time.time()}
    payload = json.dumps({"result": True, "redirect": "/dashboard/",
                          "role": user["role"]}).encode()
    origin = self.headers.get("Origin")
    self.send_response(200)
    self.send_header("Content-Type", "application/json; charset=utf-8")
    self.send_header("Content-Length", str(len(payload)))
    if origin:
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Credentials", "true")
    # HttpOnly — cannot be read with document.cookie (as in the report).
    # localhost:8000 <-> localhost:8080 is same-site; Lax is enough.
    self.send_header(
        "Set-Cookie",
        f"panel_sid={sid}; Path=/; HttpOnly; SameSite=Lax",
    )
    self.end_headers()
    self.wfile.write(payload)


Handler.do_POST = do_POST_with_cookie

if __name__ == "__main__":
    print(f"panel listening on :3000  FLAG1={FLAG1}")
    ThreadingHTTPServer(("0.0.0.0", 3000), Handler).serve_forever()
