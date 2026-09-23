#!/usr/bin/env python3
"""
Minimal WAF simulation.

Goal: mirror the F5-style rule from the scenario.
  1) Reject requests whose Referer origin is NOT the panel origin with 403.
     Same-host different-port (e.g. attacker on :8000) is cross-origin and
     must be blocked — otherwise referrerpolicy="no-referrer" would be a
     pointless lesson. An absent Referer is allowed (that is the bypass).
  2) Reject /panel/ requests without a browser User-Agent (note for curl).
"""

import http.server
import http.client
import os
import socketserver
import urllib.parse

UPSTREAM = ("panel", 3000)
LISTEN = ("0.0.0.0", 8080)
# Host port the browser uses to reach the panel (compose WAF_PORT).
PANEL_PUBLIC_PORT = os.environ.get("WAF_PORT", "8080")

BROWSER_UA_HINTS = ("mozilla", "chrome", "safari", "firefox", "edg/")


def allowed_referer_origins() -> set[str]:
    """Origins that count as 'same site as the panel' for the Referer rule."""
    ports = {PANEL_PUBLIC_PORT, "8080"}
    origins = set()
    for host in ("localhost", "127.0.0.1"):
        for port in ports:
            origins.add(f"http://{host}:{port}")
            origins.add(f"https://{host}:{port}")
    # docker-internal (if anything ever sets Referer to the upstream)
    origins.add(f"http://{UPSTREAM[0]}:{UPSTREAM[1]}")
    return origins


def is_browser_ua(ua: str) -> bool:
    ua_l = (ua or "").lower()
    return any(h in ua_l for h in BROWSER_UA_HINTS)


def referer_allowed(referer: str) -> bool:
    """
    No Referer  -> allowed (referrerpolicy="no-referrer" bypass).
    Referer     -> full origin must equal the panel origin.
                   http://localhost:8000 != http://localhost:8080 -> block.
    """
    if not referer:
        return True
    parts = urllib.parse.urlsplit(referer)
    if not parts.scheme or not parts.netloc:
        return False
    origin = f"{parts.scheme}://{parts.netloc}"
    return origin in allowed_referer_origins()


def cors_origin(self):
    """Reflect Origin for credentialed fetch ('*' + credentials fails)."""
    origin = self.headers.get("Origin")
    return origin if origin else "*"


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _connect(self):
        return http.client.HTTPConnection(*UPSTREAM, timeout=10)

    def _send_simple(self, code, body: bytes, content_type="text/html"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _cors_preflight(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", cors_origin(self))
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
        self.send_header("Access-Control-Max-Age", "600")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _relay(self, method: str):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        if parsed.query:
            path += "?" + parsed.query

        # OPTIONS never goes upstream
        if method == "OPTIONS":
            self._cors_preflight()
            return

        # --- rule 1: Referer origin must be the panel origin ---
        referer = self.headers.get("Referer", "")
        if not referer_allowed(referer):
            self._send_simple(
                403,
                b"Request Rejected (F5 BIG-IP: referenced URL not allowed)",
            )
            print(f"[WAF] 403 referer={referer!r} path={path}")
            return

        # --- rule 2: UA ---
        ua = self.headers.get("User-Agent", "")
        if path.startswith("/panel/") and not is_browser_ua(ua):
            self._send_simple(
                403,
                b"Request Rejected (F5 BIG-IP: suspicious user agent)",
            )
            print(f"[WAF] 403 ua={ua!r} path={path}")
            return

        conn = self._connect()
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else None

            headers = {
                k: v
                for k, v in self.headers.items()
                if k.lower() not in ("host", "connection", "content-length")
            }
            headers["Host"] = UPSTREAM[0]

            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read()

            self.send_response(resp.status)
            saw_cors = False
            skip = {"transfer-encoding", "connection", "content-length",
                    "server", "date"}
            for k, v in resp.getheaders():
                if k.lower() in skip:
                    continue
                if k.lower() == "access-control-allow-origin":
                    saw_cors = True
                self.send_header(k, v)
            if not saw_cors:
                self.send_header("Access-Control-Allow-Origin", cors_origin(self))
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            print(f"[WAF] {method} {path} -> {resp.status}")
        except Exception as e:
            print(f"[WAF] upstream error: {e}")
            try:
                self._send_simple(502, b"bad gateway")
            except Exception:
                pass
        finally:
            conn.close()

    def do_GET(self):
        self._relay("GET")

    def do_POST(self):
        self._relay("POST")

    def do_PUT(self):
        self._relay("PUT")

    def do_DELETE(self):
        self._relay("DELETE")

    def do_OPTIONS(self):
        self._relay("OPTIONS")

    def log_message(self, fmt, *args):
        pass


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


if __name__ == "__main__":
    print(f"WAF listening on {LISTEN[0]}:{LISTEN[1]} -> {UPSTREAM[0]}:{UPSTREAM[1]}")
    ThreadingHTTPServer(LISTEN, Handler).serve_forever()
