"""The tripwire HTTP server.

Every decoy file points at ``<base_url>/t/<token>/...``. Legitimate users never
visit those URLs, so any request is a high-confidence signal of an intruder.
The dashboard lives under ``/_dg/`` and requires the dashboard key.
"""
from __future__ import annotations

import hmac
import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Optional
from urllib.parse import parse_qs, urlparse

from .alerts import Notifier
from .config import Config
from .db import Store

MAX_BODY = 4096

# 1x1 transparent GIF, served to "tracking pixel" decoys.
PIXEL = (
    b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01"
    b"\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
)

LOGIN_PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>Sign in</title>
<style>body{font-family:sans-serif;background:#f4f5f7;display:flex;justify-content:center;padding-top:12vh}
form{background:#fff;padding:2rem;border-radius:8px;box-shadow:0 1px 4px #0002;width:280px}
input{display:block;width:100%;margin:.5rem 0;padding:.5rem;box-sizing:border-box}
button{width:100%;padding:.6rem}.err{color:#b00020;font-size:.9rem}</style></head>
<body><form method="post"><h3>Secure Sign in</h3>{error}
<input name="username" placeholder="Username" autocomplete="off">
<input name="password" type="password" placeholder="Password" autocomplete="off">
<button type="submit">Sign in</button></form></body></html>"""

NOT_FOUND_PAGE = (
    "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n"
    "<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n"
    "</body>\r\n</html>\r\n"
)

_USER_FIELDS = ("username", "user", "email", "login")


class Handler(BaseHTTPRequestHandler):
    # Look like an ordinary web server; never advertise Python.
    server_version = "nginx"
    sys_version = ""

    def log_message(self, *args) -> None:  # attacker traffic is stored in the DB instead
        pass

    # All verbs go through one handler: a tripwire should catch any of them.
    def do_GET(self): self._handle()
    def do_HEAD(self): self._handle()
    def do_POST(self): self._handle()
    def do_PUT(self): self._handle()
    def do_PATCH(self): self._handle()
    def do_DELETE(self): self._handle()
    def do_OPTIONS(self): self._handle()

    # -- helpers ---------------------------------------------------------
    def _client_ip(self) -> str:
        if self.server.cfg.trust_proxy:
            forwarded = self.headers.get("X-Forwarded-For", "")
            if forwarded:
                return forwarded.split(",")[0].strip()[:64]
        return self.client_address[0]

    def _send(self, status: int, body, ctype: str = "text/html; charset=utf-8",
              extra: Optional[Dict[str, str]] = None) -> None:
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _not_found(self) -> None:
        self._send(404, NOT_FOUND_PAGE)

    def _read_body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        return self.rfile.read(max(0, min(length, MAX_BODY)))

    # -- routing ---------------------------------------------------------
    def _handle(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/_dg" or path.startswith("/_dg/"):
            return self._dashboard(parsed)
        if path.startswith("/t/"):
            return self._tripwire(parsed)
        return self._not_found()

    def _tripwire(self, parsed) -> None:
        parts = parsed.path.split("/")  # ['', 't', token, ...]
        token = parts[2] if len(parts) > 2 else ""
        decoy = self.server.store.get_decoy(token) if token else None
        if decoy is None:
            return self._not_found()

        detail = ""
        if self.command in ("POST", "PUT", "PATCH"):
            form = parse_qs(self._read_body().decode("utf-8", "replace"))
            for field in _USER_FIELDS:
                if form.get(field):
                    # Store the username only; the password is never recorded.
                    detail = "login attempt as user %r (password not stored)" % form[field][0][:80]
                    break

        target = parsed.path + ("?" + parsed.query if parsed.query else "")
        alert = self.server.store.add_alert(
            token=token,
            source_ip=self._client_ip(),
            user_agent=self.headers.get("User-Agent", ""),
            method=self.command,
            path=target,
            detail=detail,
        )
        try:
            self.server.notifier.maybe_notify(alert, decoy)
        except Exception:
            pass  # never let alerting break the response

        lower = parsed.path.lower()
        if lower.endswith((".gif", ".png", ".jpg", ".jpeg")):
            return self._send(200, PIXEL, "image/gif")
        if self.command in ("GET", "HEAD"):
            return self._send(200, LOGIN_PAGE.replace("{error}", ""))
        error = '<p class="err">Invalid username or password.</p>'
        return self._send(401, LOGIN_PAGE.replace("{error}", error))

    # -- dashboard -------------------------------------------------------
    def _authorized(self, parsed) -> bool:
        key = self.server.cfg.dashboard_key
        supplied = parse_qs(parsed.query).get("key", [""])[0]
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            supplied = auth[7:]
        return bool(key) and hmac.compare_digest(supplied.encode("utf-8"), key.encode("utf-8"))

    def _dashboard(self, parsed) -> None:
        path = parsed.path.rstrip("/")
        if path == "/_dg/health":
            return self._send(200, "ok", "text/plain")
        if not self._authorized(parsed):
            return self._not_found()  # don't reveal that a dashboard exists
        store: Store = self.server.store
        if path == "/_dg/api/alerts":
            body = json.dumps(store.list_alerts(200), indent=2)
            return self._send(200, body, "application/json")
        if path in ("/_dg", ""):
            return self._send(
                200,
                render_dashboard(store.list_alerts(100), store.list_decoys()),
                extra={"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"},
            )
        return self._not_found()


def render_dashboard(alerts, decoys) -> str:
    esc = lambda v: html.escape(str(v if v is not None else ""))  # noqa: E731 (attacker-controlled data!)
    alert_rows = "".join(
        "<tr><td>{ts}</td><td>{label}</td><td>{ip}</td><td>{req}</td><td>{ua}</td><td>{detail}</td></tr>".format(
            ts=esc(a["ts"]), label=esc(a.get("label") or a["token"]), ip=esc(a["source_ip"]),
            req=esc(a["method"] + " " + a["path"]), ua=esc(a["user_agent"]), detail=esc(a["detail"]),
        )
        for a in alerts
    ) or '<tr><td colspan="6">No alerts. All quiet.</td></tr>'
    decoy_rows = "".join(
        "<tr><td>{label}</td><td>{kind}</td><td>{path}</td><td>{n}</td></tr>".format(
            label=esc(d["label"]), kind=esc(d["kind"]), path=esc(d["path"]), n=esc(d["triggers"]))
        for d in decoys
    ) or '<tr><td colspan="4">No decoys deployed yet.</td></tr>'
    return (
        '<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="30">'
        "<title>DecoyGuard</title><style>"
        "body{font-family:system-ui,sans-serif;margin:2rem;color:#1b1f24}"
        "table{border-collapse:collapse;width:100%%;margin-bottom:2rem;font-size:.9rem}"
        "th,td{border:1px solid #d0d7de;padding:.4rem .6rem;text-align:left;vertical-align:top}"
        "th{background:#f6f8fa}.n{color:#57606a}</style></head><body>"
        "<h1>DecoyGuard</h1><p class=\"n\">%d decoys deployed &middot; %d recent alerts &middot; refreshes every 30s</p>"
        "<h2>Alerts (newest first)</h2><table><tr><th>Time (UTC)</th><th>Decoy</th><th>Source IP</th>"
        "<th>Request</th><th>User-Agent</th><th>Detail</th></tr>%s</table>"
        "<h2>Deployed decoys</h2><table><tr><th>Label</th><th>Kind</th><th>Location</th><th>Triggers</th></tr>%s</table>"
        "</body></html>"
    ) % (len(decoys), len(alerts), alert_rows, decoy_rows)


def make_server(cfg: Config, store: Store, notifier: Notifier) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((cfg.host, cfg.port), Handler)
    server.daemon_threads = True
    server.cfg = cfg
    server.store = store
    server.notifier = notifier
    return server
