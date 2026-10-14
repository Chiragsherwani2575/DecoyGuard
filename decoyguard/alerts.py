"""Alert delivery: webhook (Slack/Teams/Discord-compatible) and email."""
from __future__ import annotations

import json
import smtplib
import sys
import threading
import time
import urllib.request
from email.message import EmailMessage
from typing import Dict, List
from urllib.parse import urlparse

from .config import Config


def format_message(alert: Dict, decoy: Dict) -> str:
    return (
        "DecoyGuard ALERT: decoy '{label}' ({kind}) was triggered.\n"
        "Source IP: {ip}\n"
        "Request: {method} {path}\n"
        "User-Agent: {ua}\n"
        "Time (UTC): {ts}\n"
        "Decoy planted at: {where}\n"
        "{detail}"
        "Nobody has a legitimate reason to touch this. Treat it as a possible intrusion."
    ).format(
        label=decoy.get("label", "?"),
        kind=decoy.get("kind", "?"),
        ip=alert["source_ip"],
        method=alert["method"],
        path=alert["path"],
        ua=alert["user_agent"] or "(none)",
        ts=alert["ts"],
        where=decoy.get("path", "?"),
        detail=("Detail: " + alert["detail"] + "\n") if alert.get("detail") else "",
    )


class Notifier:
    """Sends alerts, with a per-(decoy, IP) cooldown so a scanner can't flood you."""

    def __init__(self, cfg: Config, sync: bool = False):
        self.cfg = cfg
        self.sync = sync  # deliver inline (used by tests and test-alert)
        self.errors: List[str] = []
        self._last: Dict[tuple, float] = {}
        self._lock = threading.Lock()

    def configured(self) -> bool:
        c = self.cfg
        return bool(c.webhook_url or (c.smtp_host and c.smtp_to))

    def _cooldown_ok(self, key: tuple) -> bool:
        now = time.monotonic()
        with self._lock:
            last = self._last.get(key)
            if last is not None and now - last < self.cfg.cooldown_seconds:
                return False
            self._last[key] = now
            if len(self._last) > 10000:  # bound memory under scan floods
                cutoff = now - self.cfg.cooldown_seconds
                self._last = {k: v for k, v in self._last.items() if v >= cutoff}
            return True

    def maybe_notify(self, alert: Dict, decoy: Dict) -> bool:
        """Returns True if a notification was dispatched (i.e. not suppressed)."""
        if not self._cooldown_ok((alert["token"], alert["source_ip"])):
            return False
        if self.sync:
            self._deliver(alert, decoy)
        else:
            threading.Thread(target=self._deliver, args=(alert, decoy), daemon=True).start()
        return True

    def send_test(self) -> List[str]:
        if not self.configured():
            return ["no webhook or SMTP settings configured"]
        alert = {
            "id": 0,
            "token": "test",
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
            "source_ip": "203.0.113.7",
            "user_agent": "decoyguard test-alert",
            "method": "GET",
            "path": "/t/test",
            "detail": "this is a test, not a real intrusion",
        }
        decoy = {"label": "TEST DECOY", "kind": "test", "path": "-"}
        return self._deliver(alert, decoy)

    # -- delivery --------------------------------------------------------
    def _deliver(self, alert: Dict, decoy: Dict) -> List[str]:
        errors: List[str] = []
        text = format_message(alert, decoy)
        if self.cfg.webhook_url:
            try:
                self._webhook(text, alert, decoy)
            except Exception as exc:  # delivery must never crash the server
                errors.append("webhook: %s" % exc)
        if self.cfg.smtp_host and self.cfg.smtp_to:
            try:
                self._email(text)
            except Exception as exc:
                errors.append("email: %s" % exc)
        for err in errors:
            print("[decoyguard] delivery failed -> " + err, file=sys.stderr)
        self.errors = (self.errors + errors)[-20:]
        return errors

    def _webhook(self, text: str, alert: Dict, decoy: Dict) -> None:
        url = self.cfg.webhook_url
        if urlparse(url).scheme not in ("http", "https"):
            raise ValueError("webhook_url must be http(s)")
        payload = {"text": text, "alert": alert, "decoy": decoy}
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()

    def _email(self, text: str) -> None:
        c = self.cfg
        msg = EmailMessage()
        msg["Subject"] = "[DecoyGuard] Decoy triggered - possible intrusion"
        msg["From"] = c.smtp_from or c.smtp_user or "decoyguard@localhost"
        msg["To"] = c.smtp_to
        msg.set_content(text)
        if int(c.smtp_port) == 465:
            smtp = smtplib.SMTP_SSL(c.smtp_host, int(c.smtp_port), timeout=10)
        else:
            smtp = smtplib.SMTP(c.smtp_host, int(c.smtp_port), timeout=10)
        with smtp:
            smtp.ehlo()
            if int(c.smtp_port) != 465 and smtp.has_extn("starttls"):
                smtp.starttls()
                smtp.ehlo()
            if c.smtp_user:
                smtp.login(c.smtp_user, c.smtp_password)
            smtp.send_message(msg)
