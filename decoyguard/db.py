"""SQLite storage for decoys and alerts."""
from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS decoys (
    token      TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,
    label      TEXT NOT NULL,
    path       TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    token      TEXT NOT NULL,
    ts         TEXT NOT NULL,
    source_ip  TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    method     TEXT NOT NULL,
    path       TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_alerts_token ON alerts(token);
"""

# Everything in an alert comes from the attacker, so cap field sizes.
_MAX = 300


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _clip(value: str) -> str:
    return (value or "")[:_MAX]


class Store:
    def __init__(self, path: str):
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- decoys ----------------------------------------------------------
    def add_decoy(self, token: str, kind: str, label: str, path: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO decoys (token, kind, label, path, created_at) VALUES (?,?,?,?,?)",
                (token, kind, label, path, _now()),
            )
            self._conn.commit()

    def get_decoy(self, token: str) -> Optional[Dict]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM decoys WHERE token = ?", (token,)
            ).fetchone()
        return dict(row) if row else None

    def list_decoys(self) -> List[Dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT d.*, (SELECT COUNT(*) FROM alerts a WHERE a.token = d.token) AS triggers "
                "FROM decoys d ORDER BY d.created_at, d.label"
            ).fetchall()
        return [dict(r) for r in rows]

    # -- alerts ----------------------------------------------------------
    def add_alert(
        self,
        token: str,
        source_ip: str,
        user_agent: str,
        method: str,
        path: str,
        detail: str = "",
    ) -> Dict:
        ts = _now()
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO alerts (token, ts, source_ip, user_agent, method, path, detail) "
                "VALUES (?,?,?,?,?,?,?)",
                (token, ts, _clip(source_ip), _clip(user_agent), _clip(method), _clip(path), _clip(detail)),
            )
            self._conn.commit()
            alert_id = cur.lastrowid
        return {
            "id": alert_id,
            "token": token,
            "ts": ts,
            "source_ip": _clip(source_ip),
            "user_agent": _clip(user_agent),
            "method": _clip(method),
            "path": _clip(path),
            "detail": _clip(detail),
        }

    def list_alerts(self, limit: int = 100) -> List[Dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT a.*, d.kind AS kind, d.label AS label, d.path AS decoy_path "
                "FROM alerts a LEFT JOIN decoys d ON d.token = a.token "
                "ORDER BY a.id DESC LIMIT ?",
                (int(limit),),
            ).fetchall()
        return [dict(r) for r in rows]
