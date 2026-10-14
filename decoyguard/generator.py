"""Generates realistic-looking bait files, each carrying a unique tripwire URL.

Everything in a decoy is fake: the credentials are random strings that grant
access to nothing. The only "live" part is the callback URL, which points at
the DecoyGuard server and identifies exactly which decoy was touched.
"""
from __future__ import annotations

import os
import random
import secrets
import string
from datetime import datetime
from typing import Callable, Dict, List, Optional, Tuple

from .config import Config
from .db import Store

_UPPER_DIGITS = string.ascii_uppercase + string.digits
_ALNUM = string.ascii_letters + string.digits
_PW_CHARS = _ALNUM + "!@#$%"


def _rand(alphabet: str, n: int, rng: random.Random) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def _pw(rng: random.Random) -> str:
    return _rand(_PW_CHARS, rng.randint(12, 16), rng)


# Each builder takes (url, rng) where url is "<base>/t/<token>" and returns file text.

def _env_file(url: str, rng: random.Random) -> str:
    return (
        "# Backup of production .env - delete after migration\n"
        "APP_ENV=production\n"
        "DB_HOST=erp-db.internal\n"
        "DB_USER=erp_admin\n"
        f"DB_PASSWORD={_pw(rng)}\n"
        f"ADMIN_PANEL_URL={url}/login\n"
        f"SMTP_PASSWORD={_pw(rng)}\n"
        f"SECRET_KEY={_rand(string.hexdigits.lower(), 48, rng)}\n"
    )


def _aws_config(url: str, rng: random.Random) -> str:
    return (
        "[profile backup-admin]\n"
        f"aws_access_key_id = AKIA{_rand(_UPPER_DIGITS, 16, rng)}\n"
        f"aws_secret_access_key = {_rand(_ALNUM + '+/', 40, rng)}\n"
        "region = us-east-1\n"
        f"endpoint_url = {url}\n"
    )


def _passwords_txt(url: str, rng: random.Random) -> str:
    stamp = datetime.now().strftime("%B %Y")
    return (
        f"IT PASSWORDS - updated {stamp}\n\n"
        f"Router admin:        admin / {_pw(rng)}\n"
        f"NAS (backups):       {url}/login   backup_admin / {_pw(rng)}\n"
        f"Staff Wi-Fi:         {_pw(rng)}\n"
        f"Accounting software: finance / {_pw(rng)}\n"
    )


def _vpn_notes(url: str, rng: random.Random) -> str:
    return (
        "VPN setup (new laptops)\n"
        "=======================\n"
        f"Portal:   {url}/vpn\n"
        "Username: vpn_admin\n"
        f"Password: {_pw(rng)}\n"
        "Ask IT before sharing this with contractors.\n"
    )


def _beacon_html(url: str, rng: random.Random) -> str:
    return (
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Payroll summary</title></head><body>\n"
        "<h2>Payroll summary (confidential)</h2>\n"
        "<table border=\"1\" cellpadding=\"4\"><tr><th>Dept</th><th>Headcount</th><th>Monthly total</th></tr>\n"
        "<tr><td>Sales</td><td>6</td><td>$31,400</td></tr>\n"
        "<tr><td>Operations</td><td>9</td><td>$42,150</td></tr></table>\n"
        f"<p><a href=\"{url}/report\">Open full report</a></p>\n"
        f"<img src=\"{url}/pixel.gif\" width=\"1\" height=\"1\" alt=\"\">\n"
        "</body></html>\n"
    )


def _bank_csv(url: str, rng: random.Random) -> str:
    return (
        "system,url,username,password\n"
        f"Business bank,{url}/bank,accounts_admin,{_pw(rng)}\n"
        f"Payroll provider,{url}/payroll,hr_admin,{_pw(rng)}\n"
        f"Supplier portal,{url}/suppliers,purchasing,{_pw(rng)}\n"
    )


# kind -> (builder, plausible filenames)
KINDS: Dict[str, Tuple[Callable[[str, random.Random], str], List[str]]] = {
    "env_file": (_env_file, [".env.backup", "prod.env.old", "app-env-copy.txt"]),
    "aws_config": (_aws_config, ["aws-config.bak", "aws_credentials_old.txt"]),
    "passwords_txt": (_passwords_txt, ["IT-passwords.txt", "passwords_new.txt", "logins-2026.txt"]),
    "vpn_notes": (_vpn_notes, ["vpn-setup.txt", "remote-access-notes.txt"]),
    "beacon_html": (_beacon_html, ["payroll-summary.html", "Q3-salaries.html"]),
    "bank_csv": (_bank_csv, ["bank-logins.csv", "portal-accounts.csv"]),
}


def deploy(
    store: Store,
    cfg: Config,
    directory: str,
    count: Optional[int] = None,
    kinds: Optional[List[str]] = None,
    rng: Optional[random.Random] = None,
) -> List[Dict]:
    """Write decoy files into ``directory`` and register them. Never overwrites files."""
    rng = rng or random.Random()
    kinds = kinds or list(KINDS)
    unknown = [k for k in kinds if k not in KINDS]
    if unknown:
        raise ValueError("unknown decoy kind(s): %s (available: %s)" % (", ".join(unknown), ", ".join(KINDS)))
    count = len(kinds) if count is None else count
    os.makedirs(directory, exist_ok=True)

    created: List[Dict] = []
    for i in range(count):
        kind = kinds[i % len(kinds)]
        builder, names = KINDS[kind]
        token = secrets.token_hex(8)
        content = builder("%s/t/%s" % (cfg.base_url, token), rng)
        path = None
        for name in rng.sample(names, len(names)):
            candidate = os.path.join(directory, name)
            try:
                with open(candidate, "x", encoding="utf-8") as fh:  # "x" = fail if it exists
                    fh.write(content)
                path = candidate
                break
            except FileExistsError:
                continue
        if path is None:
            continue  # every name for this kind already exists here; skip rather than overwrite
        label = os.path.basename(path)
        abs_path = os.path.abspath(path)
        store.add_decoy(token, kind, label, abs_path)
        created.append({"token": token, "kind": kind, "label": label, "path": abs_path})
    return created
