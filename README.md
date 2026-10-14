# DecoyGuard

Drop-in **deception tripwires** for small businesses. DecoyGuard plants fake
"juicy" files (password lists, `.env` backups, VPN notes, payroll sheets) on your
file shares and laptops. Each one carries a unique callback URL. Real employees
never touch them, so **any hit is a high-confidence intrusion alert** with a
very low false-positive rate. No agents, no dependencies, one small server.

```
 attacker finds  passwords.txt ──► tries the "NAS login" URL inside
                                          │
                                          ▼
                              DecoyGuard tripwire server
                          records IP / user-agent / which decoy
                                          │
                         ┌────────────────┴───────────────┐
                         ▼                                ▼
                Slack / Teams / email alert        dashboard + JSON API
```

Pure Python standard library (3.9+). Nothing to install except the package itself.

## Quick start

```bash
pip install .                      # or: python -m decoyguard ...

# 1. Create a config. Use the public address attackers' machines could reach.
decoyguard init --base-url https://decoy.yourcompany.com --webhook https://hooks.slack.com/services/XXX

# 2. Run the tripwire server (put it behind HTTPS, see "Deployment").
decoyguard serve

# 3. Plant decoys wherever an intruder would look.
decoyguard deploy /srv/shares/finance --count 3
decoyguard deploy ~/Documents

# 4. Check that alerts reach you.
decoyguard test-alert
```

Then view `decoyguard alerts`, `decoyguard decoys`, or open the dashboard URL
printed by `init`/`serve`.

## What gets planted

| Kind            | Looks like                    | Fires when the intruder...                        |
|-----------------|-------------------------------|---------------------------------------------------|
| `passwords_txt` | IT password list              | visits the "NAS login" URL                        |
| `env_file`      | `.env.backup` with DB + admin URL | visits the admin panel URL                    |
| `aws_config`    | AWS profile with `endpoint_url` | runs the AWS CLI with the stolen profile         |
| `vpn_notes`     | VPN setup notes               | visits the "VPN portal"                           |
| `bank_csv`      | exported portal logins        | visits any listed portal URL                      |
| `beacon_html`   | payroll summary page          | **opens the file in a browser** (tracking pixel)  |

All credentials in decoys are random strings that grant access to nothing.
Decoy URLs lead to a fake login page that records the attempted **username only**.
Passwords typed by the intruder are never stored.

## Configuration

`decoyguard.json` (created by `init`, mode 0600) or `DG_<NAME>` environment variables.

| Setting            | Meaning                                                              |
|--------------------|----------------------------------------------------------------------|
| `base_url`         | Public URL embedded in decoys                                        |
| `host` / `port`    | Listen address (default `0.0.0.0:8080`)                              |
| `dashboard_key`    | Secret for `/_dg/?key=...` and `Authorization: Bearer ...` (16+ chars) |
| `webhook_url`      | Slack/Teams/Discord-style incoming webhook                           |
| `smtp_*`           | Optional email alerts (`smtp_host`, `smtp_port`, `smtp_user`, `smtp_password`, `smtp_from`, `smtp_to`) |
| `cooldown_seconds` | Max one notification per (decoy, source IP) per window (default 60)  |
| `trust_proxy`      | Read client IP from `X-Forwarded-For` (only behind your own proxy)   |

## Deployment

```bash
docker build -t decoyguard .
docker run --rm -v dg-data:/data decoyguard init --base-url https://decoy.example.com
docker run -d --name decoyguard -v dg-data:/data -p 8080:8080 decoyguard
```

- Put it behind a TLS-terminating reverse proxy (Caddy/nginx) and set `trust_proxy`.
- Use a hostname that looks internal-ish but is yours (e.g. `files-backup.yourcompany.com`).
- Keep the dashboard key secret; the dashboard returns 404 without it.
- Run `deploy` on the machines/folders you want to protect; it never overwrites existing files.

## Security design

- Dashboard and API are key-protected (constant-time compare) and return 404 otherwise.
- Everything stored from a request (IP, User-Agent, path) is attacker-controlled: it is
  length-capped, HTML-escaped in the dashboard, and the dashboard sends a strict CSP.
- Request bodies are capped at 4 KB; passwords are never persisted.
- Alert cooldown prevents a scanner from flooding your Slack.
- The server does not advertise Python; unknown paths return a generic nginx-style 404.

## Honest limitations (read before relying on it)

- A decoy fires only when the intruder **uses a URL inside it** (or opens the HTML beacon).
  Simply copying a file off a share does **not** alert. Detecting file reads needs OS-level
  auditing (Windows SACLs, Linux `auditd`/`inotify`): a planned extension.
- Attackers who spot the pattern (e.g. a callback host that isn't your internal domain) may avoid it.
  Use plausible hostnames and a mix of decoy kinds.
- Pixel beacons can be blocked by offline viewers or mail/browser privacy settings.
- Secret scanners (GitHub, trufflehog) may flag the AKIA-style fake keys if committed to a repo.
- This is a detection layer. It does not replace patching, MFA, or backups.
- Plant decoys only on systems you own or administer.

## Roadmap

- File-access monitoring agent (auditd/SACL/inotify) to alert on reads without a network hit
- Canary tokens for DNS, Word/PDF documents, and database rows
- Slack-native alert actions (acknowledge, isolate host)
- Decoy rotation and a "health check" that verifies decoys are still in place
- SQLite → Postgres option and multi-tenant mode for MSPs

## Development

```bash
python -m unittest discover -s tests -v
```

## License

MIT
