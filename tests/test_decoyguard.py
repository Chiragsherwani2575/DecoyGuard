import json
import os
import random
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

from decoyguard.alerts import Notifier
from decoyguard.config import Config, load_config, save_config
from decoyguard.db import Store
from decoyguard.generator import KINDS, deploy
from decoyguard.server import make_server

KEY = "k" * 24


def make_cfg(tmp, **overrides):
    cfg = Config(
        base_url="http://decoy.example.test",
        host="127.0.0.1",
        port=0,
        db_path=os.path.join(tmp, "dg.db"),
        dashboard_key=KEY,
        cooldown_seconds=60,
    )
    for k, v in overrides.items():
        setattr(cfg, k, v)
    cfg.validate()
    return cfg


def http(method, url, headers=None, data=None):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as err:
        return err.code, err.read(), dict(err.headers)


class WebhookCatcher:
    """Tiny local HTTP server that records webhook POST bodies."""

    def __init__(self):
        self.bodies = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                outer.bodies.append(json.loads(self.rfile.read(n)))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *a):
                pass

        self.srv = HTTPServer(("127.0.0.1", 0), H)
        self.url = "http://127.0.0.1:%d/hook" % self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.cfg = make_cfg(self.tmp)
        self.store = Store(self.cfg.db_path)
        self.addCleanup(self.store.close)


class GeneratorTests(Base):
    def test_deploy_creates_files_with_unique_tripwire_tokens(self):
        out = os.path.join(self.tmp, "share")
        created = deploy(self.store, self.cfg, out, rng=random.Random(1))
        self.assertEqual(len(created), len(KINDS))
        self.assertEqual(len({d["token"] for d in created}), len(created))
        for d in created:
            text = open(d["path"], encoding="utf-8").read()
            self.assertIn("%s/t/%s" % (self.cfg.base_url, d["token"]), text)
            self.assertIsNotNone(self.store.get_decoy(d["token"]))

    def test_deploy_never_overwrites_existing_files(self):
        out = os.path.join(self.tmp, "share")
        os.makedirs(out)
        precious = os.path.join(out, "vpn-setup.txt")
        with open(precious, "w") as fh:
            fh.write("real data")
        deploy(self.store, self.cfg, out, kinds=["vpn_notes"], count=3, rng=random.Random(2))
        self.assertEqual(open(precious).read(), "real data")

    def test_unknown_kind_rejected(self):
        with self.assertRaises(ValueError):
            deploy(self.store, self.cfg, self.tmp, kinds=["nope"])

    def test_count_cycles_through_kinds(self):
        out = os.path.join(self.tmp, "share")
        created = deploy(self.store, self.cfg, out, count=4, kinds=["bank_csv", "env_file"])
        self.assertEqual([d["kind"] for d in created], ["bank_csv", "env_file", "bank_csv", "env_file"])


class ServerTests(Base):
    def setUp(self):
        super().setUp()
        self.notifier = Notifier(self.cfg, sync=True)
        self.server = make_server(self.cfg, self.store, self.notifier)
        self.base = "http://127.0.0.1:%d" % self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self._stop)
        self.created = deploy(self.store, self.cfg, os.path.join(self.tmp, "share"))
        self.token = self.created[0]["token"]

    def _stop(self):
        self.server.shutdown()
        self.server.server_close()

    def test_decoy_url_records_alert(self):
        status, _, _ = http("GET", "%s/t/%s/login" % (self.base, self.token), {"User-Agent": "curl/8.0"})
        self.assertEqual(status, 200)
        alerts = self.store.list_alerts()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["token"], self.token)
        self.assertEqual(alerts[0]["user_agent"], "curl/8.0")
        self.assertEqual(alerts[0]["source_ip"], "127.0.0.1")

    def test_pixel_returns_gif_and_alerts(self):
        status, body, headers = http("GET", "%s/t/%s/pixel.gif" % (self.base, self.token))
        self.assertEqual(status, 200)
        self.assertTrue(body.startswith(b"GIF89a"))
        self.assertEqual(headers["Content-Type"], "image/gif")
        self.assertEqual(len(self.store.list_alerts()), 1)

    def test_unknown_token_and_random_paths_do_not_alert(self):
        for path in ("/t/deadbeefdeadbeef", "/", "/admin", "/t/", "/_dg/x"):
            status, _, _ = http("GET", self.base + path)
            self.assertEqual(status, 404, path)
        self.assertEqual(self.store.list_alerts(), [])

    def test_login_attempt_stores_username_but_never_password(self):
        data = urllib.parse.urlencode({"username": "alice", "password": "hunter2-secret"}).encode()
        status, _, _ = http("POST", "%s/t/%s/login" % (self.base, self.token), data=data)
        self.assertEqual(status, 401)
        alert = self.store.list_alerts()[0]
        self.assertIn("alice", alert["detail"])
        dump = json.dumps(self.store.list_alerts())
        self.assertNotIn("hunter2-secret", dump)

    def test_server_does_not_advertise_python(self):
        _, _, headers = http("GET", self.base + "/")
        self.assertNotIn("python", headers.get("Server", "").lower())

    def test_dashboard_requires_key(self):
        self.assertEqual(http("GET", self.base + "/_dg/")[0], 404)
        self.assertEqual(http("GET", self.base + "/_dg/?key=wrong")[0], 404)
        self.assertEqual(http("GET", self.base + "/_dg/api/alerts")[0], 404)
        self.assertEqual(http("GET", self.base + "/_dg/?key=" + KEY)[0], 200)
        status, body, _ = http("GET", self.base + "/_dg/api/alerts", {"Authorization": "Bearer " + KEY})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), [])

    def test_dashboard_escapes_attacker_controlled_fields(self):
        evil = "<script>alert(1)</script>"
        http("GET", "%s/t/%s/x" % (self.base, self.token), {"User-Agent": evil})
        status, body, headers = http("GET", self.base + "/_dg/?key=" + KEY)
        text = body.decode()
        self.assertEqual(status, 200)
        self.assertNotIn(evil, text)
        self.assertIn("&lt;script&gt;", text)
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])

    def test_health_endpoint(self):
        self.assertEqual(http("GET", self.base + "/_dg/health")[0], 200)

    def test_oversized_body_is_capped(self):
        status, _, _ = http("POST", "%s/t/%s/login" % (self.base, self.token), data=b"a=" + b"x" * 100000)
        self.assertEqual(status, 401)
        self.assertEqual(len(self.store.list_alerts()), 1)


class ProxyTrustTests(Base):
    def test_x_forwarded_for_only_used_when_trusted(self):
        for trusted, expected in ((False, "127.0.0.1"), (True, "198.51.100.9")):
            cfg = make_cfg(self.tmp, trust_proxy=trusted, db_path=os.path.join(self.tmp, "p%s.db" % trusted))
            store = Store(cfg.db_path)
            server = make_server(cfg, store, Notifier(cfg, sync=True))
            threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                created = deploy(store, cfg, os.path.join(self.tmp, "d%s" % trusted), kinds=["vpn_notes"])
                url = "http://127.0.0.1:%d/t/%s/" % (server.server_address[1], created[0]["token"])
                http("GET", url, {"X-Forwarded-For": "198.51.100.9, 10.0.0.1"})
                self.assertEqual(store.list_alerts()[0]["source_ip"], expected)
            finally:
                server.shutdown()
                server.server_close()
                store.close()


class NotifierTests(Base):
    def setUp(self):
        super().setUp()
        self.hook = WebhookCatcher()
        self.addCleanup(self.hook.close)
        self.cfg.webhook_url = self.hook.url
        self.notifier = Notifier(self.cfg, sync=True)
        self.decoy = {"label": "vpn-setup.txt", "kind": "vpn_notes", "path": "/srv/share/vpn-setup.txt"}

    def alert(self, ip="203.0.113.5", token="abc"):
        return {"id": 1, "token": token, "ts": "2026-01-01T00:00:00+00:00", "source_ip": ip,
                "user_agent": "x", "method": "GET", "path": "/t/abc", "detail": ""}

    def test_webhook_payload(self):
        self.assertTrue(self.notifier.maybe_notify(self.alert(), self.decoy))
        self.assertEqual(len(self.hook.bodies), 1)
        body = self.hook.bodies[0]
        self.assertIn("vpn-setup.txt", body["text"])
        self.assertIn("203.0.113.5", body["text"])
        self.assertEqual(body["alert"]["source_ip"], "203.0.113.5")

    def test_cooldown_suppresses_repeats_per_ip_and_decoy(self):
        self.assertTrue(self.notifier.maybe_notify(self.alert(), self.decoy))
        self.assertFalse(self.notifier.maybe_notify(self.alert(), self.decoy))
        self.assertTrue(self.notifier.maybe_notify(self.alert(ip="198.51.100.1"), self.decoy))
        self.assertTrue(self.notifier.maybe_notify(self.alert(token="other"), self.decoy))
        self.assertEqual(len(self.hook.bodies), 3)

    def test_failed_webhook_does_not_raise(self):
        self.cfg.webhook_url = "http://127.0.0.1:1/unreachable"
        self.assertTrue(self.notifier.maybe_notify(self.alert(), self.decoy))
        self.assertTrue(self.notifier.errors)

    def test_non_http_webhook_rejected(self):
        self.cfg.webhook_url = "file:///etc/passwd"
        self.notifier.maybe_notify(self.alert(), self.decoy)
        self.assertTrue(any("http(s)" in e for e in self.notifier.errors))

    def test_send_test(self):
        self.assertEqual(self.notifier.send_test(), [])
        self.assertEqual(len(self.hook.bodies), 1)
        self.assertEqual(Notifier(make_cfg(self.tmp)).send_test(),
                         ["no webhook or SMTP settings configured"])


class ConfigTests(unittest.TestCase):
    def test_validation(self):
        with self.assertRaises(ValueError):
            Config(dashboard_key="short").validate()
        with self.assertRaises(ValueError):
            Config(dashboard_key=KEY, base_url="ftp://x").validate()
        with self.assertRaises(ValueError):
            Config(dashboard_key=KEY, port=70000).validate()

    def test_save_load_roundtrip_and_permissions(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        path = os.path.join(tmp, "c.json")
        save_config(Config(dashboard_key=KEY, base_url="https://x.example/"), path)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        cfg = load_config(path)
        self.assertEqual(cfg.base_url, "https://x.example")

    def test_env_overrides_and_unknown_keys(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        path = os.path.join(tmp, "c.json")
        save_config(Config(dashboard_key=KEY), path)
        os.environ["DG_PORT"] = "9999"
        os.environ["DG_TRUST_PROXY"] = "true"
        self.addCleanup(os.environ.pop, "DG_PORT", None)
        self.addCleanup(os.environ.pop, "DG_TRUST_PROXY", None)
        cfg = load_config(path)
        self.assertEqual(cfg.port, 9999)
        self.assertTrue(cfg.trust_proxy)
        with open(path, "w") as fh:
            json.dump({"dashboard_key": KEY, "bogus": 1}, fh)
        with self.assertRaises(ValueError):
            load_config(path)


if __name__ == "__main__":
    unittest.main()
