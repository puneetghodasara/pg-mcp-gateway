"""End-to-end tests: the gateway as a subprocess, a fake OAuth + MCP server on localhost."""
import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SRC = os.path.join(os.path.dirname(__file__), "..", "src")
VALID = {"a1", "a2"}  # access tokens the fake server accepts


class Fake(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, code, obj=None, headers=None):
        body = json.dumps(obj).encode() if obj is not None else b""
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        o = f"http://127.0.0.1:{self.server.server_port}"
        if self.path == "/.well-known/oauth-protected-resource/mcp":
            return self.reply(200, {"resource": o + "/mcp", "authorization_servers": [o], "scopes_supported": ["openid"]})
        if self.path == "/.well-known/oauth-authorization-server":
            return self.reply(200, {"issuer": o, "authorization_endpoint": o + "/authorize", "token_endpoint": o + "/token"})
        self.reply(404)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.path == "/token":
            f = {k: v[0] for k, v in urllib.parse.parse_qs(body.decode()).items()}
            if f.get("grant_type") == "authorization_code" and f.get("code") == "good" and f.get("code_verifier"):
                return self.reply(200, {"access_token": "a1", "refresh_token": "r1", "expires_in": 3600})
            if f.get("grant_type") == "refresh_token" and f.get("refresh_token") == "r1":
                return self.reply(200, {"access_token": "a2", "expires_in": 3600})
            return self.reply(400, {"error": "invalid_grant"})
        if self.path == "/mcp":
            if self.headers.get("Authorization", "")[7:] not in VALID:
                return self.reply(401)
            m = json.loads(body)
            if "id" not in m:
                return self.reply(202)
            res = {"initialize": {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}},
                   "tools/list": {"tools": [{"name": "echo", "inputSchema": {"type": "object"}}]},
                   "tools/call": {"content": [{"type": "text", "text": json.dumps(
                       {"args": m["params"].get("arguments"), "agent": self.headers.get("X-Agent")})}]}}
            return self.reply(200, {"jsonrpc": "2.0", "id": m["id"], "result": res[m["method"]]},
                              {"Mcp-Session-Id": "s1"})
        self.reply(404)


class Client:
    def __init__(self, port, state, caps):
        env = dict(os.environ, PYTHONPATH=SRC, PG_MCP_UPSTREAM=f"http://127.0.0.1:{port}/mcp",
                   PG_MCP_CLIENT_ID="cid", PG_MCP_STATE_DIR=state, PG_MCP_NAME="fake",
                   PG_MCP_HEADERS='{"X-Agent": "test"}')
        self.p = subprocess.Popen([sys.executable, "-m", "pg_mcp_gateway"], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env, text=True)
        self.q = queue.Queue()
        threading.Thread(target=lambda: [self.q.put(json.loads(l)) for l in self.p.stdout], daemon=True).start()
        self.n = 0
        self.notes = []
        self.init = self.rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": caps,
                                            "clientInfo": {"name": "t", "version": "0"}})

    def send(self, m):
        self.p.stdin.write(json.dumps(m) + "\n")
        self.p.stdin.flush()

    def rpc(self, method, params, on_request=None):
        self.n += 1
        self.send({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params})
        while True:
            m = self.q.get(timeout=20)
            if m.get("id") == self.n and "method" not in m:
                return m["result"]
            if "method" in m and "id" in m:
                self.send({"jsonrpc": "2.0", "id": m["id"], "result": on_request(m["params"])})
            elif "method" in m:
                self.notes.append(m["method"])

    def wait_notification(self, timeout=15):
        if "notifications/tools/list_changed" in self.notes:
            self.notes.clear()
            return True
        end = time.time() + timeout
        while time.time() < end:
            try:
                m = self.q.get(timeout=1)
            except queue.Empty:
                continue
            if m.get("method") == "notifications/tools/list_changed":
                return True
        return False

    def tools(self):
        return [t["name"] for t in self.rpc("tools/list", {})["tools"]]

    def close(self):
        self.p.kill()
        self.p.wait()


def callback(url, code="good"):
    state = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)["state"][0]
    return f"http://localhost:8080/callback?code={code}&state={state}"


class GatewayTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), Fake)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.port = cls.srv.server_port

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        self.state = tempfile.mkdtemp()
        self.clients = []

    def tearDown(self):
        for c in self.clients:
            c.close()

    def client(self, caps=None):
        c = Client(self.port, self.state, {"elicitation": {"form": {}, "url": {}}} if caps is None else caps)
        self.clients.append(c)
        return c

    def test_sign_in_with_cards_then_call(self):
        c = self.client()
        self.assertIn("without asking first", c.init["instructions"])
        self.assertEqual(c.tools(), ["sign_in"])
        seen = {}

        def answer(p):
            if p["mode"] == "url":
                seen["url"] = p["url"]
                q = urllib.parse.parse_qs(urllib.parse.urlparse(p["url"]).query)
                self.assertEqual(q["code_challenge_method"], ["S256"])
                self.assertEqual(q["client_id"], ["cid"])
                return {"action": "accept"}
            return {"action": "accept", "content": {"address": callback(seen["url"])}}

        r = c.rpc("tools/call", {"name": "sign_in", "arguments": {}}, answer)
        self.assertFalse(r["isError"], r)
        self.assertTrue(c.wait_notification())
        self.assertEqual(c.tools(), ["echo"])
        r = c.rpc("tools/call", {"name": "echo", "arguments": {"x": 1}})
        self.assertEqual(json.loads(r["content"][0]["text"]), {"args": {"x": 1}, "agent": "test"})
        files = os.listdir(self.state)
        self.assertEqual(len(files), 1)
        self.assertEqual(os.stat(os.path.join(self.state, files[0])).st_mode & 0o777, 0o600)

    def test_decline(self):
        c = self.client()
        r = c.rpc("tools/call", {"name": "sign_in", "arguments": {}}, lambda p: {"action": "decline"})
        self.assertIn("declined", r["content"][0]["text"])
        self.assertEqual(c.tools(), ["sign_in"])

    def test_fallback_without_cards(self):
        c = self.client(caps={})
        r = c.rpc("tools/call", {"name": "sign_in", "arguments": {}})
        link = next(w for w in r["content"][0]["text"].split() if "/authorize?" in w)
        bad = c.rpc("tools/call", {"name": "sign_in", "arguments": {
            "address": "http://localhost:8080/callback?code=good&state=nope"}})
        self.assertTrue(bad["isError"])
        ok = c.rpc("tools/call", {"name": "sign_in", "arguments": {"address": callback(link)}})
        self.assertFalse(ok["isError"], ok)
        self.assertEqual(c.tools(), ["echo"])

    def test_shared_sign_in_lights_up_other_gateway(self):
        waiting = self.client(caps={})
        self.assertEqual(waiting.tools(), ["sign_in"])
        other = self.client(caps={})
        r = other.rpc("tools/call", {"name": "sign_in", "arguments": {}})
        link = next(w for w in r["content"][0]["text"].split() if "/authorize?" in w)
        other.rpc("tools/call", {"name": "sign_in", "arguments": {"address": callback(link)}})
        self.assertTrue(waiting.wait_notification())
        self.assertEqual(waiting.tools(), ["echo"])

    def test_refresh_and_expiry(self):
        c = self.client(caps={})
        r = c.rpc("tools/call", {"name": "sign_in", "arguments": {}})
        link = next(w for w in r["content"][0]["text"].split() if "/authorize?" in w)
        c.rpc("tools/call", {"name": "sign_in", "arguments": {"address": callback(link)}})
        VALID.discard("a1")  # the access token expires early: the gateway refreshes to a2
        try:
            r = c.rpc("tools/call", {"name": "echo", "arguments": {}})
            self.assertFalse(r.get("isError"), r)
            VALID.discard("a2")  # now nothing works and refresh gives a2 again: sign-in expired
            r = c.rpc("tools/call", {"name": "echo", "arguments": {}})
            self.assertTrue(r["isError"])
            self.assertIn("expired", r["content"][0]["text"])
        finally:
            VALID.update({"a1", "a2"})


if __name__ == "__main__":
    unittest.main()
