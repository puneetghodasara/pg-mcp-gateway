"""MCP sign-in gateway: OAuth for remote MCP servers, done inside the session.

Claude Code starts this as a stdio MCP server, one process per remote server.
It forwards tool calls to the real HTTP server (PG_MCP_UPSTREAM) with an access
token, so the session never runs Claude Code's own OAuth flow. That matters in
Claude Code cloud sessions, where that flow can't run.

Not signed in: the only tool is `sign_in`. Calling it shows the user a link
(an MCP URL elicitation, which claude.ai/code renders as an "Open link" card),
then a form asking for the address the browser ended on. The gateway trades
that code for tokens itself (PKCE; the verifier never leaves this process),
saves them and announces the server's real tools, with no restart. Clients
without URL elicitation get the link in the tool result and finish with
`sign_in(address=...)`.

The sign-in is saved under ~/.local/state/pg-mcp/ (mode 600), one file per
authorization server and client, so every gateway on the machine that shares
them signs in together.

Configuration (environment):
  PG_MCP_UPSTREAM   the remote MCP server URL (required)
  PG_MCP_CLIENT_ID  the OAuth client ID registered for it (required; public client)
  PG_MCP_HEADERS    extra request headers as a JSON object, e.g. {"X-Agent": "grocery"}
  PG_MCP_REDIRECT   registered redirect URI (default http://localhost:8080/callback)
  PG_MCP_SCOPE      scopes to request (default: the server's scopes_supported)
  PG_MCP_NAME       name used in messages (default: first path segment of the URL)
  PG_MCP_STATE_DIR  where sign-ins are saved (default ~/.local/state/pg-mcp)

Standard library only. Logs go to stderr and never include tokens or codes.
"""
import base64
import hashlib
import json
import os
import secrets
import signal
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

PROTOCOL = "2025-06-18"


def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def http(url, data=None, headers=None, timeout=30):
    """Returns (status, headers, body); never raises on HTTP errors."""
    req = urllib.request.Request(url, data, headers or {}, method="POST" if data is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()
    except (urllib.error.URLError, OSError) as e:  # network down, DNS, timeout
        return 0, {}, str(e).encode()


class Config:
    def __init__(self, env=os.environ):
        self.upstream = env["PG_MCP_UPSTREAM"]
        self.client_id = env["PG_MCP_CLIENT_ID"]
        self.headers = json.loads(env.get("PG_MCP_HEADERS") or "{}")
        self.redirect = env.get("PG_MCP_REDIRECT", "http://localhost:8080/callback")
        self.scope = env.get("PG_MCP_SCOPE")
        path = urllib.parse.urlparse(self.upstream).path.strip("/")
        self.name = env.get("PG_MCP_NAME") or (path.split("/")[0] if path else "server")
        self.state_dir = os.path.expanduser(env.get("PG_MCP_STATE_DIR", "~/.local/state/pg-mcp"))


class Gateway:
    def __init__(self, cfg):
        self.cfg = cfg
        self.auth = Auth(cfg, self.log)
        self.up = Upstream(cfg, self.auth, self.log)
        self.out_lock = threading.Lock()
        self.pending = {}
        self.ids = iter(range(1, 1 << 62))
        self.client_caps = {}
        self.signed_in = False
        self.mtime = None

    def log(self, *a):
        print(f"pg-mcp-gateway[{self.cfg.name}]:", *a, file=sys.stderr, flush=True)

    # --- talking to Claude Code ---

    def write(self, msg):
        with self.out_lock:
            sys.stdout.write(json.dumps(msg) + "\n")
            sys.stdout.flush()

    def request(self, method, params):
        rid = f"gw-{next(self.ids)}"
        ev = threading.Event()
        self.pending[rid] = [ev, None]
        self.write({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        ev.wait()
        resp = self.pending.pop(rid)[1]
        if "error" in resp:
            raise RuntimeError(resp["error"].get("message", f"{method} failed"))
        return resp.get("result", {})

    def tools_changed(self):
        self.write({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})

    def try_connect(self):
        try:
            self.up.connect()
            self.signed_in = True
        except AuthNeeded:
            self.signed_in = False
        except Exception as e:
            self.log("connect failed:", e)
            self.signed_in = False
        return self.signed_in

    def watch(self):
        """Lights the tools up when another gateway saves the shared sign-in."""
        while True:
            time.sleep(3)
            try:
                m = os.stat(self.auth.token_file()).st_mtime
            except (OSError, RuntimeError):
                m = None
            if m != self.mtime:
                self.mtime = m
                if m and not self.signed_in and self.try_connect():
                    self.tools_changed()

    # --- MCP handlers ---

    def instructions(self):
        n = self.cfg.name
        return (f"If `sign_in` is the only {n} tool, {n} isn't signed in. Call `sign_in` straight away, "
                f"without asking first, even on the first message and before answering: the user signs in "
                f"through the cards it shows. Servers that share the sign-in light up within a few seconds, "
                f"so call `sign_in` on one of them only. If the user declines or it fails, say so in one "
                f"line, carry on with what doesn't need {n}, and don't answer from guesses about what {n} "
                f"holds. When a {n} tool says the sign-in has expired, call `sign_in` again.")

    def on_initialize(self, p):
        self.client_caps = p.get("capabilities", {})
        self.log("client elicitation capability:", json.dumps(self.client_caps.get("elicitation")))
        return {"protocolVersion": p.get("protocolVersion", PROTOCOL),
                "capabilities": {"tools": {"listChanged": True}},
                "serverInfo": {"name": f"pg-mcp-gateway ({self.cfg.name})", "version": "0.1.0"},
                "instructions": self.instructions()}

    def sign_in_tool(self):
        return {
            "name": "sign_in",
            "description": (f"Sign in to {self.cfg.name}. Only listed while not signed in. Call it with no "
                            "arguments: the user gets a link card and then a box for the address their browser "
                            "ends on. If the result instead contains a link, send it to the user exactly as "
                            "given, and call this again with `address` set to the address they paste back."),
            "inputSchema": {"type": "object", "properties": {"address": {
                "type": "string", "description": "The callback address the user pasted, with code and state"}}},
        }

    def on_tools_list(self, p):
        if not self.signed_in:
            self.try_connect()
        return {"tools": self.up.tools if self.signed_in else [self.sign_in_tool()]}

    def on_tools_call(self, p):
        if p.get("name") == "sign_in":
            return self.sign_in(p.get("arguments") or {})
        if not self.signed_in:
            return text(f"{self.cfg.name} isn't signed in. Call sign_in first.", error=True)
        try:
            r = self.up.call("tools/call", p)
        except AuthNeeded:
            self.signed_in = False
            self.up.tools = None
            self.tools_changed()
            return text(f"The {self.cfg.name} sign-in has expired. Call sign_in to sign in again.", error=True)
        if "error" in r:
            raise RuntimeError(r["error"].get("message", "upstream error"))
        return r["result"]

    def done(self):
        if not self.try_connect():
            return text("Signed in, but the server still refused the token.", error=True)
        self.tools_changed()
        return text(f"Signed in to {self.cfg.name}: {len(self.up.tools)} tools are now available. "
                    "Other servers that share this sign-in light up within a few seconds.")

    def sign_in(self, args):
        n = self.cfg.name
        if args.get("address"):
            self.auth.finish(args["address"])
            return self.done()
        url = self.auth.start()
        el = self.client_caps.get("elicitation")
        if isinstance(el, dict) and "url" in el:
            r = self.request("elicitation/create", {
                "mode": "url", "elicitationId": secrets.token_hex(8), "url": url,
                "message": f"Sign in to {n}. Your browser then ends on a page that doesn't load; "
                           "copy its whole address, then continue here."})
            if r.get("action") != "accept":
                return text(f"The user declined the {n} sign-in.")
            r = self.request("elicitation/create", {
                "mode": "form",
                "message": f"Paste the whole address your browser ended on (it starts with {self.cfg.redirect}?code=).",
                "requestedSchema": {"type": "object", "required": ["address"], "properties": {
                    "address": {"type": "string", "title": "Address"}}}})
            if r.get("action") != "accept":
                return text(f"The user didn't finish the {n} sign-in.")
            self.auth.finish(r.get("content", {}).get("address", ""))
            return self.done()
        return text(f"Send the user this link, exactly as is, to sign in to {n}:\n{url}\n\n"
                    f"Their browser ends on a {self.cfg.redirect}?code=... page that doesn't load. "
                    "When they paste that address, call sign_in again with it as `address`.")

    def handle(self, msg):
        method, mid = msg.get("method"), msg.get("id")
        handlers = {"initialize": self.on_initialize, "tools/list": self.on_tools_list,
                    "tools/call": self.on_tools_call, "ping": lambda p: {}}
        try:
            if method not in handlers:
                self.write({"jsonrpc": "2.0", "id": mid,
                            "error": {"code": -32601, "message": f"unknown method {method}"}})
                return
            self.write({"jsonrpc": "2.0", "id": mid, "result": handlers[method](msg.get("params") or {})})
        except Exception as e:
            self.log("error in", method, type(e).__name__, e)
            if method == "tools/call":
                self.write({"jsonrpc": "2.0", "id": mid, "result": text(str(e), error=True)})
            else:
                self.write({"jsonrpc": "2.0", "id": mid, "error": {"code": -32603, "message": str(e)}})

    def run(self, stdin=sys.stdin):
        threading.Thread(target=self.watch, daemon=True).start()
        for line in stdin:
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if "method" not in msg:  # a response to one of our requests
                slot = self.pending.get(msg.get("id"))
                if slot:
                    slot[1] = msg
                    slot[0].set()
            elif "id" in msg:
                threading.Thread(target=self.handle, args=(msg,), daemon=True).start()


def text(t, error=False):
    return {"content": [{"type": "text", "text": t}], "isError": error}


class Auth:
    """OAuth 2.1 authorization code + PKCE against the server's advertised authorization server."""

    def __init__(self, cfg, log):
        self.cfg = cfg
        self.log = log
        self.lock = threading.Lock()
        self.meta = None
        self.scopes = None
        self.pending = None  # (state, verifier)

    def discover(self):
        if self.meta:
            return self.meta
        u = urllib.parse.urlparse(self.cfg.upstream)
        origin = f"{u.scheme}://{u.netloc}"
        issuer = origin
        st, _, body = http(f"{origin}/.well-known/oauth-protected-resource{u.path}", timeout=10)
        if st == 200:
            prm = json.loads(body)
            issuer = prm["authorization_servers"][0]
            self.scopes = prm.get("scopes_supported")
        st, _, body = http(issuer.rstrip("/") + "/.well-known/oauth-authorization-server", timeout=10)
        if st != 200:
            raise RuntimeError(f"sign-in discovery failed: HTTP {st}")
        self.meta = json.loads(body)
        self.scopes = self.scopes or self.meta.get("scopes_supported")
        return self.meta

    def token_file(self):
        key = hashlib.sha256(f"{self.discover()['token_endpoint']} {self.cfg.client_id}".encode()).hexdigest()[:16]
        return os.path.join(self.cfg.state_dir, f"signin-{key}.json")

    def load(self):
        try:
            with open(self.token_file()) as f:
                return json.load(f)
        except (OSError, ValueError, RuntimeError):
            return None

    def save(self, tok):
        os.makedirs(self.cfg.state_dir, mode=0o700, exist_ok=True)
        path = self.token_file()
        tmp = f"{path}.{os.getpid()}"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(tok, f)
        os.replace(tmp, path)

    def token_request(self, form):
        st, _, body = http(self.discover()["token_endpoint"], urllib.parse.urlencode(form).encode(),
                           {"Content-Type": "application/x-www-form-urlencoded"}, timeout=15)
        if st != 200:
            try:
                err = json.loads(body).get("error", "")
            except ValueError:
                err = ""
            raise RuntimeError(f"token endpoint: HTTP {st} {err}".strip())
        return json.loads(body)

    def access_token(self, force_refresh=False):
        """A valid access token, refreshed if needed; None when not signed in."""
        with self.lock:
            tok = self.load()
            if not tok or not tok.get("refresh_token"):
                return None
            if not force_refresh and tok.get("expires_at", 0) > time.time() + 120:
                return tok["access_token"]
            try:
                new = self.token_request({"grant_type": "refresh_token", "client_id": self.cfg.client_id,
                                          "refresh_token": tok["refresh_token"]})
            except RuntimeError as e:
                self.log("refresh failed:", e)
                if "invalid_grant" in str(e):  # expired or revoked: forget it
                    try:
                        os.remove(self.token_file())
                    except OSError:
                        pass
                return None
            tok.update(access_token=new["access_token"],
                       expires_at=time.time() + int(new.get("expires_in", 3600)))
            if new.get("refresh_token"):  # rotation
                tok["refresh_token"] = new["refresh_token"]
            self.save(tok)
            return tok["access_token"]

    def start(self):
        meta = self.discover()
        verifier = b64url(secrets.token_bytes(32))
        state = b64url(secrets.token_bytes(16))
        self.pending = (state, verifier)
        q = {"response_type": "code", "client_id": self.cfg.client_id, "redirect_uri": self.cfg.redirect,
             "state": state, "code_challenge": b64url(hashlib.sha256(verifier.encode()).digest()),
             "code_challenge_method": "S256"}
        scope = self.cfg.scope or " ".join(self.scopes or [])
        if scope:
            q["scope"] = scope
        return meta["authorization_endpoint"] + "?" + urllib.parse.urlencode(q)

    def finish(self, address):
        if not self.pending:
            raise RuntimeError("no sign-in in progress; call sign_in first")
        state, verifier = self.pending
        q = urllib.parse.parse_qs(urllib.parse.urlparse(address.strip()).query)
        if "error" in q:
            raise RuntimeError("sign-in was refused: " + q["error"][0])
        if q.get("state", [""])[0] != state:
            raise RuntimeError("that address belongs to a different sign-in; open the newest link")
        code = q.get("code", [""])[0]
        if not code:
            raise RuntimeError("no code in that address")
        new = self.token_request({"grant_type": "authorization_code", "client_id": self.cfg.client_id,
                                  "code": code, "redirect_uri": self.cfg.redirect, "code_verifier": verifier})
        self.pending = None
        with self.lock:
            self.save({"refresh_token": new.get("refresh_token", ""), "access_token": new["access_token"],
                       "expires_at": time.time() + int(new.get("expires_in", 3600))})


class AuthNeeded(Exception):
    pass


class Upstream:
    """MCP client for the remote server over streamable HTTP (tools only)."""

    def __init__(self, cfg, auth, log):
        self.cfg = cfg
        self.auth = auth
        self.log = log
        self.session = None
        self.tools = None
        self.ids = iter(range(1, 1 << 62))
        self.lock = threading.RLock()

    def _post(self, msg, token):
        h = {**self.cfg.headers, "Content-Type": "application/json",
             "Accept": "application/json, text/event-stream",
             "Authorization": "Bearer " + token, "MCP-Protocol-Version": PROTOCOL}
        if self.session:
            h["Mcp-Session-Id"] = self.session
        st, hdrs, body = http(self.cfg.upstream, json.dumps(msg).encode(), h, timeout=120)
        if st in (401, 403):
            raise AuthNeeded()
        if st == 404 and self.session:
            self.session = None
            raise ConnectionResetError("upstream session expired")
        if st == 0 or st >= 400:
            raise RuntimeError(f"{self.cfg.name}: " + (f"HTTP {st}" if st else "unreachable"))
        if hdrs.get("Mcp-Session-Id"):
            self.session = hdrs["Mcp-Session-Id"]
        if "id" not in msg or not body:
            return None
        if "text/event-stream" in (hdrs.get("Content-Type") or ""):
            data = []
            for line in body.decode().splitlines() + [""]:
                if line.startswith("data:"):
                    data.append(line[5:].lstrip())
                elif not line and data:
                    m = json.loads("\n".join(data))
                    data = []
                    if m.get("id") == msg["id"]:
                        return m
            raise RuntimeError(f"{self.cfg.name}: no response in event stream")
        return json.loads(body)

    def _send(self, method, params=None, notify=False):
        msg = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        if not notify:
            msg["id"] = next(self.ids)
        for attempt in (0, 1):
            token = self.auth.access_token(force_refresh=attempt == 1)
            if not token:
                raise AuthNeeded()
            try:
                return self._post(msg, token)
            except AuthNeeded:
                if attempt:
                    raise

    def connect(self):
        with self.lock:
            self._connect()

    def _connect(self):
        self.session = None
        self._send("initialize", {"protocolVersion": PROTOCOL, "capabilities": {},
                                  "clientInfo": {"name": "pg-mcp-gateway", "version": "0.1.0"}})
        self._send("notifications/initialized", notify=True)
        tools, cursor = [], None
        while True:
            r = self._send("tools/list", {"cursor": cursor} if cursor else {})
            res = r.get("result", {})
            tools += res.get("tools", [])
            cursor = res.get("nextCursor")
            if not cursor:
                break
        self.tools = tools
        self.log(f"connected, {len(tools)} tools")

    def call(self, method, params):
        with self.lock:
            for attempt in (0, 1):
                try:
                    if self.tools is None:
                        self._connect()
                    return self._send(method, params)
                except ConnectionResetError:
                    if attempt:
                        raise
                    self.tools = None


def main():
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: os._exit(0))
    Gateway(Config()).run()


if __name__ == "__main__":
    main()
