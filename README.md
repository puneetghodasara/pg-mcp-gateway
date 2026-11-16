# pg-mcp-gateway

A stdio MCP server that signs in to a remote OAuth-protected MCP server from inside the session and then forwards its tools. It's built for Claude Code cloud sessions, where Claude Code's own MCP OAuth sign-in can't run. It works anywhere Claude Code does.

- **No sign-in yet:** the only tool is `sign_in`. Calling it shows an **Open link** card (MCP URL elicitation), then a form for the address the browser ends on. The gateway does the PKCE code exchange itself, and the verifier never leaves the process. Then it announces the server's real tools, with no restart.
- **One sign-in per authorization server and client:** it's saved in `~/.local/state/pg-mcp/` (mode 600). Every gateway on the machine that uses the same pair picks it up within seconds.
- **Refresh:** access tokens are refreshed from the saved refresh token. When that's rejected, `sign_in` comes back.
- **Fallback:** clients without URL elicitation get the link in the tool result, then finish with `sign_in(address=…)`.
- **Startup instructions:** they tell the agent to call `sign_in` straight away when it's the only tool.
- **Standard library only:** Python 3.11+. Tools are forwarded; resources, prompts and requests from the server back to the client aren't.

## Use

One entry per remote server in `.mcp.json`, pinned to a commit:

```json
{
  "mcpServers": {
    "orders": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/puneetghodasara/pg-mcp-gateway@<commit>", "pg-mcp-gateway"],
      "env": {
        "PG_MCP_UPSTREAM": "https://api.example.com/orders/mcp",
        "PG_MCP_CLIENT_ID": "<public OAuth client id>",
        "PG_MCP_HEADERS": "{\"X-Agent\": \"grocery\"}"
      }
    }
  }
}
```

| Variable | Meaning |
|---|---|
| `PG_MCP_UPSTREAM` | Remote MCP server URL (required) |
| `PG_MCP_CLIENT_ID` | OAuth client ID, public client (required) |
| `PG_MCP_HEADERS` | Extra request headers as a JSON object |
| `PG_MCP_REDIRECT` | Registered redirect URI, default `http://localhost:8080/callback` |
| `PG_MCP_SCOPE` | Scopes to request, default the server's `scopes_supported` |
| `PG_MCP_NAME` | Name used in messages, default the URL's first path segment |
| `PG_MCP_STATE_DIR` | Where sign-ins are saved, default `~/.local/state/pg-mcp` |

**Requirements:**
- The remote server must publish RFC 9728 protected-resource metadata, and its authorization server must publish RFC 8414 metadata.
- The authorization server must support PKCE (S256) and public clients.
- The redirect URI must be registered with the authorization server.

A Claude Code cloud session can fetch this repository because it's public. `uv` is preinstalled there.

## Test

```sh
python3 -m unittest -v tests/test_gateway.py
```

The tests run the gateway against a local fake OAuth + MCP server.
