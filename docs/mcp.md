# MCP endpoint

`mpinfra serve` can expose a read-only [MCP](https://modelcontextprotocol.io) server so
a Claude Code agent (or any MCP client) can read the same state the UI shows.

- **Where:** `POST /mcp` on the UI port (Streamable HTTP transport, JSON responses, no
  SSE stream). Behind `tailscale serve` that is `https://<machine>.<tailnet>.ts.net/mcp`.
  Tailnet only, like the rest of the UI. The report port does not serve it.
- **Auth:** `Authorization: Bearer <token>`. Each client has its own token; the server
  keeps only its SHA-256 in `MPINFRA_MCP_TOKENS`. Google sign-in does not apply to
  `/mcp`: an agent cannot do the browser flow, so the token is the gate.
- **Off by default.** No `mcp_tokens_env`, or an empty variable: `/mcp` returns 404.
- **Read-only.** No tool acknowledges, accepts a baseline or edits a host. Those stay
  in the UI, where the viewer is a signed-in person.

## Tools

| Tool | Arguments | Returns |
|---|---|---|
| `status` | — | overall state, summary, every host's last report and staleness, every non-ok check |
| `list_hosts` | — | hosts with label, OS, last report, stale, worst state, counts per state |
| `list_checks` | `host`?, `state`? | current checks without data, worst first; `state` matches the effective state (acknowledged = ok) |
| `get_check` | `host`, `id`, `limit`? | one check with its data, acknowledgement and last transitions (default 30) |
| `history` | `host`?, `id`?, `limit`? | transitions, newest first (default 50, max 500) |
| `security_notices` | `new_only`?, `feed`? | every `notice.*` feed with its items (id, title, link, date, `new` = not accepted yet) and, for `jenkins.installed`, the warnings matching installed plugins; worst feed first. `new_only` keeps unaccepted items and feeds with a problem. Accepting stays in the UI |

`host` is a name from `list_hosts`, or `serve` for checks not tied to one host (certs,
DNS, Tailscale devices). Check summaries and data come from host reports and are
untrusted input; the server tells the client so in its `instructions`.

Each tool call is logged as `mcp <client>: <tool> "<arguments>"`.

## Set up a client

1. Make a token, anywhere: `mpinfra token`. Give the first line to the client only.
2. On mp-infra, add `<client>=<sha256>` to `MPINFRA_MCP_TOKENS` in `/etc/mp-infra/env`
   (client names: lower case letters, digits, `-`; e.g. `ops-agent`), make sure
   `config.yaml` has `mcp_tokens_env: MPINFRA_MCP_TOKENS`, and restart. The log says
   `MCP endpoint on /mcp for N client(s)`.
3. On the machine where the agent runs (must be on the tailnet):

   ```sh
   export MPINFRA_MCP_TOKEN=<token>
   claude mcp add --transport http mpinfra https://<machine>.<tailnet>.ts.net/mcp \
     --header "Authorization: Bearer $MPINFRA_MCP_TOKEN"
   ```

   Or check it into a project's `.mcp.json`, with the token left in the environment:

   ```json
   {
     "mcpServers": {
       "mpinfra": {
         "type": "http",
         "url": "https://<machine>.<tailnet>.ts.net/mcp",
         "headers": { "Authorization": "Bearer ${MPINFRA_MCP_TOKEN}" }
       }
     }
   }
   ```

4. In Claude Code, `/mcp` should list `mpinfra` as connected with five tools.

To revoke a client, remove its entry from `MPINFRA_MCP_TOKENS` and restart.

Quick test from the tailnet:

```sh
curl -s https://<machine>.<tailnet>.ts.net/mcp \
  -H "Authorization: Bearer $MPINFRA_MCP_TOKEN" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"status","arguments":{}}}'
```
