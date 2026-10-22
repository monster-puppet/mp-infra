# mp-infra

Monster Puppet's infrastructure watch. One Go binary that shows the state of every
server on one page and alerts when something turns red.

It exists because the failures that hurt us were silent ones. The P4 checkpoints had
been failing for six months before anyone noticed. The Windows build agent can lock us
out for good if Tailscale ever drops off it.

**Status:** phases 0–3 of [`docs/spec.md`](docs/spec.md) are built and tested in CI.
Not yet deployed. Collectors that parse host output still need fixtures captured on
the real hosts (`internal/report/testdata/README.md`).

## How it works

```
 monster-p4 ─┐
 jenkins ────┼─ mpinfra report ──(tailnet, per-host token)──► mpinfra serve ──► web UI (tailnet only)
 jenkins-win ┘   (cron / scheduled task, read-only)             │                └► Slack / email alerts
                                                                └─ probes: ports, certs, Tailscale API, Jenkins API
```

- **Hosts report on themselves.** The server never holds SSH keys to anything.
- **Tailnet only.** The UI and the report endpoint listen on the Tailscale interface.
  Viewers are identified by their Tailscale identity, so there are no passwords.
- **Runs 24/7** on a server, not on anyone's PC, so the alerts work when we are asleep.

## Build

Requires Go 1.23+. No Node, no frontend build step.

```sh
make build          # -> bin/mpinfra (bin/mpinfra.exe on Windows)
make check          # vet + test; run before saying you are done
make dist           # cross-compile linux/amd64 + windows/amd64 into dist/
make serve          # UI on 127.0.0.1:8098, reports on :8099, db in data/
bin/mpinfra token   # new report token + the hash for MPINFRA_REPORT_TOKENS
```

On Windows without `make`:

```sh
go build -o bin/mpinfra.exe ./cmd/mpinfra
./bin/mpinfra.exe serve -config config.example.yaml -addr 127.0.0.1:8098
```

Step-by-step for getting hosts to report: [`docs/setup.md`](docs/setup.md).

Deployment (systemd unit, Windows scheduled task, Tailscale ACL) is in
[`docs/deploy.md`](docs/deploy.md).

Read-only MCP endpoint for Claude Code and other agents: [`docs/mcp.md`](docs/mcp.md).

## Building with Claude Code in the cloud

The repo is set up for Claude Code on the web (claude.ai/code). `CLAUDE.md` pulls in
`AGENTS.md` and adds the cloud rules. A SessionStart hook in `.claude/settings.json`
fetches Go modules, and GitHub Actions runs `make check` on every PR.

```sh
claude --cloud "Implement phase 0 of docs/spec.md. Open a PR when make check passes."
claude --teleport            # pull a cloud session back into this checkout
```

Cloud sessions can build, test and open PRs. They cannot deploy: the cloud VM is not on
the tailnet. Deploying is a local step (`docs/deploy.md`).

## Secrets

None in this repo, ever. Tokens come from environment variables named in the config
(`*_env` keys). The config file in the repo is an example with placeholders. The real
one lives at `/etc/mp-infra/config.yaml` on the server and is not committed.
