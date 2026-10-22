# AGENTS.md — mp-infra

Guidance for coding agents (Claude Code, Codex, Shelley) working on this repository.
Read this and `docs/spec.md` before touching code. The spec is the build plan.

## What this is

A read-only infrastructure watch for Monster Puppet's servers: monster-p4 (Perforce +
Code Review), jenkins, the Windows build agent, and later p4-game. One Go binary:
`serve` (UI, report API, probes, alerts) and `report` (per-host agent).

## Rules

1. **No secrets in the repo.** Not in code, config examples, fixtures, tests or commit
   messages. Tokens come from env vars named in config. Fixture output must have real
   IPs, hostnames of third parties and usernames replaced by placeholders.
2. **Read-only.** Collectors and probes never change anything on a host. The single
   exception is the monthly `ACTION=status` build of the break-glass Jenkins job, which
   is itself read-only.
3. **Tailnet only.** Never add a code path that serves the UI on a public interface by
   default. Keep the UI port and the report port separate.
4. **Untrusted reports.** Treat everything in a report body as hostile input: size-limit
   it, validate it, escape it in templates, and never let one host's report touch
   another host's checks.
5. **Stdlib first.** Allowed: `modernc.org/sqlite`, `gopkg.in/yaml.v3`. No CGO. No npm,
   no bundler, no SPA: server-rendered `html/template`.
6. **Cross-platform agent.** Windows collectors go behind `//go:build windows`. The
   agent must build for linux/amd64 and windows/amd64 (`make dist`).

## Build and test

```sh
make build    # -> bin/mpinfra
make check    # vet + test; run this before you say you are done
make dist     # release binaries + SHA256SUMS
```

## Gotchas from the real servers

- The jenkins-win agent's Jenkins connection uses the **public** Jenkins URL and port
  50001 on purpose. It is the only route to that machine when Tailscale is down. Never
  suggest moving it.
- monster-p4's root shell prints SDP login noise ("Enter password / User perforce logged
  in"). Collectors that shell out must ignore it.
- `checkpoint.log` and Code Review logs have continuation lines. Match timestamps with
  `^YYYY-MM-DDTHH` only.
- P4 trust is keyed by IP:port. A probe connecting to P4 by a new IP needs its own trust
  entry.
