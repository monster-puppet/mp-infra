# mp-infra — build spec

This is the plan for building the app. Work through the phases in order. Each phase
ends with something deployed and useful, and its own acceptance checks.

## 1. Goals

1. **Catch silent failures.** A job that stops working must turn red within one run of
   that job, not six months later.
2. **Guard the lockout paths.** If a server or the Windows agent drops off Tailscale,
   or a key that would make it drop off is about to expire, alert immediately.
3. **Catch drift.** A public port that opens, a firewall rule that comes back after a
   reinstall, or a certificate that is about to expire.
4. **One page.** Anyone on the team can open it on the tailnet and see the whole state
   in five seconds.

Non-goals: metrics graphs, log aggregation, uptime SLAs, multi-tenant, remote control.
The app **reads**. It never changes anything on a host.

## 2. Hosts in scope

| Host | OS | Reports via |
|---|---|---|
| `monster-p4` | Rocky 8 | `mpinfra report` from cron (root) |
| `jenkins` | CentOS Stream 9 | `mpinfra report` from cron (root). Also runs `mpinfra serve` |
| `jenkins-win` | Windows Server 2022 (AWS) | `mpinfra.exe report` from a scheduled task (SYSTEM) |
| `p4-game` | Ubuntu 24.04 | `mpinfra report` from cron. Not on the tailnet yet, so phase 3 |

Addresses, tokens and hostnames go in the config file, never in code.

## 3. Architecture

### Binary

One executable, `mpinfra`, with subcommands:

```
mpinfra serve  -config /etc/mp-infra/config.yaml   # UI + /api/report + probes + alerter
mpinfra report -config /etc/mp-infra/agent.yaml    # collect local facts, POST them, exit
mpinfra check  -config ...                          # run report collectors, print JSON, don't send
mpinfra version
```

Go standard library first. Allowed dependencies: `modernc.org/sqlite` (pure Go, no CGO,
same as mp-crm) and `gopkg.in/yaml.v3`. Anything else needs a reason in the PR.

### Data flow

1. **Report (push).** Each host runs `mpinfra report` every 5 minutes. It collects facts
   locally (see §4) and POSTs one JSON document to `serve` over the tailnet.
2. **Probe (pull).** `serve` runs its own checks from the outside every 5 minutes: TCP and
   HTTP reachability, certificate expiry, a public port scan of each host's public IP,
   the Tailscale API (device list, last seen, key expiry), and the Jenkins API (agent
   online, last result of selected jobs).
3. **Evaluate.** Every fact becomes a `check` with a state: `ok`, `warn`, `crit` or `stale`.
   A host that has not reported for 15 minutes makes all its checks `stale`, which
   alerts like `crit`.
4. **Alert** on state *changes* only (see §6).

### Report payload

```json
{
  "host": "monster-p4",
  "agent_version": "0.1.0",
  "collected_at": "2026-10-22T14:05:00Z",
  "checks": [
    {"id": "p4.checkpoint", "state": "ok", "summary": "checkpoint 02:05 ok, 41 s", "data": {"...": "..."}}
  ]
}
```

The agent decides `state` for local facts, using thresholds from its own config. The
server stores the payload as received and adds its own probe checks next to it.

### Trust model

- **No central credentials.** `serve` holds no SSH keys or root passwords. The only tokens
  it holds are read-only: a Tailscale OAuth client with `devices:core:read`, and a
  Jenkins read-only API token.
- **Per-host report tokens.** Each host has its own token. The server accepts a report
  only for the host that token belongs to, so a compromised host cannot fake another's
  state. Store only a hash of each token on the server.
- **`jenkins-win` is untrusted** (`tag:ci-untrusted`). Its reports may be lies. Its
  critical checks (on the tailnet, agent online) must therefore also be confirmed by
  server-side probes (Tailscale API, Jenkins API), and those win when they disagree.
- **Tailnet only.** `serve` binds to the Tailscale IP. A startup check refuses to bind to
  `0.0.0.0` or a public address unless `-insecure-bind` is passed.
- **Viewer identity** comes from the Tailscale LocalAPI `whois` on the remote address.
  The app shows who is viewing and logs every request. Optional Google sign-in
  (`google_login`, deploy.md §8) adds a second gate on top of the tailnet; then the
  viewer is the Google account.
- **Tailscale ACL:** a new tag `tag:monitor` for the serve host. Members may reach it on the
  UI port. Every reporting host, `tag:ci-untrusted` included, may reach only its
  `/api/report` port. Changing the ACL is a manual step for Marcus (see deploy.md).

### Storage

SQLite at `/var/lib/mp-infra/mpinfra.db`. Tables: `reports` (raw JSON, 90-day retention),
`checks` (current state per host+id), `transitions` (state change history, kept forever),
`alerts_sent`. WAL mode. Daily `VACUUM INTO` backup next to the DB.

## 4. Checks

Each check has an id, a default threshold, and the phase it ships in. The thresholds
are config values, not constants.

### Lockout paths (phase 1)

| id | Source | ok / warn / crit |
|---|---|---|
| `ts.online.<host>` | Tailscale API | last seen < 5 min / < 15 / older |
| `ts.key_expiry.<host>` | Tailscale API | expiry disabled / — / expiry enabled or < 14 days |
| `jenkins.agent.<name>` | Jenkins API | online / — / offline > 5 min |
| `win.tailscale_service` | jenkins-win report | running + Automatic + restart-on-failure / — / anything else |
| `win.breakglass_job` | Jenkins API | last `break-glass-windows-tailscale` run SUCCESS within 35 days / — / failed or older |

`server` runs a monthly `ACTION=status` build of the break-glass job through the Jenkins
API so that route is proven regularly (needs a Jenkins token with Build on that one job;
see deploy.md).

### Silent failures (phase 1)

| id | Source | ok / warn / crit |
|---|---|---|
| `p4.checkpoint` | monster-p4 report: tail of `/p4/1/logs/checkpoint.log` | last run < 26 h and no "Aborting" / — / otherwise |
| `p4.offline_db` | monster-p4 report: `verify_sdp` result or offline db journal age | usable / — / not |
| `serve.self` | external dead-man ping (§6) | — | — |

### Drift (phase 2)

| id | Source | ok / warn / crit |
|---|---|---|
| `ports.public.<host>` | serve probe: TCP connect scan of the host's public IP for a configured port list | open set == expected set / — / any unexpected open port |
| `fw.rules.<host>` | report: `firewall-cmd --list-all` hash vs. last accepted | same / changed (acknowledge in UI) / — |
| `win.fw.allow_any` | jenkins-win report: enabled inbound allow rules with RemoteAddress Any | none / — / any |
| `tls.<name>` | serve probe | > 21 days / > 7 / less |
| `dns.<name>` | serve probe: A record vs. expected | match / — / mismatch |

### Patches and limits (phase 2)

| id | Source | ok / warn / crit |
|---|---|---|
| `os.security_updates.<host>` | report: `dnf updateinfo list --security` / `apt list --upgradable` / Windows Update COM | 0 / any < 14 days old / any older |
| `pkg.version.<name>` | report: p4d, PHP, Code Review, Jenkins versions | shown, plus warn when a configured minimum is not met |
| `disk.<host>.<mount>` | report | < 80% / < 90% / more |
| `p4.licence` | report: `p4 license -u` users and clients | < limit / at limit / — |
| `snapshot.age.<droplet>` | serve probe: DigitalOcean API, read-only token | < 35 days / < 60 / older |

### Attack surface (phase 3)

| id | Source |
|---|---|
| `auth.failures.<host>` | report: failed SSH/P4/RDP logins in the last 24 h, top source IPs. warn at `warn` total or `warn_per_ip` from one IP (brute force) |
| `auth.logins.<host>` | report: successful SSH/RDP logins in the last 24 h. crit when one comes from outside the tailnet, loopback and `logins.allow`, unless the server matches the address to the current public endpoint of an untagged (personal) tailnet device from `ts.devices` |
| `sec.accounts.<host>` | report: uid 0 and login-shell accounts, wheel/sudo members, sudoers hashes, authorized_keys fingerprints (Windows: enabled users, Administrators / RDP / WinRM group members). Item list vs. last accepted: crit on any change, the summary names what was added and removed; accept in the UI |
| `sec.listeners.<host>` | report: listening TCP sockets (not loopback) and their process; ports from 49152 up are reported as "dynamic". Vs. last accepted: warn on change; accept in the UI |
| `ts.devices` | Tailscale API: devices not in the expected list, or not seen for 30 days |
| `opsec.items` | Notion OpSec checklist (read-only Notion token), count of open items |

## 5. Web UI

- Server-rendered `html/template`, one hand-written `static/app.js` at most. No npm, no
  bundler, no SPA. Auto-refresh every 60 s.
- Dark theme in Monster Puppet colours (red accent). Works at phone width.
- **Home:** one row per host with its worst state, then the cross-host groups (Tailscale,
  ports, certs, licences). Red and stale sort to the top. Every check shows its age.
- **Check detail:** current data, the last 30 transitions, an "acknowledge until …" button
  for `warn` states (e.g. an accepted firewall change). `crit` cannot be acknowledged
  for more than 24 h.
- **History:** the transitions table, filterable by host.
- `/healthz` (no auth, tailnet only) and `/api/status.json` (for the SecondBrain morning
  brief to read one line from).

## 6. Alerts

- Sent on transitions into `crit` or `stale`, and on recovery. Never repeated while the
  state holds, except a reminder every 12 h for unacknowledged `crit`.
- Channels: a **new, dedicated** Slack incoming webhook (not the bot token on the Notion
  P4 Maintenance page, which is due for rotation) and email via SMTP. Both URLs/passwords
  come from env vars.
- Message: host, check, old → new state, summary, link to the check page.
- **Dead-man switch:** `serve` pings an external heartbeat URL (e.g. healthchecks.io free
  tier) every 5 minutes. If `serve` or its whole droplet dies, that service emails us.
  Without this, a dead monitor looks exactly like a quiet night.
- Quiet hours: none for `crit`. A daily 08:00 digest lists the `warn` items.

## 7. Phases

### Phase 0 — skeleton and deploy (½ day)
- `serve` with the home page reading from SQLite, `/healthz`, tailnet-only bind check.
- `report` with one trivial collector (`host.uptime`), per-host token auth.
- Deployed on `jenkins` per deploy.md, reporting from all three hosts.
- **Accept:** the page lists three hosts with fresh data. A request from outside the
  tailnet times out. A report signed with host A's token for host B returns 403.

### Phase 1 — lockout paths and silent failures (1 day)
- All phase 1 checks, Slack + email alerts, dead-man switch.
- **Accept (do each one for real, then undo):**
  - Stop Tailscale on `jenkins-win` through the break-glass job → `ts.online.jenkins-win`
    goes crit and alerts within 10 minutes, then recovers.
  - Rename `checkpoint.log` temporarily, or point the check at a test file with
    "Aborting" → `p4.checkpoint` goes crit.
  - Stop `mpinfra serve` → the dead-man service emails within its grace period.

### Phase 2 — drift, patches, limits (1–2 days)
- **Accept:** open a test port on `jenkins` → `ports.public.jenkins` crit within 10 min.
  Close it → recovers. Security update counts match a manual `dnf updateinfo` run.

### Phase 3 — attack surface, p4-game, history polish
- p4-game joins the tailnet first (separate infra task).

## 8. Repo layout

```
cmd/mpinfra/          main.go, subcommand wiring
internal/config/      YAML config + env secret lookup
internal/report/      collectors (one file per check family, build tags for windows/linux)
internal/probe/       server-side probes (tcp, tls, tailscale, jenkins, digitalocean)
internal/store/       SQLite schema + queries
internal/eval/        thresholds → states, stale detection, transitions
internal/alert/       slack, smtp, deadman
internal/server/      ingest, server-side rules, stale sweep, periodic loops
internal/web/         handlers, templates, static
examples/             agent configs per host (placeholders only)
docs/                 spec.md (this), deploy.md
```

## 9. Testing

- Every collector has a test that runs against fixture output (captured command output in
  `testdata/`), so tests never need a real server.
- `internal/eval` is table-tested: thresholds, stale, transitions, acknowledge expiry.
- `make check` (vet + test) passes before any commit.
