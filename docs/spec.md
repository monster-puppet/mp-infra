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
The app **reads**. It never changes anything on a host. The single exception is
**unban** (`sec.fail2ban`): an admin (server config `admins`) pastes an IP address on
`/unban`, and each host whose own `agent.yaml` has `fail2ban: {unban: true}` gets it in
the reply to its next report. The server sends only addresses, at most 20, never
commands. The agent accepts only plain IP addresses (`netip.ParseAddr`: no CIDR,
hostname or zone), runs the fixed argv `<fail2ban client> unban <ip>` without a
shell, and sends the results in its next report. Every request, delivery and result
is stored with who and when.

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
- **Endpoint hosts** (`endpoint: true`, workstations reporting through the MP Launcher)
  carry no token: the launcher is shared through Perforce and cannot hold a secret. The
  report API accepts a token-less report only from a tailnet address that the last
  `ts.devices` probe maps to exactly one device of that endpoint host (a second device
  renamed to the same hostname makes both refused), only for that host, and only
  `endpoint.*` and `os.security_updates.*` checks. The device is matched by its Tailscale name or
  hostname; the launcher asks `GET /api/whoami` (report port) which host it is, and a
  device that is not enrolled gets 404 and sends nothing. The client sends facts with state ok;
  the server decides the state (§4 Endpoints).
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
| `report.fresh` | server sweep | reported within `stale_after` / — / `stale`. When `ts.online.<host>` is still ok the summary adds "online on tailnet, agent stopped or removed" (plus "(check Defender)" on `os: windows`); the last `agent_version` is kept in its data. Endpoint hosts never get the hint |
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
| `av.defender.<host>` | Windows report (`windows.defender`, default on): `Get-MpThreatDetection` of the last 7 days with names from `Get-MpThreat`, and `Get-MpComputerStatus` | no detection, real-time protection on, signatures ≤ 3 days old / RTP off, signatures older or of unknown age / any detection in 7 days, "Defender quarantined the mp-infra agent" when a resource is `mpinfra.exe`, `mpinfra.staged.exe` or the `mp-infra-report` task. Lists capped at 50 |
| `tls.<name>` | serve probe | > 21 days / > 7 / less |
| `dns.<name>` | serve probe: A record vs. expected | match / — / mismatch |
| `http.<name>` | serve probe: GET without following redirects. Optional `status` (exact), `location` (prefix of the redirect target), `contains` (text in the first MiB of the body) | all met / — / failed request, wrong status, wrong redirect, or text missing (a parked or wrong site) |

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
| `auth.failures.<host>` | report: failed SSH/P4/RDP logins in the last 24 h, top source IPs. warn at `warn` total or `warn_per_ip` from one IP (brute force). With a named group `time` in every source pattern: the 4 h count (`last_4h`) and each top IP's newest failure (`last`); a brute force whose IP has not failed for 4 h is reported as ended and stays ok. A match whose `time` is older than 24 h is ignored, so a source can be a whole log file (DSM's `auth.log`). Failures from `ignore` CIDRs (an office LAN) are not counted; their number is `ignored` in the data |
| `auth.logins.<host>` | report: successful SSH/RDP logins in the last 24 h. crit when one comes from outside the tailnet, loopback and `logins.allow`, unless the server matches the address to the current public endpoint of an untagged (personal) tailnet device from `ts.devices`. A source pattern with a named group `time` adds each login's newest time (`last`, UTC) and the summary says how long ago the outside login was |
| `sec.accounts.<host>` | report: uid 0 and login-shell accounts, wheel/sudo members, sudoers hashes, authorized_keys fingerprints (Windows: enabled users, Administrators / RDP / WinRM group members). Item list vs. last accepted: crit on any change, the summary names what was added and removed; accept in the UI |
| `ssh.auth.<host>` | report: `sshd -T`. Keys only, or passwords too (password or keyboard-interactive, with `AuthenticationMethods` chains that need a key counted as keys). ok when keys only, warn when passwords are accepted, crit when root may log in by password too. The network map marks the SSH port chip on the internet line with a key or a password field |
| `sec.listeners.<host>` | report: listening TCP sockets (not loopback) and their process; ports from 49152 up are reported as "dynamic". Vs. last accepted: warn on change; accept in the UI |
| `raid.<host>` | report: `/proc/mdstat`. crit when a data array is inactive or missing a member; warn when only a `system` array is (Synology md0/md1, DSM's copy on every disk) or while an array rebuilds or resyncs. A scrub is ok. A one-disk array is ok, noted "no redundancy" |
| `sec.fail2ban.<host>` | report: `fail2ban-client status` / `banned` and the `Ban` lines in `fail2ban.log` (last 24 h, host local time; "Restore Ban" after a restart is not new). ok while fail2ban runs with an sshd jail; warn when it does not run or has no sshd jail. The data also carries `banned_ips` (sorted, at most 1000 and cut short to fit the 16 KiB data limit, then `banned_ips_cut`), `unban` (the agent's `fail2ban.unban`) and `unban_results` (see §1). The network map sums `banned_now` (distinct addresses) over all hosts in the internet bubble, followed in brackets by that sum as a percentage of all failed logins in 24 h (`auth.failures`), with an "Unban an IP" link to `/unban`; `bans_24h` stays on the check page. A host whose check is not ok gets a shield badge on its internet line |
| `smart.<host>` | report: `smartctl -H -A -i` per device. crit on a failed self-assessment, an attribute FAILING_NOW, or pending (197) or uncorrectable (198) sectors; warn on reallocated sectors (5) or an unreadable drive. Attributes are matched by number |
| `ts.devices` | Tailscale API: devices not in the expected list, or not seen for 30 days |
| `opsec.items` | Notion OpSec checklist (read-only Notion token), count of open items |

### Endpoints (workstations)

Hosts with `endpoint: true` report through the MP Launcher every 4 h while it runs, as
the logged-in user (no admin, no agent install). They go stale only after
`endpoint_stale_after` (default 7 days), never while waiting for their first report,
and get no `ts.online` / `ts.key_expiry` checks. The server sets each state from the
reported facts, with thresholds under `thresholds.endpoint_*`.

| id | Facts | ok / warn / crit |
|---|---|---|
| `endpoint.bitlocker.<host>` | Shell `System.Volume.BitLockerProtection` of the system drive | on / unknown or encrypting / off, suspended or decrypting |
| `endpoint.av.<host>` | `root\SecurityCenter2` products (productState), `Get-MpComputerStatus` | an enabled product, up to date / signatures out of date or older than `endpoint_av_sig_days` (3), Defender tamper protection off / no enabled product, active Defender with real-time protection off, or `defender.detections.count` > 0 (optional `{count, names}` for the last 7 days) |
| `endpoint.firewall.<host>` | `Get-NetFirewallProfile`, SecurityCenter2 firewall products | all profiles on or a third-party firewall / a profile off / — |
| `endpoint.boot.<host>` | `SecureBoot\State`, `tpmtool getdeviceinformation` | Secure Boot on and TPM 2.0 / otherwise / — |
| `endpoint.screenlock.<host>` | `InactivityTimeoutSecs` policy, else the user's screensaver with sign-in | lock within `endpoint_screen_lock_secs` (900) / longer or none / — |
| `endpoint.os.<host>` | build, UBR, newest `Get-HotFix`, reboot-pending keys | supported and updated / no update for `endpoint_update_age` (45 d) or reboot pending / build below `endpoint_min_build` (26200, Windows 11 25H2) |

### Security notices

Public feeds, no credentials (config `notices`, off unless `enabled`). Feeds are fetched hourly, KEV and the Jenkins update centre every 6 h; between fetches the last result is reused. On a feed's first run, items older than 14 days count as seen.

| id | Source | ok / warn / crit |
|---|---|---|
| `notice.<feed>` | RSS/Atom feed (`notices.feeds`, default exe.dev, Tailscale, Jenkins advisories, PHP 8.3 security releases, Let's Encrypt incidents, DigitalOcean trust-security). Optional `tag` and `title` filters | no unaccepted notices / feed unreachable, or new notices on a `warn` feed / new notices on a `crit` feed (exe.dev, Tailscale). **Accept** in the UI marks all current items seen |
| `notice.kev` | CISA Known Exploited Vulnerabilities JSON, entries whose vendor or product contains a `kev_products` word | no new entries / catalogue unreachable / new matching entry (actively exploited). Accept as above |
| `notice.jenkins.installed` | Jenkins update centre `warnings` matched (full-regex, like Jenkins) to the core (`X-Jenkins`) and installed plugins (`/pluginManager/api/json`, jenkins token) | no match / update centre or Jenkins unreachable / an installed component has a warning. Clears by itself after the update; no accept |

## 5. Web UI

- Server-rendered `html/template`, one hand-written `static/app.js` at most. No npm, no
  bundler, no SPA. Auto-refresh every 60 s: `app.js` fetches the page and swaps
  `<main>` in place (no full reload); a `<noscript>` meta refresh covers no-JS.
- Dark theme in Monster Puppet colours (red accent). Works at phone width.
- **Home:** one row per host with its worst state, then the cross-host groups (Tailscale,
  ports, certs, licences). Red and stale sort to the top. Every check shows its age.
- **Meters:** checks with a number on a natural scale show a bar under the summary:
  disk used, licences used (`p4.licence`), days left on a certificate (`tls.*`, full at
  90) or node key (`ts.key_expiry.*`, full at 180), snapshot age against its crit days.
- **Check detail:** current data, a 30-day chart from the stored reports for disk
  used, failed logins and licensed users (one point per 6 h), the last 30 transitions, an "acknowledge until …" button
  for `warn` states (e.g. an accepted firewall change). `crit` cannot be acknowledged
  for more than 24 h.
- **History:** the transitions table, filterable by host.
- **Unban** (`/unban`): admins paste an IP address and it is queued for every host whose
  latest `sec.fail2ban` data says `unban: true`. The report handler answers that host's
  next report with `200 application/json {"unban":[...]}` instead of `204` and marks the
  rows sent; a request not delivered within 1 h expires. Results from a report update
  only that host's own rows. Everyone sees where an address is currently banned
  (`?ip=`, from each host's latest `banned_ips`) and the last 50 requests with a state
  per host: waiting, sent, done, failed or expired.
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
