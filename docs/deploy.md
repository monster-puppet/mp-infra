# Deploying mp-infra

Real addresses and tokens are not in this file. They live in the server config and in
the Monster Puppet IT notes (Notion 🔐 OpSec, without secrets) and in 1Password.

## 1. Build

```sh
make dist
# dist/mpinfra-linux-amd64
# dist/mpinfra-windows-amd64.exe
# dist/SHA256SUMS
```

Copy with `scp` to the Linux hosts. Compare the SHA256 on the target before installing.

## 2. Server (`jenkins` droplet)

```sh
install -m 0755 mpinfra-linux-amd64 /usr/local/bin/mpinfra
useradd --system --home /var/lib/mp-infra --shell /sbin/nologin mpinfra
install -d -o mpinfra -m 0750 /var/lib/mp-infra /etc/mp-infra
install -o root -g mpinfra -m 0640 config.yaml /etc/mp-infra/config.yaml
install -o root -g mpinfra -m 0640 /dev/null /etc/mp-infra/env   # secrets, KEY=value lines
```

`/etc/systemd/system/mpinfra.service`:

```ini
[Unit]
Description=mp-infra watch
After=network-online.target tailscaled.service
Wants=network-online.target

[Service]
User=mpinfra
EnvironmentFile=/etc/mp-infra/env
ExecStart=/usr/local/bin/mpinfra serve -config /etc/mp-infra/config.yaml
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/mp-infra
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```sh
systemctl daemon-reload && systemctl enable --now mpinfra
curl -s http://<tailnet-ip>:8098/healthz
```

`serve` refuses to start unless `ui_addr` and `report_addr` are loopback or tailnet
addresses on different ports. It keeps a daily `VACUUM INTO` copy at
`/var/lib/mp-infra/mpinfra.db.backup` and deletes raw reports after 90 days.

Viewer names come from tailscaled's LocalAPI socket
(`/var/run/tailscale/tailscaled.sock`). Without it the UI shows viewer addresses.

**Do not open the port in firewalld.** It is reached only over `tailscale0`. Check from
outside the tailnet that it times out.

## 3. Report tokens

Make one token per host, on any machine with the binary:

```sh
mpinfra token
# token:  <put in that host's agent.yaml>
# sha256: <add host=sha256 to MPINFRA_REPORT_TOKENS in /etc/mp-infra/env>
```

`MPINFRA_REPORT_TOKENS=monster-p4=<sha256>,jenkins=<sha256>,jenkins-win=<sha256>`.
The server keeps only the hashes. A report made with one host's token for another
host is refused with 403.

## 4. Reporting agent, Linux hosts

Start from `examples/agent-monster-p4.yaml` or `examples/agent-jenkins.yaml`. Replace
the placeholders, then:

```sh
install -m 0755 mpinfra-linux-amd64 /usr/local/bin/mpinfra
install -d -m 0700 /etc/mp-infra
install -m 0600 agent.yaml /etc/mp-infra/agent.yaml    # host name, server URL, token
mpinfra check -config /etc/mp-infra/agent.yaml         # dry run, prints JSON
echo '*/5 * * * * root /usr/local/bin/mpinfra report -config /etc/mp-infra/agent.yaml >/dev/null 2>&1' \
  > /etc/cron.d/mpinfra
```

The agent runs as root because the checkpoint log, firewall state and `dnf updateinfo`
need it. It only reads.

## 5. Reporting agent, `jenkins-win`

Start from `examples/agent-jenkins-win.yaml`.

Over SSH on the tailnet (`ssh jenkins-win`). Multi-line PowerShell over SSH stdin
silently does nothing there. Send each block as `-EncodedCommand` (base64 UTF-16LE).

```powershell
New-Item -ItemType Directory -Force C:\ProgramData\mp-infra
# copy mpinfra.exe + agent.yaml there, then restrict the folder to SYSTEM + Administrators
icacls C:\ProgramData\mp-infra /inheritance:r /grant SYSTEM:F /grant Administrators:F
$a = New-ScheduledTaskAction -Execute C:\ProgramData\mp-infra\mpinfra.exe `
       -Argument 'report -config C:\ProgramData\mp-infra\agent.yaml'
$t = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5)
Register-ScheduledTask mp-infra-report -Action $a -Trigger $t -User SYSTEM -RunLevel Highest
```

Never open an inbound port on this machine for mp-infra. The agent only connects out.

## 6. Tailscale ACL (Marcus, admin console)

Tag the server device `tag:monitor`. Then add grants along these lines:

```jsonc
// members can open the UI
{"src": ["autogroup:member"], "dst": ["tag:monitor"], "ip": ["tcp:8098"]},
// every host, including the untrusted CI agent, may only post reports
{"src": ["tag:ci-untrusted"], "dst": ["tag:monitor"], "ip": ["tcp:8099"]}
```

UI and report API listen on separate ports (8098, 8099) so the untrusted agent can
reach only the report endpoint. Test that `jenkins-win` cannot open the UI port.

## 7. Tokens (all read-only, all in `/etc/mp-infra/env`)

| Env var | What | Scope |
|---|---|---|
| `MPINFRA_TS_CLIENT_ID` / `_SECRET` | Tailscale OAuth client | `devices:core:read` only |
| `MPINFRA_JENKINS_TOKEN` | Jenkins API token of a dedicated `mpinfra` user | Overall/Read, Job/Read; Job/Build on `break-glass-windows-tailscale` only |
| `MPINFRA_DO_TOKEN` | DigitalOcean API token | read scope |
| `MPINFRA_SLACK_WEBHOOK` | new incoming webhook for an alerts channel | — |
| `MPINFRA_SMTP_PASSWORD` | alert mail | — |
| `MPINFRA_NOTION_TOKEN` | Notion integration shared with the OpSec checklist only | read content |
| `MPINFRA_DEADMAN_URL` | heartbeat ping URL | — |
| `MPINFRA_REPORT_TOKENS` | `host=sha256hash,...` | — |
| `MPINFRA_GOOGLE_CLIENT_SECRET` | Google OAuth client secret (§8), only with `google_login` | — |
| `MPINFRA_SESSION_KEY` | signs sign-in cookies; `mpinfra token`, first line | — |
| `MPINFRA_MCP_TOKENS` | `client=sha256hash,...` for the read-only `/mcp` endpoint ([mcp.md](mcp.md)) | — |

Create each one fresh for mp-infra. Never reuse an existing token, so any one of them
can be revoked without breaking something else.

## 8. Google sign-in (optional)

Off unless `google_login.client_id` is set. When on, every UI page needs a Google
account from `allowed_domain` (a Workspace account: Google's `hd` claim must match)
or one listed in `allowed_emails`. It is a second gate; the tailnet ACL still applies.
`/healthz` and `/api/status.json` stay open on the tailnet for the morning brief.
`/mcp` skips sign-in too and requires its own bearer token instead ([mcp.md](mcp.md)).

Google accepts an http redirect URI only for localhost, so the UI needs https on a
real name. Use `tailscale serve` with the tailnet's ts.net certificate:

1. Tailscale admin console → DNS: MagicDNS on, HTTPS Certificates on. The machine
   name and tailnet name become public in Certificate Transparency logs.
2. In `config.yaml`: `ui_addr: "127.0.0.1:8098"` and
   `base_url: "https://<machine>.<tailnet>.ts.net"`.
3. On the server: `tailscale serve --bg --https=443 http://127.0.0.1:8098`.
4. ACL: members reach `tag:monitor` on `tcp:443` instead of `tcp:8098`. The report
   grant is unchanged.
5. Google Cloud console, in a project owned by the Workspace:
   - OAuth consent screen: user type **Internal**, scopes `openid` and `email`.
   - Credentials → OAuth client ID → **Web application**. Authorized redirect URI:
     `https://<machine>.<tailnet>.ts.net/auth/callback`. No JavaScript origins.
6. Put the client ID in `google_login.client_id`, the secret in
   `MPINFRA_GOOGLE_CLIENT_SECRET`, and a fresh `mpinfra token` value in
   `MPINFRA_SESSION_KEY`. Restart.

`serve` must reach `oauth2.googleapis.com` over HTTPS. The browser alone talks to
`accounts.google.com`. Behind `tailscale serve` the log's `tailnet=` field shows
`local`; `viewer=` is the Google account. Changing `MPINFRA_SESSION_KEY` signs
everyone out. Removing someone from the allow list locks them out after a restart.

## Rollback

`systemctl disable --now mpinfra`, remove `/etc/cron.d/mpinfra` on each host, and run
`Unregister-ScheduledTask mp-infra-report` on jenkins-win. Nothing else on the hosts
depends on it.
