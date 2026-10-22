# Getting the hosts to report

## The quick way

From a checkout of this repo, on a machine that can `ssh` to the server and to
every host (and has Go, for `make dist`):

```sh
scripts/enroll.sh mp-infra monster-p4 jenkins jenkins-win
```

The first name is the server, the rest are the hosts, all as you `ssh` to them. If a
host's ssh name differs from its mp-infra name, write `NAME=SSHNAME`. It prints `OK`
or `FAIL` per host. The manual steps below are what the script does.

## By hand

There are two kinds of machine:

- **The server**: the machine that runs `mpinfra serve` and shows the web page
  (the one you log into as `exedev@mp-infra`).
- **The hosts**: monster-p4, jenkins and jenkins-win. Each one runs a small program
  every 5 minutes that sends its status to the server.

A host shows **stale** on the page until the server has received a report from it.
Right now no host sends reports yet, so all of them are stale. The steps below fix
that, one host at a time. Run each command exactly as shown, replacing only the
words in CAPITALS.

---

## Part A: on the server (once)

### A1. Check the server listens for reports

```sh
sudo ss -ltnp | grep mpinfra
```

You should see **two** lines, one ending `:8098` (the web page) and one ending
`:8099` (where hosts send reports). Both must start with an address like
`100.x.y.z`, not `127.0.0.1`.

Note the `100.x.y.z` address. Below it is called **SERVER_IP**. You can also get it
with:

```sh
tailscale ip -4
```

If the `:8099` line is missing or shows `127.0.0.1`, open the config:

```sh
sudo nano /etc/mp-infra/config.yaml
```

and make these two lines read (with your SERVER_IP):

```yaml
ui_addr: "SERVER_IP:8098"
report_addr: "SERVER_IP:8099"
```

Save (Ctrl+O, Enter, Ctrl+X), then `sudo systemctl restart mpinfra` and run the
`ss` command again.

### A2. Make one password ("token") per host

Run this three times, once for each host:

```sh
mpinfra token
```

Each run prints two lines:

```
token:  3f9a...   <- goes to the host
sha256: 81bc...   <- stays on the server
```

Write them down in a table like this (keep it private, e.g. in 1Password):

| Host | token | sha256 |
|---|---|---|
| monster-p4 | ... | ... |
| jenkins | ... | ... |
| jenkins-win | ... | ... |

### A3. Tell the server the three sha256 values

```sh
sudo nano /etc/mp-infra/env
```

Add one line (all on one line, no spaces), using the three **sha256** values:

```
MPINFRA_REPORT_TOKENS=monster-p4=SHA_FOR_P4,jenkins=SHA_FOR_JENKINS,jenkins-win=SHA_FOR_WIN
```

Save, then:

```sh
sudo systemctl restart mpinfra
sudo journalctl -u mpinfra -n 20 --no-pager
```

The log must **not** contain `warning: no report tokens`. If it does, the line in
`/etc/mp-infra/env` is misspelled.

### A4. Put the program somewhere the hosts can fetch it

```sh
cp /usr/local/bin/mpinfra ~/mpinfra-linux
cp ~/mp-infra/dist/mpinfra-windows-amd64.exe ~/mpinfra.exe   # built by make dist
```

---

## Part B: on each Linux host (monster-p4, then jenkins)

### B1. Can the host reach the server?

On the host:

```sh
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://SERVER_IP:8099/api/report
```

- `401` means good: the host reaches the server (401 only means "no token yet").
- Nothing for a while, then `000`: the host cannot reach the server. Tailscale is
  blocking it. In the Tailscale admin console, allow this host to reach the server
  on port 8099 (docs/deploy.md section 6), then try again.

### B2. Copy the program over

From the **server**:

```sh
scp ~/mpinfra-linux HOSTNAME:/tmp/mpinfra
```

On the **host**:

```sh
sudo install -m 0755 /tmp/mpinfra /usr/local/bin/mpinfra
mpinfra version
```

### B3. Write the host's settings file

On the host. Replace HOSTNAME with `monster-p4` or `jenkins`, and TOKEN with that
host's **token** (not the sha256) from step A2:

```sh
sudo mkdir -p /etc/mp-infra
sudo tee /etc/mp-infra/agent.yaml >/dev/null <<'EOF'
host: HOSTNAME
server_url: "http://SERVER_IP:8099"
token: "TOKEN"
disks: ["/"]
EOF
sudo chmod 600 /etc/mp-infra/agent.yaml
```

This is the minimal setup: uptime and disk only. The other checks (checkpoint,
firewall, updates, ...) get added later from `examples/agent-*.yaml`, once the
basics work.

### B4. Send one report by hand

```sh
sudo mpinfra report -config /etc/mp-infra/agent.yaml && echo OK
```

- `OK`: done. Reload the web page: the host is no longer stale.
- Anything else: see "If it fails" at the bottom.

### B5. Send a report every 5 minutes

```sh
echo '*/5 * * * * root /usr/local/bin/mpinfra report -config /etc/mp-infra/agent.yaml >/dev/null 2>&1' \
  | sudo tee /etc/cron.d/mpinfra
```

---

## Part C: on jenkins-win

Log in with RDP and open **PowerShell as Administrator**.

### C1. Can it reach the server?

```powershell
curl.exe -s -o NUL -w "%{http_code}`n" -X POST http://SERVER_IP:8099/api/report
```

`401` is good. `000` means Tailscale blocks it (same fix as B1).

### C2. Copy the program over

Copy `~/mpinfra.exe` from the server to `C:\ProgramData\mp-infra\mpinfra.exe`
(for example via `scp` from the server: `scp ~/mpinfra.exe jenkins-win:C:/ProgramData/mp-infra/`).
Then:

```powershell
New-Item -ItemType Directory -Force C:\ProgramData\mp-infra | Out-Null
& C:\ProgramData\mp-infra\mpinfra.exe version
```

### C3. Write the settings file

Replace SERVER_IP and TOKEN (jenkins-win's **token**):

```powershell
@'
host: jenkins-win
server_url: "http://SERVER_IP:8099"
token: "TOKEN"
disks: ['C:\']
'@ | Set-Content -Encoding ascii C:\ProgramData\mp-infra\agent.yaml
icacls C:\ProgramData\mp-infra /inheritance:r /grant SYSTEM:F /grant Administrators:F
```

### C4. Send one report by hand

```powershell
& C:\ProgramData\mp-infra\mpinfra.exe report -config C:\ProgramData\mp-infra\agent.yaml; "exit $LASTEXITCODE"
```

`exit 0` is good. Reload the web page.

### C5. Every 5 minutes

```powershell
$a = New-ScheduledTaskAction -Execute C:\ProgramData\mp-infra\mpinfra.exe -Argument 'report -config C:\ProgramData\mp-infra\agent.yaml'
$t = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5)
Register-ScheduledTask mp-infra-report -Action $a -Trigger $t -User SYSTEM -RunLevel Highest
```

---

## If it fails

The report command prints why. Find the message:

| Message contains | What it means | Fix |
|---|---|---|
| `timeout`, `connection refused`, `no route` | host cannot reach SERVER_IP:8099 | B1 / C1, and A1 |
| `401` `unknown token` | the token in agent.yaml does not match any sha256 in A3 | copy the **token** (not the sha256) again; check the server line in A3; `sudo systemctl restart mpinfra` |
| `401` `missing bearer token` | `token:` line empty in agent.yaml | fill it in |
| `403` | the `host:` name in agent.yaml is not the name you put before `=` in A3 | make them identical |
| `400` `collected_at` | the host's clock is wrong by more than a day | fix the clock |
| `429` | you ran it twice within 30 seconds | wait half a minute |

On the server, every attempt is logged:

```sh
sudo journalctl -u mpinfra -n 50 --no-pager | grep api/report
```

No lines at all means the report never arrived (network). A line ending in `204`
means it worked.
