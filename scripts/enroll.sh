#!/usr/bin/env bash
# Enroll hosts with the mp-infra server in one go.
#
#   scripts/enroll.sh SERVER HOST [HOST...]
#   scripts/enroll.sh mp-infra monster-p4 jenkins jenkins-win
#
# Run it from a checkout of this repo on a machine that can `ssh` to the server and
# to every host. For each host it:
#   1. makes a fresh report token,
#   2. registers the token's hash on the server (MPINFRA_REPORT_TOKENS) and restarts it,
#   3. copies the agent binary and a minimal agent config to the host,
#   4. sends one report and checks it was accepted,
#   5. installs the 5-minute cron job (Linux) or scheduled task (Windows).
#
# SERVER and HOST are ssh names. If a host's ssh name differs from its mp-infra
# name, write it as NAME=SSHNAME (e.g. jenkins-win=win-admin@100.64.1.2).
# Running it again for a host replaces that host's token; other hosts are kept.
# Tokens are never printed or stored on this machine.
#
# Every NAME must already be listed under hosts: in the server config, because the
# server refuses to start with a token for an unknown host.
#
# Env overrides: REPORT_PORT (8099), ENV_FILE (/etc/mp-infra/env),
# CONFIG_FILE (/etc/mp-infra/config.yaml), TOKENS_VAR (MPINFRA_REPORT_TOKENS).
set -euo pipefail

REPORT_PORT=${REPORT_PORT:-8099}
ENV_FILE=${ENV_FILE:-/etc/mp-infra/env}
CONFIG_FILE=${CONFIG_FILE:-/etc/mp-infra/config.yaml}
TOKENS_VAR=${TOKENS_VAR:-MPINFRA_REPORT_TOKENS}

if [ $# -lt 2 ]; then
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
fi
SERVER=$1
shift

cd "$(dirname "$0")/.."
say() { printf '\n== %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

sha256() { if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi | cut -d' ' -f1; }
b64() { base64 | tr -d '\n'; }
# PowerShell -EncodedCommand wants base64 of UTF-16LE. Multi-line scripts sent any
# other way over ssh can silently do nothing on Windows.
ps_encode() { iconv -f UTF-8 -t UTF-16LE | b64; }

# --- binaries ---
say "Building the agent binaries"
make -s dist >/dev/null
LINUX_BIN=dist/mpinfra-linux-amd64
WIN_BIN=dist/mpinfra-windows-amd64.exe
[ -f "$LINUX_BIN" ] && [ -f "$WIN_BIN" ] || die "make dist did not produce the binaries"
echo "version $("$LINUX_BIN" version 2>/dev/null || echo '?')"

# --- server ---
say "Checking the server ($SERVER)"
SERVER_IP=$(ssh "$SERVER" 'tailscale ip -4' | head -1 | tr -d '\r')
[ -n "$SERVER_IP" ] || die "could not read the server's Tailscale IP (is tailscale running on $SERVER?)"
echo "tailnet IP $SERVER_IP"
if ! ssh "$SERVER" "ss -ltn" | grep -q "$SERVER_IP:$REPORT_PORT"; then
  die "the server is not listening on $SERVER_IP:$REPORT_PORT.
Set report_addr: \"$SERVER_IP:$REPORT_PORT\" in /etc/mp-infra/config.yaml on $SERVER,
run 'sudo systemctl restart mpinfra', then run this script again."
fi
if ! ssh "$SERVER" 'systemctl cat mpinfra 2>/dev/null' | grep -q "EnvironmentFile=-\?$ENV_FILE"; then
  echo "warning: the mpinfra unit on $SERVER does not load $ENV_FILE (EnvironmentFile=); tokens will not reach it"
fi
SERVER_URL="http://$SERVER_IP:$REPORT_PORT"

# --- tokens ---
declare -a NAMES TARGETS TOKENS PAIRS
for arg in "$@"; do
  name=${arg%%=*}
  target=${arg#*=}
  [[ $name =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] || die "invalid host name '$name' (lowercase letters, digits, dashes)"
  tok=$(openssl rand -hex 32)
  NAMES+=("$name"); TARGETS+=("$target"); TOKENS+=("$tok")
  PAIRS+=("$name=$(printf %s "$tok" | sha256)")
done

say "Registering ${#NAMES[@]} token(s) on the server and restarting it"
ssh "$SERVER" "sudo sh -s -- '$ENV_FILE' '$TOKENS_VAR' '$CONFIG_FILE' ${PAIRS[*]}" <<'REMOTE'
set -e
f=$1; var=$2; cfg=$3; shift 3
# The server refuses to start with a token for a host it does not know.
for pair in "$@"; do
  h=${pair%%=*}
  grep -Eq "^[[:space:]]*-[[:space:]]*name:[[:space:]]*\"?$h\"?[[:space:]]*$" "$cfg" || {
    echo "host '$h' is not listed under hosts: in $cfg. Add it there first; nothing was changed."; exit 1; }
done
[ -f "$f" ] || { install -m 0640 /dev/null "$f"; chgrp mpinfra "$f" 2>/dev/null || true; }
cp -p "$f" "$f.enroll-bak"
cur=$(grep "^$var=" "$f" | tail -1 | cut -d= -f2-)
new=$cur
for pair in "$@"; do
  h=${pair%%=*}
  new=$(printf '%s\n' "$new" | tr ',' '\n' | grep -v "^$h=" | grep -v '^$' | paste -sd, - || true)
  new=${new:+$new,}$pair
done
{ grep -v "^$var=" "$f" || true; echo "$var=$new"; } > "$f.tmp"
chown --reference="$f" "$f.tmp"; chmod --reference="$f" "$f.tmp"; mv "$f.tmp" "$f"
since=$(date '+%Y-%m-%d %H:%M:%S')
systemctl restart mpinfra
sleep 3
if ! systemctl is-active --quiet mpinfra; then
  journalctl -u mpinfra --since "$since" --no-pager | tail -5
  echo "the server did not start with the new tokens; restoring $f and restarting"
  mv "$f.enroll-bak" "$f"; systemctl restart mpinfra; exit 1
fi
rm -f "$f.enroll-bak"
# Only this start's lines: an older "no report tokens" warning must not fail the run.
if journalctl -u mpinfra --since "$since" --no-pager | grep -q 'no report tokens'; then
  echo "the server says it has no report tokens: check $f and the unit's EnvironmentFile"; exit 1
fi
echo "server restarted with tokens for: $(printf '%s\n' "$new" | tr ',' '\n' | cut -d= -f1 | paste -sd' ' -)"
REMOTE

# --- hosts ---
declare -a RESULTS

# Security checks every host gets: failed and successful logins (a login from
# outside the tailnet is crit), and baselines of admin accounts / SSH keys and of
# listening ports. -t (syslog identifier) works on RHEL and Ubuntu alike, where
# the unit is sshd or ssh; newer OpenSSH logs sessions as sshd-session.
LINUX_SEC=$(cat <<'YAML'
auth_failures:
  warn_per_ip: 100
  sources:
    - name: ssh
      cmd: ["journalctl", "-t", "sshd", "-t", "sshd-session", "--since", "-24h", "--no-pager", "-o", "cat"]
      pattern: '(?:Failed password|Invalid user) .* from (?P<ip>[0-9a-fA-F.:]+)'
logins:
  sources:
    - name: ssh
      cmd: ["journalctl", "-t", "sshd", "-t", "sshd-session", "--since", "-24h", "--no-pager", "-o", "cat"]
      pattern: 'Accepted \S+ for (?P<user>\S+) from (?P<ip>[0-9a-fA-F.:]+)'
accounts: true
listeners: true
YAML
)
WIN_SEC=$(cat <<'YAML'
auth_failures:
  warn_per_ip: 100
  sources:
    - name: rdp
      cmd: ["powershell.exe", "-NoProfile", "-Command", "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=(Get-Date).AddDays(-1)} -ErrorAction SilentlyContinue | ForEach-Object { $_.Properties[19].Value }"]
      pattern: '^(?P<ip>[0-9a-fA-F.:]+)\s*$'
logins:
  sources:
    - name: rdp
      cmd: ["powershell.exe", "-NoProfile", "-Command", "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624;StartTime=(Get-Date).AddDays(-1)} -ErrorAction SilentlyContinue | Where-Object { $_.Properties[8].Value -in 3,10 -and $_.Properties[18].Value -notin '-','','127.0.0.1','::1' } | ForEach-Object { '{0} {1} {2}' -f $_.Properties[5].Value, $_.Properties[18].Value, $_.Properties[8].Value }"]
      pattern: '^(?P<user>\S+) (?P<ip>[0-9a-fA-F.:]+) \d+\s*$'
accounts: true
listeners: true
YAML
)

enroll_linux() {
  local name=$1 target=$2 tok=$3 sudo=sudo
  [ "$(ssh "$target" 'id -u' | tr -d '\r')" = 0 ] && sudo=
  scp -q "$LINUX_BIN" "$target:/tmp/mpinfra.new"
  ssh "$target" "$sudo install -d -m 0700 /etc/mp-infra && $sudo install -m 0755 /tmp/mpinfra.new /usr/local/bin/mpinfra && rm -f /tmp/mpinfra.new \
    && if [ -f /etc/mp-infra/agent.yaml ]; then $sudo cp /etc/mp-infra/agent.yaml /etc/mp-infra/agent.yaml.bak; fi"
  { printf 'host: %s\nserver_url: "%s"\ntoken: "%s"\ndisks: ["/"]\n' "$name" "$SERVER_URL" "$tok"; printf '%s\n' "$LINUX_SEC"; } \
    | ssh "$target" "$sudo tee /etc/mp-infra/agent.yaml >/dev/null && $sudo chmod 600 /etc/mp-infra/agent.yaml"
  ssh "$target" "$sudo /usr/local/bin/mpinfra report -config /etc/mp-infra/agent.yaml" || return 1
  ssh "$target" "echo '*/5 * * * * root /usr/local/bin/mpinfra report -config /etc/mp-infra/agent.yaml >/dev/null 2>&1' | $sudo tee /etc/cron.d/mpinfra >/dev/null"
}

enroll_windows() {
  local name=$1 target=$2 tok=$3 script
  ssh "$target" "powershell -NoProfile -NonInteractive -EncodedCommand $(printf '%s' "New-Item -ItemType Directory -Force C:\\ProgramData\\mp-infra | Out-Null" | ps_encode)"
  # -O: legacy scp protocol. Win32-OpenSSH often has no working sftp subsystem,
  # which is what plain scp uses ("scp: Connection closed").
  scp -O -q "$WIN_BIN" "$target:C:/ProgramData/mp-infra/mpinfra.exe"
  script=$(cat <<PS
\$ErrorActionPreference = 'Stop'
\$d = 'C:\\ProgramData\\mp-infra'
if (Test-Path "\$d\\agent.yaml") { Copy-Item "\$d\\agent.yaml" "\$d\\agent.yaml.bak" -Force }
@"
host: $name
server_url: "$SERVER_URL"
token: "$tok"
disks: ['C:\\']
"@ | Set-Content -Encoding ascii "\$d\\agent.yaml"
@'
$WIN_SEC
'@ | Add-Content -Encoding ascii "\$d\\agent.yaml"
# (OI)(CI) so the files inside inherit it; without them SYSTEM cannot read agent.yaml.
# Folder only: /T would strip the files' inherited ACEs and leave them unreadable.
icacls \$d /inheritance:r /grant 'SYSTEM:(OI)(CI)F' /grant 'Administrators:(OI)(CI)F' | Out-Null
Get-ChildItem \$d -File | ForEach-Object { icacls \$_.FullName /reset | Out-Null }
& "\$d\\mpinfra.exe" report -config "\$d\\agent.yaml"
if (\$LASTEXITCODE -ne 0) { exit 1 }
Unregister-ScheduledTask mp-infra-report -Confirm:\$false -ErrorAction SilentlyContinue
\$a = New-ScheduledTaskAction -Execute "\$d\\mpinfra.exe" -Argument "report -config \$d\\agent.yaml"
\$t = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5)
Register-ScheduledTask mp-infra-report -Action \$a -Trigger \$t -User SYSTEM -RunLevel Highest | Out-Null
PS
)
  ssh "$target" "powershell -NoProfile -NonInteractive -EncodedCommand $(printf '%s' "$script" | ps_encode)"
}

for i in "${!NAMES[@]}"; do
  name=${NAMES[$i]} target=${TARGETS[$i]} tok=${TOKENS[$i]}
  say "Enrolling $name (ssh $target)"
  if ssh "$target" 'uname -s' >/dev/null 2>&1; then kind=linux; else kind=windows; fi
  echo "$kind host"
  if "enroll_$kind" "$name" "$target" "$tok"; then
    RESULTS+=("OK    $name")
  else
    RESULTS+=("FAIL  $name   (the report error is printed above)")
  fi
done

say "Done"
printf '%s\n' "${RESULTS[@]}"
echo
echo "Open the UI (https://<server>.<tailnet>.ts.net/ behind tailscale serve) — enrolled hosts turn green on the next refresh."
printf '%s\n' "${RESULTS[@]}" | grep -q '^FAIL' && exit 1 || exit 0
