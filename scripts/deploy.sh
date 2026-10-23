#!/usr/bin/env bash
# Ship the current main to the server and every agent in one go.
#
#   scripts/deploy.sh                 server, then every host in deploy/hosts
#   scripts/deploy.sh --agents        agents only
#   scripts/deploy.sh jenkins nas     the server, then just these agents
#   scripts/deploy.sh -n ...          dry run: print what would happen
#
# Run it from a clean checkout of main on the admin machine (TACCO-PC), in a real
# terminal: the server and any host whose ssh user is not root ask for a sudo
# password. Security model:
#   - push only, over the ssh keys that already exist; no host pulls updates and
#     no new credentials, ports or sudo rules are added
#   - only code that is on origin/main ships, the same commit the server builds
#   - each binary's sha256 is checked on the host, after it is copied into the
#     root-owned agent directory, before it is installed
#   - agent configs (and their tokens) are never read, copied or printed
#   - the new binary must pass `check` with the host's own config before it is
#     installed, and must send a report after; otherwise the old one is restored
# A failed host does not stop the others. Exit status is 1 if any host failed.
set -euo pipefail

cd "$(dirname "$0")/.."
say() { printf '\n== %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
b64() { base64 | tr -d '\n'; }
# PowerShell -EncodedCommand wants base64 of UTF-16LE (see enroll.sh).
ps_encode() { iconv -f UTF-8 -t UTF-16LE | b64; }

DRY= SERVER=1 ONLY=()
for a in "$@"; do
  case $a in
    -n|--dry-run) DRY=1 ;;
    --agents) SERVER= ;;
    -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) die "unknown option $a" ;;
    *) ONLY+=("$a") ;;
  esac
done
SERVER_SSH=${SERVER_SSH:-mp-infra}
HOSTS_FILE=${HOSTS_FILE:-deploy/hosts}
run() { if [ -n "$DRY" ]; then printf '  would run: %s\n' "$*"; else "$@"; fi; }

# --- guard: only pushed code on main ---
say "Checking the checkout"
[ "$(git branch --show-current)" = main ] || die "not on main"
[ -z "$(git status --porcelain)" ] || die "the checkout has local changes; commit and push first"
git fetch -q origin main
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] || die "local main differs from origin/main; push or pull first"
VERSION=$(git describe --tags --always --dirty)
echo "shipping $VERSION"

say "Testing and building"
# What `make check` and `make dist` do, without needing make (none on Windows).
go vet ./... && GOOS=windows GOARCH=amd64 go vet ./... && go test ./... >/dev/null || die "vet or tests failed"
LDFLAGS="-s -w -X main.version=$VERSION"
LINUX_BIN=dist/mpinfra-linux-amd64
WIN_BIN=dist/mpinfra-windows-amd64.exe
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$LDFLAGS" -o "$LINUX_BIN" ./cmd/mpinfra
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$LDFLAGS" -o "$WIN_BIN" ./cmd/mpinfra
sha() { sha256sum "$1" | cut -d' ' -f1; }
LINUX_SUM=$(sha "$LINUX_BIN") WIN_SUM=$(sha "$WIN_BIN")

# --- server first, so it already knows any new report fields ---
if [ -n "$SERVER" ]; then
  say "Server ($SERVER_SSH)"
  cur=$(ssh "$SERVER_SSH" 'mpinfra version' 2>/dev/null | tr -d '\r' || true)
  if [ "$cur" = "$VERSION" ]; then
    echo "already at $VERSION"
  else
    echo "$cur -> $VERSION (asks for the sudo password)"
    # pulls origin/main, tests, builds, restarts, checks healthz, rolls back itself
    run ssh -t "$SERVER_SSH" 'sudo /update-mpinfra.sh' || die "the server update failed; no agent was touched"
  fi
fi

# --- agents ---
# Runs on the host as root, from the ssh user's staging dir: step.sh WANT BIN CFG
read -r -d '' STEP_SH <<'SH' || true
set -u
want=$1 bin=$2 cfg=$3
here=$(dirname "$0")
staged=$(dirname "$bin")/mpinfra.staged
# Verify the copy inside the root-owned agent dir: the upload sits in the ssh
# user's home, where it could still change after a check there.
install -m 700 "$here/mpinfra.new" "$staged" || exit 2
rm -f "$here/mpinfra.new"
if [ "$(sha256sum "$staged" | cut -d' ' -f1)" != "$want" ]; then
  echo "sha256 mismatch: not installed"; rm -f "$staged"; exit 3
fi
if ! "$staged" check -config "$cfg" >/dev/null 2>&1; then
  echo "the new binary fails 'check' with this host's config: not installed"; rm -f "$staged"; exit 4
fi
old=$("$bin" version 2>/dev/null || echo none)
cp -p "$bin" "$bin.prev"
chmod 755 "$staged"
mv -f "$staged" "$bin"
for try in 1 2; do
  if err=$("$bin" report -config "$cfg" 2>&1); then
    echo "OK $old -> $("$bin" version)"; exit 0
  fi
  case $err in *"Too Many Requests"*) [ "$try" = 1 ] && { sleep 35; continue; } ;; esac
  break
done
echo "the report failed: $(printf %s "$err" | head -c 300)"
cp -p "$bin.prev" "$bin" && echo "rolled back to $old"
exit 5
SH

deploy_unix() { # target bin cfg
  local target=$1 bin=$2 cfg=$3 sudo=sudo tty=
  if [ -n "$DRY" ]; then printf '  would copy %s, check sha256 %s, test, install to %s\n' "$LINUX_BIN" "${LINUX_SUM:0:12}" "$bin"; return 0; fi
  # Last line only: a login profile may print first (p4-main's p4 login does).
  [ "$(ssh "$target" 'id -u' | tr -d '\r' | tail -n 1)" = 0 ] && sudo= || tty=-t
  ssh "$target" 'mkdir -p -m 700 .mpinfra-deploy && cat > .mpinfra-deploy/step.sh' <<<"$STEP_SH"
  scp -q "$LINUX_BIN" "$target:.mpinfra-deploy/mpinfra.new"
  local rc=0
  ssh $tty "$target" "$sudo sh \"\$HOME/.mpinfra-deploy/step.sh\" $LINUX_SUM '$bin' '$cfg'" || rc=$?
  ssh "$target" 'rm -f .mpinfra-deploy/step.sh .mpinfra-deploy/mpinfra.new; rmdir .mpinfra-deploy' 2>/dev/null || true
  return $rc
}

deploy_windows() { # target bin cfg
  local target=$1 bin=$2 cfg=$3 dir script
  dir=${bin%\\*}
  if [ -n "$DRY" ]; then printf '  would copy %s, check sha256 %s, test, install to %s\n' "$WIN_BIN" "${WIN_SUM:0:12}" "$bin"; return 0; fi
  # -O: legacy scp; Win32-OpenSSH often has no working sftp subsystem.
  scp -O -q "$WIN_BIN" "$target:${dir//\\//}/mpinfra.staged.exe"
  script=$(cat <<PS
# Not 'Stop': in PowerShell 5.1 a native program's stderr would then throw.
# File operations that must not half-fail carry -ErrorAction Stop instead.
\$ErrorActionPreference = 'Continue'
\$ProgressPreference = 'SilentlyContinue'   # else ssh shows CLIXML progress records
\$bin = '$bin'; \$cfg = '$cfg'; \$staged = '$dir\\mpinfra.staged.exe'
if ((Get-FileHash \$staged -Algorithm SHA256).Hash -ne '$WIN_SUM'.ToUpper()) { Remove-Item \$staged; 'sha256 mismatch: not installed'; exit 3 }
& \$staged check -config \$cfg *> \$null
if (\$LASTEXITCODE -ne 0) { Remove-Item \$staged; "the new binary fails 'check' with this host's config: not installed"; exit 4 }
# Wait out a scheduled report that is running right now.
for (\$i = 0; \$i -lt 60 -and (Get-ScheduledTask -TaskName 'mp-infra-report').State -eq 'Running'; \$i++) { Start-Sleep 2 }
\$old = & \$bin version
Copy-Item \$bin "\$bin.prev" -Force -ErrorAction Stop
Move-Item \$staged \$bin -Force -ErrorAction Stop
foreach (\$try in 1, 2) {
  \$err = & \$bin report -config \$cfg 2>&1 | Out-String
  if (\$LASTEXITCODE -eq 0) { "OK \$old -> \$(& \$bin version)"; exit 0 }
  if (\$try -eq 1 -and \$err -match 'Too Many Requests') { Start-Sleep 35 } else { break }
}
"the report failed: " + \$err.Substring(0, [Math]::Min(300, \$err.Length))
Copy-Item "\$bin.prev" \$bin -Force; "rolled back to \$old"
exit 5
PS
)
  ssh "$target" "powershell -NoProfile -NonInteractive -EncodedCommand $(printf '%s' "$script" | ps_encode)"
}

declare -a RESULTS
FAILED=
# The host list is read on fd 3, so ssh and sudo keep the terminal on stdin.
while read -r name target os bin cfg <&3; do
  case $name in ''|'#'*) continue ;; esac
  if [ ${#ONLY[@]} -gt 0 ] && ! printf '%s\n' "${ONLY[@]}" | grep -qx "$name"; then continue; fi
  say "Agent $name (ssh $target, $os)"
  case $os in
    linux|dsm) f=deploy_unix ;;
    windows) f=deploy_windows ;;
    *) RESULTS+=("FAIL  $name   unknown os '$os'"); FAILED=1; continue ;;
  esac
  if out=$("$f" "$target" "$bin" "$cfg" 2>&1 | tee /dev/stderr); then
    RESULTS+=("OK    $name")
  else
    case $out in *"rolled back"*) RESULTS+=("BACK  $name   rolled back, see above") ;; *) RESULTS+=("FAIL  $name   see above") ;; esac
    FAILED=1
  fi
done 3< "$HOSTS_FILE"

say "Done ($VERSION)"
printf '%s\n' "${RESULTS[@]}"
[ -z "$FAILED" ]
