# Plan: track Defender removing the agent (2026-10-26)

Approved by Marcus. Read `CLAUDE.md`, `AGENTS.md` and `docs/spec.md` first.

## Why

On 2026-10-25 at 21:24Z, Microsoft Defender on jenkins-win flagged `C:\ProgramData\mp-infra\mpinfra.exe`
as `Trojan:Win32/Bearfoos.A!ml` (an ML heuristic false positive on the unsigned Go binary). It quarantined
the exe and the `mp-infra-report` scheduled task. The server only showed "no report for 9h" and 7 stale
checks, while `ts.online.jenkins-win` stayed "connected". Nothing said *why*.

## Work

- [ ] **A. Stale hint (server).** In `Server.Sweep` (`internal/server/server.go` ~500-505), read
  `s.Store.Check(ctx, h.Name, "ts.online."+h.Name)`. If it is ok, append
  `"; online on tailnet, agent stopped or removed"` (plus `" (check Defender)"` when the host os is `windows`)
  to the report.fresh summary. Slack/email already append the summary (`internal/alert/format.go` `slackLine`),
  so the format stays the same. Endpoint hosts have no ts.online, so they never get the hint.
  Also: the stale `PutCheck` currently replaces report.fresh data with `{}`. Keep the previous `agent_version`.
- [ ] **B. Defender check (agent, Windows only).** New check `av.defender.<host>` (avoid reserved prefixes,
  `internal/eval/eval.go:107-112`). Collector in `internal/report/windows.go`, script + platform-neutral parser
  in `win_parse.go`, following `tailscaleServiceScript` / `evalTailscaleService`. Use `powershell()`
  (EncodedCommand, which is required on jenkins-win).
  - Script: `Get-MpThreatDetection` from the last 7 days (time, threat name via `Get-MpThreat`, resources, action success)
    and `Get-MpComputerStatus` (RealTimeProtectionEnabled, AntivirusSignatureLastUpdated, IsTamperProtected),
    then `ConvertTo-Json -Compress`.
  - State: **crit** on any detection in the window. The summary names the threat and file, and says so when the
    resource is the agent's own exe ("Defender quarantined the mp-infra agent"). **warn** if RTP is off or
    signatures are more than 3 days old. Clip strings and cap lists at 50, as the other parsers do.
  - Config: `windows.defender` in `WindowsChecks` (`internal/config/config.go` ~780), default on in `LoadAgent`.
    Update `examples/agent-jenkins-win.yaml`.
- [ ] **C. Workstations.** Extend the existing `endpoint.av` facts (`internal/server/endpoint.go`, the `defender`
  struct ~121) with an optional `detections` (count + names, last 7 days), crit when > 0. Do not add a new id:
  the allow-list `EndpointCheckAllowed` stays the same. The Launcher side (`endpoint_security.py`, in P4,
  not this repo) is out of scope.
- [ ] **Tests.** Sweep: hint when ts.online is ok, no hint when it is crit, no hint for endpoint hosts, version kept.
  Parser: detection, none, RTP off, old signatures, own-exe detection. Use inline JSON in the tests, as
  `TestTailscaleService` does. **Do not invent `testdata/` captures** (AGENTS.md rule 1). Marcus will add a real
  `win_defender.json` capture later. `go test ./...` and `GOOS=windows GOARCH=amd64 go vet ./...`.
- [ ] **Docs.** Add rows to the check tables in `docs/spec.md` (~120-160).

## Not for a cloud session

These need TACCO-PC (tailnet + ssh keys) and Marcus:
- restore the quarantined agent on jenkins-win and add a file exclusion for `mpinfra.exe` + `mpinfra.staged.exe`
- `scripts/deploy.sh` (server + jenkins-win)
- the real `testdata/win_defender.json` capture
- verify: jenkins-win report.fresh ok, and `av.defender.jenkins-win` crit showing the 10/25 detection

Deliver A-C as a PR against main.
