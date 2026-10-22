package report

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/monster-puppet/mp-infra/internal/eval"
)

// The parsers in this file are platform-neutral so they are tested on Linux CI.
// The collectors that run them are in windows.go behind a build tag.

// powershell runs a script with -EncodedCommand (base64 UTF-16LE). Multi-line
// scripts passed any other way can silently do nothing on jenkins-win.
func powershell(ctx context.Context, script string) (string, error) {
	u := make([]byte, 0, len(script)*2)
	for _, r := range script {
		if r > 0xFFFF {
			r = '?'
		}
		u = binary.LittleEndian.AppendUint16(u, uint16(r))
	}
	return run(ctx, []string{"powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-EncodedCommand", base64.StdEncoding.EncodeToString(u)}, nil)
}

// tailscaleServiceScript prints the Tailscale service state, start mode and its
// FailureActions registry value (base64).
const tailscaleServiceScript = `$ErrorActionPreference = 'Stop'
$n = '%s'
$s = Get-CimInstance Win32_Service -Filter "Name='$n'"
if (-not $s) { '{}'; exit 0 }
$fa = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$n" -Name FailureActions -ErrorAction SilentlyContinue).FailureActions
$b = ''
if ($fa) { $b = [Convert]::ToBase64String($fa) }
[pscustomobject]@{ State = $s.State; StartMode = $s.StartMode; FailureActions = $b } | ConvertTo-Json -Compress`

type winService struct {
	State          string `json:"State"`
	StartMode      string `json:"StartMode"`
	FailureActions string `json:"FailureActions"`
}

// SC_ACTION_RESTART in a SERVICE_FAILURE_ACTIONS record.
const scActionRestart = 1

// restartsOnFailure decodes the FailureActions registry value: a 20-byte header
// (reset period, reboot message, command, action count, actions pointer) followed
// by one (type, delay) pair of uint32 per action. The first action must restart.
func restartsOnFailure(b []byte) bool {
	if len(b) < 28 {
		return false
	}
	n := binary.LittleEndian.Uint32(b[12:16])
	if n == 0 {
		return false
	}
	return binary.LittleEndian.Uint32(b[20:24]) == scActionRestart
}

func evalTailscaleService(out string) (Check, error) {
	var s winService
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &s); err != nil {
		return Check{}, fmt.Errorf("service output: %w", err)
	}
	c := Check{ID: "win.tailscale_service", State: eval.OK}
	if s.State == "" {
		c.State = eval.Crit
		c.Summary = "Tailscale service not installed"
		return c, nil
	}
	fa, _ := base64.StdEncoding.DecodeString(s.FailureActions)
	restart := restartsOnFailure(fa)
	c.Data = mustJSON(map[string]any{"state": s.State, "start_mode": s.StartMode, "restart_on_failure": restart})
	var bad []string
	if s.State != "Running" {
		bad = append(bad, "state "+s.State)
	}
	if s.StartMode != "Auto" {
		bad = append(bad, "start mode "+s.StartMode)
	}
	if !restart {
		bad = append(bad, "no restart on failure")
	}
	if len(bad) > 0 {
		c.State = eval.Crit
		c.Summary = "Tailscale service: " + strings.Join(bad, ", ")
		return c, nil
	}
	c.Summary = "Tailscale service running, automatic, restarts on failure"
	return c, nil
}

// firewallAnyScript lists enabled inbound allow rules whose remote address is Any.
const firewallAnyScript = `$ErrorActionPreference = 'Stop'
$r = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | ForEach-Object {
  $a = $_ | Get-NetFirewallAddressFilter
  if (@($a.RemoteAddress) -contains 'Any') {
    $p = $_ | Get-NetFirewallPortFilter
    [pscustomobject]@{ Name = $_.Name; DisplayName = $_.DisplayName; Protocol = [string]$p.Protocol; LocalPort = [string](@($p.LocalPort) -join ',') }
  } })
ConvertTo-Json -Compress -InputObject $r`

type winRule struct {
	Name        string `json:"Name"`
	DisplayName string `json:"DisplayName"`
	Protocol    string `json:"Protocol"`
	LocalPort   string `json:"LocalPort"`
}

func evalFirewallAny(out string, allow []string) (Check, error) {
	var rules []winRule
	if s := strings.TrimSpace(out); s != "" {
		if err := json.Unmarshal([]byte(s), &rules); err != nil {
			return Check{}, fmt.Errorf("firewall output: %w", err)
		}
	}
	ok := map[string]bool{}
	for _, a := range allow {
		ok[a] = true
	}
	var open []winRule
	for _, r := range rules {
		if !ok[r.Name] {
			r.Name, r.DisplayName = Clip(r.Name, 200), Clip(r.DisplayName, 200)
			r.Protocol, r.LocalPort = Clip(r.Protocol, 20), Clip(r.LocalPort, 200)
			open = append(open, r)
		}
	}
	sort.Slice(open, func(i, j int) bool { return open[i].Name < open[j].Name })
	if len(open) > 50 {
		open = open[:50]
	}
	c := Check{ID: "win.fw.allow_any", State: eval.OK, Summary: "no inbound allow-any rules",
		Data: mustJSON(map[string]any{"rules": open, "accepted": len(rules) - len(open)})}
	if len(open) > 0 {
		c.State = eval.Crit
		c.Summary = fmt.Sprintf("%d inbound rule(s) allow any remote address, e.g. %s", len(open), open[0].DisplayName)
	}
	return c, nil
}
