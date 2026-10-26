package report

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

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

// defenderScript prints Defender's detections from the last 7 days, newest first,
// and its protection status. On 2026-10-25 it quarantined the agent itself on
// jenkins-win, and the server only saw the reports stop.
const defenderScript = `$ErrorActionPreference = 'Stop'
$since = (Get-Date).AddDays(-7)
$names = @{}
Get-MpThreat | ForEach-Object { $names[[string]$_.ThreatID] = [string]$_.ThreatName }
$d = @(Get-MpThreatDetection | Where-Object { $_.InitialDetectionTime -ge $since } |
  Sort-Object InitialDetectionTime -Descending | Select-Object -First 50 | ForEach-Object {
  [pscustomobject]@{ Time = $_.InitialDetectionTime.ToUniversalTime().ToString('o'); Threat = $names[[string]$_.ThreatID]
    Resources = @($_.Resources | ForEach-Object { [string]$_ }); ActionSuccess = [bool]$_.ActionSuccess } })
$s = Get-MpComputerStatus
$sig = ''
if ($s.AntivirusSignatureLastUpdated) { $sig = $s.AntivirusSignatureLastUpdated.ToUniversalTime().ToString('o') }
[pscustomobject]@{ Detections = $d; RealTimeProtectionEnabled = [bool]$s.RealTimeProtectionEnabled
  AntivirusSignatureLastUpdated = $sig; IsTamperProtected = [bool]$s.IsTamperProtected } | ConvertTo-Json -Compress -Depth 4`

// jsonList decodes a JSON array, a single value or null: ConvertTo-Json in
// Windows PowerShell can flatten a one-element array.
type jsonList[T any] []T

func (l *jsonList[T]) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "null" {
		*l = nil
		return nil
	}
	if strings.HasPrefix(s, "[") {
		return json.Unmarshal(b, (*[]T)(l))
	}
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*l = jsonList[T]{v}
	return nil
}

type winDetection struct {
	Time          string           `json:"Time"`
	Threat        string           `json:"Threat"`
	Resources     jsonList[string] `json:"Resources"`
	ActionSuccess bool             `json:"ActionSuccess"`
}

type winDefender struct {
	Detections jsonList[winDetection] `json:"Detections"`
	RTP        bool                   `json:"RealTimeProtectionEnabled"`
	SigUpdated string                 `json:"AntivirusSignatureLastUpdated"`
	Tamper     bool                   `json:"IsTamperProtected"`
}

// defenderSigMaxAge is the signature age at which av.defender warns.
const defenderSigMaxAge = 3 * 24 * time.Hour

// agentFiles are the last path segments of what Defender removes when it takes
// the agent: the exe, the copy deploy.sh stages, and the scheduled task.
var agentFiles = map[string]bool{"mpinfra.exe": true, "mpinfra.staged.exe": true, "mp-infra-report": true}

// detectionPath drops the "file:_" style prefix Defender puts on a resource.
func detectionPath(r string) string {
	if i := strings.Index(r, ":_"); i > 0 && i < 20 {
		return r[i+2:]
	}
	return r
}

func isAgentResource(r string) bool {
	p := strings.ToLower(detectionPath(r))
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		p = p[i+1:]
	}
	return agentFiles[p]
}

func evalDefender(id, out string, now time.Time) (Check, error) {
	var d winDefender
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &d); err != nil {
		return Check{}, fmt.Errorf("defender output: %w", err)
	}
	type detection struct {
		Time      string   `json:"time"`
		Threat    string   `json:"threat"`
		Resources []string `json:"resources"`
		Removed   bool     `json:"action_success"`
	}
	var dets []detection
	agent := -1
	for _, x := range d.Detections {
		if len(dets) == 50 {
			break
		}
		det := detection{Time: Clip(x.Time, 40), Threat: Clip(x.Threat, 200), Removed: x.ActionSuccess}
		for _, r := range x.Resources {
			if len(det.Resources) == 50 {
				break
			}
			det.Resources = append(det.Resources, Clip(r, 300))
			if agent < 0 && isAgentResource(r) {
				agent = len(dets)
			}
		}
		dets = append(dets, det)
	}
	sig, sigErr := time.Parse(time.RFC3339Nano, d.SigUpdated)
	data := map[string]any{"detections": dets, "rtp": d.RTP, "tamper_protected": d.Tamper}
	if sigErr == nil {
		data["signatures_updated"] = sig.UTC()
	}
	c := Check{ID: id, State: eval.OK, Data: mustJSON(data)}
	switch {
	case len(dets) > 0:
		c.State = eval.Crit
		x := dets[0]
		if agent >= 0 {
			x = dets[agent]
		}
		what := x.Threat
		if what == "" {
			what = "unknown threat"
		}
		if len(x.Resources) > 0 {
			what += " in " + detectionPath(x.Resources[0])
		}
		if agent >= 0 {
			c.Summary = "Defender quarantined the mp-infra agent: " + what
		} else {
			c.Summary = fmt.Sprintf("Defender: %d detection(s) in 7 days, latest %s", len(dets), what)
		}
		if !x.Removed {
			c.Summary += " (action failed)"
		}
		c.Summary = Clip(c.Summary, MaxSummary)
	case !d.RTP:
		c.State, c.Summary = eval.Warn, "Defender real-time protection off"
	case sigErr != nil:
		c.State, c.Summary = eval.Warn, "Defender signature age unknown"
	case now.Sub(sig) > defenderSigMaxAge:
		c.State, c.Summary = eval.Warn, "Defender signatures "+Human(now.Sub(sig))+" old"
	default:
		c.Summary = "Defender on, signatures " + Human(now.Sub(sig)) + " old, no detections in 7 days"
	}
	return c, nil
}
