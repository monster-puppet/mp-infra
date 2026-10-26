package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/eval"
	"github.com/monster-puppet/mp-infra/internal/probe"
	"github.com/monster-puppet/mp-infra/internal/report"
	"github.com/monster-puppet/mp-infra/internal/store"
)

// Endpoint hosts are workstations that report through the MP Launcher. The
// launcher is shared through Perforce and cannot hold a secret, so the report
// API identifies them by their Tailscale address instead of a token, and they may
// only send the checks below. The client sends raw facts with state ok; the
// rules here decide the state, so thresholds change without touching clients.

// tsDevices returns the device list from the last ts.devices probe.
func (s *Server) tsDevices(ctx context.Context) ([]probe.TSDevice, error) {
	c, err := s.Store.Check(ctx, config.ServeHost, "ts.devices")
	if err != nil || c == nil {
		return nil, err
	}
	var data struct {
		Devices []probe.TSDevice `json:"devices"`
	}
	if json.Unmarshal([]byte(c.Data), &data) != nil {
		return nil, nil
	}
	return data.Devices, nil
}

// EndpointHost returns the endpoint host whose tailnet device has address a.
// It refuses when no device or more than one device claims that host, so a
// second machine renamed to an endpoint's hostname cannot report for it.
func (s *Server) EndpointHost(ctx context.Context, a netip.Addr) (string, bool) {
	a = a.Unmap()
	if !tailnetRange.Contains(a) {
		return "", false
	}
	devices, err := s.tsDevices(ctx)
	if err != nil {
		return "", false
	}
	host, claims := "", map[string]int{}
	for _, d := range devices {
		if d.Host != "" {
			claims[d.Host]++
		}
		if da, err := netip.ParseAddr(d.Addr); err == nil && da.Unmap() == a {
			host = d.Host
		}
	}
	if host == "" || claims[host] != 1 || !s.Cfg.IsEndpoint(host) {
		return "", false
	}
	return host, true
}

// tailnetRange is Tailscale's IPv4 range (CGNAT).
var tailnetRange = netip.MustParsePrefix("100.64.0.0/10")

// EndpointCheckAllowed reports whether an endpoint host may send check id.
func EndpointCheckAllowed(id string) bool {
	return strings.HasPrefix(id, "endpoint.") || strings.HasPrefix(id, "os.security_updates.")
}

// endpointFacts is the data of every endpoint.* check: the facts for that check
// plus Error when the launcher could not read them.
type endpointFacts struct {
	Error string `json:"error"`

	// endpoint.bitlocker: the Shell's System.Volume.BitLockerProtection of the
	// system drive. 1 on, 2 off, 3 encrypting, 4 decrypting, 5 suspended,
	// 6 on and locked, 0 not encryptable.
	Protection *int `json:"protection"`

	// endpoint.av
	Products []avProduct `json:"products"`
	Defender *defender   `json:"defender"`

	// endpoint.firewall
	Profiles         map[string]bool `json:"profiles"`
	FirewallProducts []string        `json:"firewall_products"`

	// endpoint.boot
	SecureBoot *int   `json:"secure_boot"` // UEFISecureBootEnabled, absent on BIOS machines
	TPMPresent *bool  `json:"tpm_present"`
	TPMVersion string `json:"tpm_version"`

	// endpoint.screenlock
	PolicySecs  *int `json:"policy_secs"` // machine inactivity limit (InactivityTimeoutSecs)
	SaverActive bool `json:"saver_active"`
	SaverSecure bool `json:"saver_secure"`
	SaverSecs   *int `json:"saver_secs"`

	// endpoint.os
	Build         int    `json:"build"`
	UBR           int    `json:"ubr"`
	Edition       string `json:"edition"`
	LastUpdate    string `json:"last_update"` // YYYY-MM-DD of the newest installed update
	RebootPending bool   `json:"reboot_pending"`
}

type avProduct struct {
	Name  string `json:"name"`
	State int64  `json:"state"` // SecurityCenter2 productState
}

// enabled and upToDate decode productState: bits 12-15 are the scanner (1 on),
// bits 4-7 the signatures (0 up to date).
func (p avProduct) enabled() bool  { return (p.State>>12)&0xF == 1 }
func (p avProduct) upToDate() bool { return (p.State>>4)&0xF == 0 }

type defender struct {
	Mode       string   `json:"mode"` // AMRunningMode: Normal, Passive, ...
	RTP        bool     `json:"rtp"`
	Tamper     bool     `json:"tamper"`
	SigAgeDays *float64 `json:"sig_age_days"`
	// Detections in the last 7 days, absent from launchers that predate it.
	Detections *detections `json:"detections"`
}

type detections struct {
	Count int      `json:"count"`
	Names []string `json:"names"`
}

// endpointRule sets the state of an endpoint.* check from its facts.
func (s *Server) endpointRule(c *store.Check, now time.Time) {
	kind, _, _ := strings.Cut(strings.TrimPrefix(c.ID, "endpoint."), ".")
	var f endpointFacts
	if err := json.Unmarshal([]byte(c.Data), &f); err != nil {
		c.State, c.Summary = eval.Warn, "facts unreadable"
		return
	}
	if f.Error != "" {
		c.State, c.Summary = eval.Warn, "launcher could not read this: "+firstLine(f.Error)
		return
	}
	th := s.Cfg.Thresholds
	var st eval.State
	var sum string
	switch kind {
	case "bitlocker":
		st, sum = bitlockerState(f.Protection)
	case "av":
		st, sum = avState(f, th.EndpointAVSigDays)
	case "firewall":
		st, sum = firewallState(f)
	case "boot":
		st, sum = bootState(f)
	case "screenlock":
		st, sum = screenLockState(f, th.EndpointScreenLockSecs)
	case "os":
		st, sum = osState(f, th.EndpointMinBuild, th.EndpointUpdateAge, now)
	default:
		st, sum = eval.Warn, "unknown endpoint check"
	}
	c.State, c.Summary = st, report.Clip(sum, report.MaxSummary)
}

// firstLine keeps the first line of a client error, short.
func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

func bitlockerState(p *int) (eval.State, string) {
	if p == nil {
		return eval.Warn, "BitLocker state unknown"
	}
	switch *p {
	case 1, 6:
		return eval.OK, "system drive encrypted (BitLocker on)"
	case 3:
		return eval.Warn, "system drive is being encrypted"
	case 2:
		return eval.Crit, "system drive not encrypted (BitLocker off)"
	case 4:
		return eval.Crit, "system drive is being decrypted"
	case 5:
		return eval.Crit, "BitLocker suspended on the system drive"
	case 0:
		return eval.Crit, "system drive cannot be encrypted"
	}
	return eval.Warn, fmt.Sprintf("BitLocker state %d unknown", *p)
}

func avState(f endpointFacts, sigDays float64) (eval.State, string) {
	var on []string
	outdated := false
	for _, p := range f.Products {
		if p.enabled() {
			on = append(on, p.Name)
			if !p.upToDate() {
				outdated = true
			}
		}
	}
	sort.Strings(on)
	if d := f.Defender; d != nil && d.Detections != nil && d.Detections.Count > 0 {
		sum := fmt.Sprintf("Defender: %d detection(s) in 7 days", d.Detections.Count)
		names := d.Detections.Names
		if len(names) > 3 {
			names = names[:3]
		}
		if len(names) > 0 {
			sum += ": " + strings.Join(names, ", ")
		}
		return eval.Crit, sum
	}
	if len(on) == 0 {
		return eval.Crit, "no antivirus enabled"
	}
	names := strings.Join(on, " + ")
	if d := f.Defender; d != nil && d.Mode == "Normal" {
		if !d.RTP {
			return eval.Crit, "Defender real-time protection off"
		}
		if d.SigAgeDays != nil && *d.SigAgeDays > sigDays {
			return eval.Warn, fmt.Sprintf("Defender signatures %.0f days old", *d.SigAgeDays)
		}
		if !d.Tamper {
			return eval.Warn, names + " on, but Defender tamper protection off"
		}
	}
	if outdated {
		return eval.Warn, names + " on, signatures out of date"
	}
	return eval.OK, names + " on and up to date"
}

func firewallState(f endpointFacts) (eval.State, string) {
	var off []string
	for name, on := range f.Profiles {
		if !on {
			off = append(off, name)
		}
	}
	sort.Strings(off)
	switch {
	case len(f.Profiles) == 0 && len(f.FirewallProducts) == 0:
		return eval.Warn, "firewall state unknown"
	case len(off) == 0:
		return eval.OK, "Windows Firewall on for all profiles"
	case len(f.FirewallProducts) > 0:
		return eval.OK, "firewall: " + strings.Join(f.FirewallProducts, " + ")
	}
	return eval.Warn, "Windows Firewall off for " + strings.Join(off, ", ")
}

func bootState(f endpointFacts) (eval.State, string) {
	var bad []string
	if f.SecureBoot == nil || *f.SecureBoot != 1 {
		bad = append(bad, "Secure Boot off")
	}
	if f.TPMPresent == nil || !*f.TPMPresent {
		bad = append(bad, "no TPM")
	} else if !strings.HasPrefix(f.TPMVersion, "2") {
		bad = append(bad, "TPM "+f.TPMVersion)
	}
	if len(bad) > 0 {
		return eval.Warn, strings.Join(bad, ", ")
	}
	return eval.OK, "Secure Boot on, TPM 2.0"
}

func screenLockState(f endpointFacts, maxSecs float64) (eval.State, string) {
	lock, how := 0, ""
	if f.PolicySecs != nil && *f.PolicySecs > 0 {
		lock, how = *f.PolicySecs, "machine inactivity limit"
	} else if f.SaverActive && f.SaverSecure && f.SaverSecs != nil && *f.SaverSecs > 0 {
		lock, how = *f.SaverSecs, "screensaver with sign-in"
	}
	if lock == 0 {
		return eval.Warn, "no automatic screen lock"
	}
	if float64(lock) > maxSecs {
		return eval.Warn, fmt.Sprintf("screen locks after %d min (%s), limit %.0f min", lock/60, how, maxSecs/60)
	}
	return eval.OK, fmt.Sprintf("screen locks after %d min (%s)", lock/60, how)
}

func osState(f endpointFacts, minBuild int, maxAge time.Duration, now time.Time) (eval.State, string) {
	ver := fmt.Sprintf("build %d.%d", f.Build, f.UBR)
	if f.Build == 0 {
		return eval.Warn, "Windows build unknown"
	}
	if f.Build < minBuild {
		return eval.Crit, fmt.Sprintf("%s is out of support (minimum %d)", ver, minBuild)
	}
	var bad []string
	if t, err := time.Parse("2006-01-02", f.LastUpdate); err != nil {
		bad = append(bad, "last update date unknown")
	} else if age := now.Sub(t); age > maxAge {
		bad = append(bad, fmt.Sprintf("no update installed for %.0f days", age.Hours()/24))
	}
	if f.RebootPending {
		bad = append(bad, "reboot pending")
	}
	if len(bad) > 0 {
		return eval.Warn, ver + ": " + strings.Join(bad, ", ")
	}
	return eval.OK, ver + ", updated " + f.LastUpdate
}
