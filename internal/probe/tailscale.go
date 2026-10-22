package probe

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/eval"
)

// tsDevice is the part of a Tailscale API device we read.
type tsDevice struct {
	Hostname           string    `json:"hostname"`
	Name               string    `json:"name"`
	LastSeen           time.Time `json:"lastSeen"`
	Expires            time.Time `json:"expires"`
	KeyExpiryDisabled  bool      `json:"keyExpiryDisabled"`
	ConnectedToControl bool      `json:"connectedToControl"`
	Tags               []string  `json:"tags"`
	OS                 string    `json:"os"`
	Addresses          []string  `json:"addresses"`
	ClientConnectivity struct {
		Endpoints []string `json:"endpoints"` // "ip:port" the device was last reached on
	} `json:"clientConnectivity"`
}

// TSDevice is one tailnet device as listed in the data of ts.devices.
type TSDevice struct {
	Name      string    `json:"name"`
	OS        string    `json:"os"`
	Addr      string    `json:"addr"`
	Connected bool      `json:"connected"`
	LastSeen  time.Time `json:"last_seen"`
	Tags      []string  `json:"tags,omitempty"`
	Host      string    `json:"host,omitempty"` // the configured host this device is
	// PublicIPs are the device's public endpoint addresses, its NAT's address for a
	// laptop at home. A login from one of them is that device going around the VPN.
	PublicIPs []string `json:"public_ips,omitempty"`
}

var tsRange = netip.MustParsePrefix("100.64.0.0/10")

// publicIPs keeps the public addresses of "ip:port" endpoints, once each.
func publicIPs(endpoints []string) []string {
	var out []string
	seen := map[netip.Addr]bool{}
	for _, e := range endpoints {
		ap, err := netip.ParseAddrPort(e)
		if err != nil {
			continue
		}
		a := ap.Addr().Unmap()
		if !a.IsGlobalUnicast() || a.IsPrivate() || tsRange.Contains(a) || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a.String())
	}
	return out
}

func (p *Prober) tailscaleChecks(ctx context.Context) []Check {
	ts := p.cfg.Tailscale
	id, secret := config.Env(ts.ClientIDEnv), config.Env(ts.ClientSecretEnv)
	if id == "" || secret == "" {
		return nil
	}
	devices, err := p.tsDevices(ctx, id, secret)
	if err != nil {
		return []Check{errCheck(config.ServeHost, "ts.api", eval.Crit, err)}
	}
	out := []Check{{Host: config.ServeHost, ID: "ts.api", State: eval.OK, Summary: fmt.Sprintf("%d devices", len(devices))}}
	return append(out, p.evalTailscale(devices)...)
}

func (p *Prober) tsDevices(ctx context.Context, id, secret string) ([]tsDevice, error) {
	tok, err := p.tsAccessToken(ctx, id, secret)
	if err != nil {
		return nil, err
	}
	api := strings.TrimRight(p.cfg.Tailscale.APIURL, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		api+"/api/v2/tailnet/"+url.PathEscape(p.cfg.Tailscale.Tailnet)+"/devices?fields=all", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	var body struct {
		Devices []tsDevice `json:"devices"`
	}
	if err := p.doJSON(req, &body); err != nil {
		return nil, err
	}
	return body.Devices, nil
}

// tsAccessToken exchanges the OAuth client credentials for an access token and
// caches it until shortly before it expires.
func (p *Prober) tsAccessToken(ctx context.Context, id, secret string) (string, error) {
	p.mu.Lock()
	if p.tsToken != "" && p.now().Before(p.tsTokenExpiry) {
		t := p.tsToken
		p.mu.Unlock()
		return t, nil
	}
	p.mu.Unlock()
	form := url.Values{"client_id": {id}, "client_secret": {secret}, "grant_type": {"client_credentials"}}
	api := strings.TrimRight(p.cfg.Tailscale.APIURL, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, api+"/api/v2/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := p.doJSON(req, &tok); err != nil {
		return "", fmt.Errorf("tailscale oauth: %w", err)
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("tailscale oauth: empty access token")
	}
	life := time.Duration(tok.ExpiresIn) * time.Second
	if life <= 0 {
		life = time.Hour
	}
	p.mu.Lock()
	p.tsToken, p.tsTokenExpiry = tok.AccessToken, p.now().Add(life-5*time.Minute)
	p.mu.Unlock()
	return tok.AccessToken, nil
}

// deviceName is the Tailscale hostname of a configured host.
func (p *Prober) deviceName(host string) string {
	if d, ok := p.cfg.Tailscale.Devices[host]; ok {
		return strings.ToLower(d)
	}
	return host
}

func (p *Prober) evalTailscale(devices []tsDevice) []Check {
	now := p.now()
	th := p.cfg.Thresholds
	byName := map[string]tsDevice{}
	for _, d := range devices {
		n := strings.ToLower(d.Hostname)
		if old, ok := byName[n]; !ok || d.LastSeen.After(old.LastSeen) || d.ConnectedToControl {
			byName[n] = d
		}
	}
	var out []Check
	known := map[string]bool{}
	hostOf := map[string]string{}
	for _, h := range p.cfg.Hosts {
		if h.NotOnTailnet {
			continue
		}
		name := p.deviceName(h.Name)
		known[name] = true
		hostOf[name] = h.Name
		d, ok := byName[name]
		if !ok {
			out = append(out,
				Check{Host: h.Name, ID: "ts.online." + h.Name, State: eval.Crit, Summary: "device " + name + " not on the tailnet"},
				Check{Host: h.Name, ID: "ts.key_expiry." + h.Name, State: eval.Crit, Summary: "device " + name + " not on the tailnet"})
			continue
		}
		var age time.Duration
		if !d.ConnectedToControl {
			age = now.Sub(d.LastSeen)
		}
		online := Check{Host: h.Name, ID: "ts.online." + h.Name, State: eval.OK, Summary: "connected",
			Data: map[string]any{"device": d.Name, "last_seen": d.LastSeen, "connected": d.ConnectedToControl}}
		switch {
		case age >= th.TSOnlineCrit:
			online.State = eval.Crit
		case age >= th.TSOnlineWarn:
			online.State = eval.Warn
		}
		if !d.ConnectedToControl {
			online.Summary = "last seen " + humanAgo(age)
		}
		out = append(out, online)

		key := Check{Host: h.Name, ID: "ts.key_expiry." + h.Name, State: eval.OK, Summary: "key expiry disabled",
			Data: map[string]any{"key_expiry_disabled": d.KeyExpiryDisabled, "expires": d.Expires}}
		if !d.KeyExpiryDisabled {
			left := days(d.Expires.Sub(now))
			key.State = eval.Crit
			key.Summary = fmt.Sprintf("key expiry enabled, expires in %.0f days", left)
			if left < th.TSKeyExpiryDays {
				key.Summary = fmt.Sprintf("key expires in %.1f days", left)
			}
		}
		out = append(out, key)
	}
	for _, e := range p.cfg.Tailscale.ExpectedDevices {
		known[strings.ToLower(e)] = true
	}
	var unknown, unseen []string
	list := make([]TSDevice, 0, len(devices))
	for _, d := range devices {
		n := strings.ToLower(d.Hostname)
		td := TSDevice{Name: d.Hostname, OS: d.OS, Connected: d.ConnectedToControl, LastSeen: d.LastSeen, Tags: d.Tags, Host: hostOf[n],
			PublicIPs: publicIPs(d.ClientConnectivity.Endpoints)}
		if len(d.Addresses) > 0 {
			td.Addr = d.Addresses[0]
		}
		list = append(list, td)
		if !known[n] {
			unknown = append(unknown, d.Hostname)
		}
		if !d.ConnectedToControl && days(now.Sub(d.LastSeen)) > th.TSDeviceUnseenDays {
			unseen = append(unseen, d.Hostname)
		}
	}
	sort.Strings(unknown)
	sort.Strings(unseen)
	dev := Check{Host: config.ServeHost, ID: "ts.devices", State: eval.OK,
		Summary: fmt.Sprintf("%d devices, all expected", len(devices)),
		Data:    map[string]any{"count": len(devices), "unexpected": unknown, "unseen": unseen, "devices": list}}
	if len(unknown)+len(unseen) > 0 {
		dev.State = eval.Warn
		var parts []string
		if len(unknown) > 0 {
			parts = append(parts, fmt.Sprintf("%d unexpected (%s)", len(unknown), strings.Join(unknown, ", ")))
		}
		if len(unseen) > 0 {
			parts = append(parts, fmt.Sprintf("%d not seen for %.0f days (%s)", len(unseen), th.TSDeviceUnseenDays, strings.Join(unseen, ", ")))
		}
		dev.Summary = clip(strings.Join(parts, "; "), 300)
	}
	return append(out, dev)
}

func humanAgo(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%.0f days ago", days(d))
	case d >= time.Hour:
		return fmt.Sprintf("%.0f h ago", d.Hours())
	case d >= time.Minute:
		return fmt.Sprintf("%.0f min ago", d.Minutes())
	}
	return "just now"
}
