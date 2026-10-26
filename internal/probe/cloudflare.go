package probe

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/eval"
)

// --- Cloudflare Tunnels ---

type cfTunnel struct {
	Name        string `json:"name"`
	Status      string `json:"status"` // healthy, degraded, down, inactive
	Connections []struct {
		ClientVersion string `json:"client_version"`
		ColoName      string `json:"colo_name"`
	} `json:"connections"`
}

func (p *Prober) tunnelChecks(ctx context.Context) []Check {
	cf := p.cfg.Cloudflare
	token := config.Env(cf.TokenEnv)
	if token == "" || cf.AccountID == "" {
		return nil
	}
	tunnels, err := p.cfTunnels(ctx, token)
	if err != nil {
		// Keep the configured tunnels' ids, so their checks turn warn instead of
		// quietly keeping their last state.
		if len(cf.Tunnels) == 0 {
			return []Check{errCheck(config.ServeHost, "tunnel.api", eval.Warn, err)}
		}
		var out []Check
		for name, host := range cf.Tunnels {
			out = append(out, errCheck(p.hostFor(host), "tunnel."+name, eval.Warn, err))
		}
		return out
	}
	seen := map[string]bool{}
	var out []Check
	for _, t := range tunnels {
		seen[t.Name] = true
		out = append(out, p.evalTunnel(t))
	}
	for name, host := range cf.Tunnels {
		if !seen[name] {
			out = append(out, Check{Host: p.hostFor(host), ID: "tunnel." + name, State: eval.Crit,
				Summary: "tunnel not found in the Cloudflare account"})
		}
	}
	return out
}

func (p *Prober) cfTunnels(ctx context.Context, token string) ([]cfTunnel, error) {
	cf := p.cfg.Cloudflare
	u := strings.TrimRight(cf.APIURL, "/") + "/accounts/" + url.PathEscape(cf.AccountID) +
		"/cfd_tunnel?is_deleted=false&per_page=100"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	var body struct {
		Success bool       `json:"success"`
		Result  []cfTunnel `json:"result"`
	}
	if err := p.doJSON(req, &body); err != nil {
		return nil, fmt.Errorf("cloudflare: %w", err)
	}
	if !body.Success {
		return nil, fmt.Errorf("cloudflare: request not successful")
	}
	return body.Result, nil
}

func (p *Prober) evalTunnel(t cfTunnel) Check {
	cf := p.cfg.Cloudflare
	c := Check{Host: p.hostFor(cf.Tunnels[t.Name]), ID: "tunnel." + clip(t.Name, 64), State: eval.OK}
	var versions []string
	have := map[string]bool{}
	for _, k := range t.Connections {
		if v := clip(k.ClientVersion, 32); !have[v] {
			have[v] = true
			versions = append(versions, v)
		}
	}
	sort.Slice(versions, func(i, j int) bool { return cmpVersion(versions[i], versions[j]) < 0 })
	c.Data = map[string]any{"status": t.Status, "connections": len(t.Connections), "versions": versions}

	status := clip(t.Status, 32)
	if len(t.Connections) == 0 {
		c.State = eval.Crit
		c.Summary = "no connectors (" + status + ")"
		return c
	}
	var notes []string
	switch status {
	case "healthy":
	case "degraded":
		c.State = eval.Warn
	default:
		c.State = eval.Crit
	}
	oldest := versions[0]
	if cf.MinVersion != "" && cmpVersion(oldest, cf.MinVersion) < 0 {
		c.State = eval.Crit
		notes = append(notes, "below the required "+cf.MinVersion)
	} else if when, ok := versionDate(oldest); ok {
		if age := p.now().Sub(when); age > cf.MaxAge {
			c.State = eval.Worst(c.State, eval.Warn)
			notes = append(notes, fmt.Sprintf("%.0f days old, update it", days(age)))
		}
	}
	c.Summary = fmt.Sprintf("%s, %d connection(s), cloudflared %s", status, len(t.Connections), strings.Join(versions, " + "))
	if len(notes) > 0 {
		c.Summary += ": " + oldest + " is " + strings.Join(notes, ", ")
	}
	return c
}

// cmpVersion compares dotted numeric versions (2025.10.1 < 2026.10.2). A part that
// is not a number counts as 0.
func cmpVersion(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y int
		if i < len(as) {
			x, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(bs[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// versionDate reads cloudflared's calendar version (YYYY.M.patch) as the first day
// of that month.
func versionDate(v string) (time.Time, bool) {
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return time.Time{}, false
	}
	y, err1 := strconv.Atoi(parts[0])
	m, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || y < 2017 || m < 1 || m > 12 {
		return time.Time{}, false
	}
	return time.Date(y, time.Month(m), 1, 0, 0, 0, 0, time.UTC), true
}
