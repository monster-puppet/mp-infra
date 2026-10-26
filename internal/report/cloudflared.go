package report

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/eval"
)

// --- cloudflared.<host> ---

var (
	cfdVersion = regexp.MustCompile(`(?m)^build_info\{[^}]*\bversion="([0-9][0-9.]*)"`)
	cfdConns   = regexp.MustCompile(`(?m)^cloudflared_tunnel_ha_connections ([0-9.e+]+)$`)
)

// cloudflaredPorts are the metrics ports cloudflared picks from when none is set.
var cloudflaredPorts = []int{20241, 20242, 20243, 20244, 20245}

// fetchCloudflaredMetrics GETs the metrics page: the configured URL, else the first
// default port that answers with cloudflared's build_info.
func fetchCloudflaredMetrics(ctx context.Context, url string) (string, error) {
	client := &http.Client{Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	get := func(u string) (string, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return "", err
		}
		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("%s: %s", u, resp.Status)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		return string(b), err
	}
	if url != "" {
		return get(url)
	}
	for _, port := range cloudflaredPorts {
		if out, err := get("http://127.0.0.1:" + strconv.Itoa(port) + "/metrics"); err == nil && cfdVersion.MatchString(out) {
			return out, nil
		}
	}
	return "", fmt.Errorf("no cloudflared metrics on 127.0.0.1:20241-20245")
}

// cloudflaredCheck judges the metrics page. now dates the calendar version.
func cloudflaredCheck(id, metrics string, cfg *config.Cloudflared, now time.Time) Check {
	version := ""
	if m := cfdVersion.FindStringSubmatch(metrics); m != nil {
		version = Clip(m[1], 32)
	}
	conns := -1
	if m := cfdConns.FindStringSubmatch(metrics); m != nil {
		if f, err := strconv.ParseFloat(m[1], 64); err == nil {
			conns = int(f)
		}
	}
	data := map[string]any{"version": version, "connections": conns}
	c := Check{ID: id, State: eval.OK, Data: mustJSON(data)}
	if version == "" {
		c.State, c.Summary = eval.Crit, "cloudflared metrics have no version (not cloudflared?)"
		return c
	}
	c.Summary = fmt.Sprintf("cloudflared %s, %d tunnel connection(s)", version, conns)
	var notes []string
	if conns <= 0 {
		c.State = eval.Crit
		notes = append(notes, "the tunnel is down")
	}
	if cfg.MinVersion != "" && cmpVersion(version, cfg.MinVersion) < 0 {
		c.State = eval.Crit
		notes = append(notes, "below the required "+cfg.MinVersion)
	} else if when, ok := versionDate(version); ok {
		if age := now.Sub(when).Hours() / 24; age > cfg.MaxAgeDays {
			c.State = eval.Worst(c.State, eval.Warn)
			notes = append(notes, fmt.Sprintf("version %.0f days old, update it", age))
		}
	}
	if len(notes) > 0 {
		c.Summary += ": " + strings.Join(notes, ", ")
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
