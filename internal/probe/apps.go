package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/eval"
)

// unboundPort finds the port in exe.dev's "app not running" page: when nothing
// listens on the VM's port, the proxy answers "Port 5000 unbound. We dialed port
// 5000 on this VM and nobody answered."
var unboundPort = regexp.MustCompile(`Port (\d+) unbound`)

// appChecks checks each web app: the front page, its certificate and the app's
// own health endpoint, folded into one app.<name> check.
func (p *Prober) appChecks(ctx context.Context) []Check {
	var out []Check
	for _, a := range p.cfg.Apps {
		out = append(out, p.appCheck(ctx, a))
	}
	return out
}

// appCheck GETs the front page without following redirects. Any status below
// 500 is up: many apps answer a redirect to their login page, or 401 or 403.
func (p *Prober) appCheck(ctx context.Context, a config.AppTarget) Check {
	data := map[string]any{"url": a.URL, "vm": a.VM}
	c := Check{Host: config.ServeHost, ID: "app." + a.Name, State: eval.OK, Data: data}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.URL, nil)
	if err != nil {
		c.State, c.Summary = eval.Crit, clip(err.Error(), 300)
		return c
	}
	start := p.now()
	resp, err := p.client.Do(req)
	if err != nil {
		c.State, c.Summary = eval.Crit, clip("unreachable: "+err.Error(), 300)
		// An expired or untrusted certificate fails the handshake.
		var cv *tls.CertificateVerificationError
		if errors.As(err, &cv) {
			c.Summary = clip("certificate invalid: "+cv.Err.Error(), 300)
		}
		return c
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	ms := p.now().Sub(start).Milliseconds()
	data["status"], data["rtt_ms"] = resp.StatusCode, ms

	front := fmt.Sprintf("%d in %d ms", resp.StatusCode, ms)
	if loc := resp.Header.Get("Location"); loc != "" {
		data["location"] = clip(loc, 200)
		if resp.StatusCode/100 == 3 {
			front = fmt.Sprintf("%d to %s in %d ms", resp.StatusCode, clip(loc, 100), ms)
		}
	}
	// The proxy's page is caught by its exact phrase, whatever status it comes
	// with; an app page that merely mentions "port" and "unbound" is not it.
	m := unboundPort.FindSubmatch(body)
	unbound := m != nil
	switch {
	case unbound:
		c.State, front = eval.Crit, "Port "+string(m[1])+" unbound (app not running)"
	case resp.StatusCode >= 500:
		c.State, front = eval.Crit, fmt.Sprintf("%s in %d ms", resp.Status, ms)
	case a.Contains != "" && !bytes.Contains(body, []byte(a.Contains)):
		c.State, front = eval.Crit, fmt.Sprintf("%s but the page lacks %q", front, a.Contains)
	case ms > int64(p.cfg.Thresholds.AppSlowMS):
		c.State, front = eval.Warn, front+" (slow)"
	}

	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		leaf := resp.TLS.PeerCertificates[0]
		left, st := p.certDays(leaf)
		data["cert_days"], data["cert_not_after"] = int(left), leaf.NotAfter.UTC().Format(time.RFC3339)
		c.State = eval.Worst(c.State, st)
		if !unbound {
			front += fmt.Sprintf(", cert %d days", int(left))
		}
	}

	parts := []string{front}
	if a.Health != "" && !unbound {
		hs, hsum, err := p.appHealth(ctx, req.URL, a.Health)
		problem := ""
		switch {
		case err != nil:
			hs, problem = eval.Warn, "health endpoint failed: "+err.Error()
			data["health_status"], data["health_summary"] = "error", clip(err.Error(), 200)
		default:
			data["health_status"], data["health_summary"] = string(hs), hsum
			if hs != eval.OK {
				problem = "health: " + hsum
				if hsum == "" {
					problem = "health: " + string(hs)
				}
			}
		}
		if problem != "" {
			// The worse part leads the summary.
			if hs.Severity() > c.State.Severity() {
				parts = []string{problem, front}
			} else {
				parts = append(parts, problem)
			}
			c.State = eval.Worst(c.State, hs)
		}
	}
	c.Summary = clip(strings.Join(parts, "; "), 300)
	return c
}

// appHealth reads the app's health endpoint, path on front's origin. It must
// answer {"status":"ok"|"warn"|"crit","summary":"..."}, with any HTTP status: an
// app may well say crit with a 503.
func (p *Prober) appHealth(ctx context.Context, front *url.URL, path string) (eval.State, string, error) {
	origin := url.URL{Scheme: front.Scheme, Host: front.Host}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin.String()+path, nil)
	if err != nil {
		return "", "", err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	var h struct {
		Status  string `json:"status"`
		Summary string `json:"summary"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&h); err != nil {
		return "", "", fmt.Errorf("%s, not JSON", resp.Status)
	}
	switch s := eval.State(h.Status); s {
	case eval.OK, eval.Warn, eval.Crit:
		return s, clip(strings.TrimSpace(h.Summary), 200), nil
	}
	return "", "", fmt.Errorf("unknown status %q", clip(h.Status, 20))
}
