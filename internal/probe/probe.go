// Package probe runs the server-side checks: reachability, certificates, DNS, the
// public port scan, the Tailscale, Jenkins, DigitalOcean, Notion and Cloudflare APIs, and the
// vendors' security notices (notices.go). All
// of them only read, except the monthly break-glass status build (see jenkins.go).
package probe

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/eval"
)

// Check is one probe result, filed under Host.
type Check struct {
	Host    string
	ID      string
	State   eval.State
	Summary string
	Data    any
}

// KV persists small bits of probe state across restarts.
type KV interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string) error
}

// Prober runs all configured probes.
type Prober struct {
	cfg    *config.Server
	kv     KV
	client *http.Client
	now    func() time.Time
	roots  *x509.CertPool // nil = system roots; set in tests

	mu             sync.Mutex
	tsToken        string
	tsTokenExpiry  time.Time
	jenkinsOffline map[string]time.Time
	notices        map[string]noticeCache // by check id, see cachedNotices
	ucWarnings     []ucWarning            // Jenkins update-centre warnings
	ucAt           time.Time
}

// New returns a Prober. kv may be nil, which disables the break-glass trigger.
func New(cfg *config.Server, kv KV) *Prober {
	return &Prober{
		cfg: cfg,
		kv:  kv,
		client: &http.Client{
			Timeout: 20 * time.Second,
			// Never follow redirects: a probe reports what the target says, and a
			// token must not be forwarded to another host.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		now:            time.Now,
		jenkinsOffline: map[string]time.Time{},
		notices:        map[string]noticeCache{},
	}
}

// Run runs every probe concurrently and returns all results.
func (p *Prober) Run(ctx context.Context) []Check {
	probes := []func(context.Context) []Check{
		p.tcpChecks, p.httpChecks, p.tlsChecks, p.dnsChecks, p.portChecks,
		p.tailscaleChecks, p.jenkinsChecks, p.snapshotChecks, p.notionChecks,
		p.noticeChecks, p.tunnelChecks,
	}
	var mu sync.Mutex
	var out []Check
	var wg sync.WaitGroup
	for _, f := range probes {
		wg.Add(1)
		go func(f func(context.Context) []Check) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					mu.Lock()
					out = append(out, Check{Host: config.ServeHost, ID: "serve.probe_panic", State: eval.Crit, Summary: fmt.Sprint("probe panicked: ", r)})
					mu.Unlock()
				}
			}()
			res := f(ctx)
			mu.Lock()
			out = append(out, res...)
			mu.Unlock()
		}(f)
	}
	wg.Wait()
	return out
}

// hostFor files a check under host when it is configured, else under serve.
func (p *Prober) hostFor(host string) string {
	if host != "" && p.cfg.HasHost(host) {
		return host
	}
	return config.ServeHost
}

// getJSON performs req and decodes a JSON response of at most 8 MB.
func (p *Prober) doJSON(req *http.Request, v any) error {
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s %s: %s", req.Method, redact(req.URL.String()), resp.Status)
	}
	if v == nil {
		return nil
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("%s: %w", redact(req.URL.String()), err)
	}
	return nil
}

// redact drops the query string from a URL for error messages.
func redact(u string) string {
	if i := strings.IndexByte(u, '?'); i >= 0 {
		return u[:i]
	}
	return u
}

func days(d time.Duration) float64 { return d.Hours() / 24 }

// errCheck turns a probe failure into a check.
func errCheck(host, id string, state eval.State, err error) Check {
	return Check{Host: host, ID: id, State: state, Summary: clip(err.Error(), 300)}
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && (s[n]&0xC0) == 0x80 {
		n--
	}
	return s[:n]
}
