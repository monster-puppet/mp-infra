package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/eval"
)

const dialTimeout = 5 * time.Second

func (p *Prober) tcpChecks(ctx context.Context) []Check {
	var out []Check
	for _, t := range p.cfg.TCP {
		id := "tcp." + t.Name
		start := p.now()
		d := net.Dialer{Timeout: dialTimeout}
		conn, err := d.DialContext(ctx, "tcp", t.Addr)
		if err != nil {
			out = append(out, errCheck(config.ServeHost, id, eval.Crit, err))
			continue
		}
		conn.Close()
		rtt := p.now().Sub(start)
		out = append(out, Check{Host: config.ServeHost, ID: id, State: eval.OK,
			Summary: fmt.Sprintf("%s reachable in %d ms", t.Addr, rtt.Milliseconds()),
			Data:    map[string]any{"addr": t.Addr, "rtt_ms": rtt.Milliseconds()}})
	}
	return out
}

func (p *Prober) httpChecks(ctx context.Context) []Check {
	var out []Check
	for _, t := range p.cfg.HTTP {
		id := "http." + t.Name
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.URL, nil)
		if err != nil {
			out = append(out, errCheck(config.ServeHost, id, eval.Crit, err))
			continue
		}
		start := p.now()
		resp, err := p.client.Do(req)
		if err != nil {
			out = append(out, errCheck(config.ServeHost, id, eval.Crit, err))
			continue
		}
		var body []byte
		if t.Contains != "" {
			body, _ = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		}
		resp.Body.Close()
		rtt := p.now().Sub(start)
		ok := resp.StatusCode < 400
		if t.Status != 0 {
			ok = resp.StatusCode == t.Status
		}
		loc := resp.Header.Get("Location")
		data := map[string]any{"url": t.URL, "status": resp.StatusCode, "rtt_ms": rtt.Milliseconds()}
		if loc != "" {
			data["location"] = clip(loc, 200)
		}
		c := Check{Host: config.ServeHost, ID: id, State: eval.OK, Data: data,
			Summary: fmt.Sprintf("%s in %d ms", resp.Status, rtt.Milliseconds())}
		switch {
		case !ok:
			c.State, c.Summary = eval.Crit, "unexpected "+c.Summary
		case t.Location != "" && !strings.HasPrefix(loc, t.Location):
			c.State, c.Summary = eval.Crit, fmt.Sprintf("%s redirects to %q, not %s", resp.Status, clip(loc, 100), t.Location)
		case t.Contains != "" && !bytes.Contains(body, []byte(t.Contains)):
			c.State, c.Summary = eval.Crit, fmt.Sprintf("%s but the page lacks %q", resp.Status, t.Contains)
		case t.Location != "":
			c.Summary = fmt.Sprintf("%s to %s in %d ms", resp.Status, clip(loc, 100), rtt.Milliseconds())
		}
		out = append(out, c)
	}
	return out
}

func (p *Prober) tlsChecks(ctx context.Context) []Check {
	var out []Check
	for _, t := range p.cfg.TLS {
		out = append(out, p.tlsCheck(ctx, t))
	}
	return out
}

func (p *Prober) tlsCheck(ctx context.Context, t config.TLSTarget) Check {
	id := "tls." + t.Name
	u, err := url.Parse(t.URL)
	if err != nil || u.Hostname() == "" {
		return errCheck(config.ServeHost, id, eval.Crit, fmt.Errorf("bad url %q", t.URL))
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: dialTimeout}, Config: &tls.Config{ServerName: u.Hostname(), RootCAs: p.roots}}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(u.Hostname(), port))
	if err != nil {
		// An expired or untrusted certificate fails the handshake: that is crit too.
		return errCheck(config.ServeHost, id, eval.Crit, err)
	}
	defer conn.Close()
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return errCheck(config.ServeHost, id, eval.Crit, fmt.Errorf("no certificate"))
	}
	leaf := certs[0]
	left := days(leaf.NotAfter.Sub(p.now()))
	th := p.cfg.Thresholds
	return Check{Host: config.ServeHost, ID: id, State: eval.Lower(left, th.TLSWarnDays, th.TLSCritDays),
		Summary: fmt.Sprintf("certificate expires in %.0f days (%s)", left, leaf.NotAfter.UTC().Format("2006-01-02")),
		Data: map[string]any{"subject": leaf.Subject.CommonName, "issuer": leaf.Issuer.CommonName,
			"not_after": leaf.NotAfter.UTC().Format(time.RFC3339), "days_left": left, "dns_names": leaf.DNSNames}}
}

// resolver is replaced in tests.
var resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
} = net.DefaultResolver

func (p *Prober) dnsChecks(ctx context.Context) []Check {
	var out []Check
	for _, t := range p.cfg.DNS {
		id := "dns." + t.Name
		got, err := resolver.LookupHost(ctx, t.Host)
		if err != nil {
			out = append(out, errCheck(config.ServeHost, id, eval.Crit, err))
			continue
		}
		sort.Strings(got)
		want := append([]string(nil), t.Expected...)
		sort.Strings(want)
		c := Check{Host: config.ServeHost, ID: id, State: eval.OK,
			Summary: t.Host + " -> " + strings.Join(got, ", "),
			Data:    map[string]any{"host": t.Host, "got": got, "expected": want}}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			c.State = eval.Crit
			c.Summary = fmt.Sprintf("%s resolves to %s, expected %s", t.Host, strings.Join(got, ", "), strings.Join(want, ", "))
		}
		out = append(out, c)
	}
	return out
}

// dialPort is replaced in tests so the scan can run against loopback.
var dialPort = func(ctx context.Context, ip string, port int) bool {
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// portChecks connect-scans each host's public IP. Any open port that is not
// expected is crit; an expected port that is closed is warn.
func (p *Prober) portChecks(ctx context.Context) []Check {
	var out []Check
	for _, h := range p.cfg.Hosts {
		if h.PublicIP == "" {
			continue
		}
		id := "ports.public." + h.Name
		ip := net.ParseIP(h.PublicIP)
		if ip == nil {
			out = append(out, errCheck(h.Name, id, eval.Warn, fmt.Errorf("public_ip %q is not an IP", h.PublicIP)))
			continue
		}
		out = append(out, p.scan(ctx, h, ip.String(), id))
	}
	return out
}

func (p *Prober) scan(ctx context.Context, h config.Host, ip, id string) Check {
	ports := map[int]bool{}
	for _, port := range p.cfg.ScanPorts {
		ports[port] = true
	}
	expected := map[int]bool{}
	for _, port := range h.ExpectedPublicPorts {
		ports[port] = true
		expected[port] = true
	}
	var mu sync.Mutex
	var open []int
	sem := make(chan struct{}, 32)
	var wg sync.WaitGroup
	for port := range ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()
			if dialPort(ctx, ip, port) {
				mu.Lock()
				open = append(open, port)
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()
	sort.Ints(open)
	var unexpected, closed []int
	isOpen := map[int]bool{}
	for _, port := range open {
		isOpen[port] = true
		if !expected[port] {
			unexpected = append(unexpected, port)
		}
	}
	for _, port := range h.ExpectedPublicPorts {
		if !isOpen[port] {
			closed = append(closed, port)
		}
	}
	sort.Ints(closed)
	c := Check{Host: h.Name, ID: id, State: eval.OK, Summary: "open: " + ints(open),
		Data: map[string]any{"open": open, "expected": h.ExpectedPublicPorts, "unexpected": unexpected, "expected_closed": closed, "scanned": len(ports)}}
	switch {
	case len(unexpected) > 0:
		c.State = eval.Crit
		c.Summary = "unexpected open port(s): " + ints(unexpected)
	case len(closed) > 0:
		c.State = eval.Warn
		c.Summary = "expected port(s) closed: " + ints(closed)
	}
	return c
}

func ints(v []int) string {
	if len(v) == 0 {
		return "none"
	}
	s := make([]string, len(v))
	for i, n := range v {
		s[i] = strconv.Itoa(n)
	}
	return strings.Join(s, ", ")
}
