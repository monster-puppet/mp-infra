package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// DefaultTailscaleSocket is tailscaled's LocalAPI socket on Linux.
const DefaultTailscaleSocket = "/var/run/tailscale/tailscaled.sock"

// TailscaleWhois asks the local tailscaled who is behind a tailnet address.
// Answers are cached per IP for five minutes.
type TailscaleWhois struct {
	client *http.Client

	mu    sync.Mutex
	cache map[string]whoisEntry
}

type whoisEntry struct {
	name string
	at   time.Time
}

// NewTailscaleWhois talks to tailscaled over the unix socket at path.
func NewTailscaleWhois(path string) *TailscaleWhois {
	return &TailscaleWhois{
		client: &http.Client{
			Timeout: 2 * time.Second,
			Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", path)
			}},
		},
		cache: map[string]whoisEntry{},
	}
}

func (t *TailscaleWhois) Whois(ctx context.Context, remoteAddr string) string {
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	if p := net.ParseIP(ip); p != nil && p.IsLoopback() {
		return "local"
	}
	t.mu.Lock()
	if e, ok := t.cache[ip]; ok && time.Since(e.at) < 5*time.Minute {
		t.mu.Unlock()
		return e.name
	}
	t.mu.Unlock()
	name, err := t.lookup(ctx, remoteAddr)
	if err != nil {
		return ip
	}
	t.mu.Lock()
	t.cache[ip] = whoisEntry{name, time.Now()}
	t.mu.Unlock()
	return name
}

func (t *TailscaleWhois) lookup(ctx context.Context, addr string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://local-tailscaled.sock/localapi/v0/whois?addr="+url.QueryEscape(addr), nil)
	if err != nil {
		return "", err
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("whois: %s", resp.Status)
	}
	var w struct {
		UserProfile struct {
			LoginName   string `json:"LoginName"`
			DisplayName string `json:"DisplayName"`
		} `json:"UserProfile"`
		Node struct {
			ComputedName string `json:"ComputedName"`
			Name         string `json:"Name"`
		} `json:"Node"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&w); err != nil {
		return "", err
	}
	switch {
	case w.UserProfile.LoginName != "" && w.UserProfile.LoginName != "tagged-devices":
		return w.UserProfile.LoginName, nil
	case w.Node.ComputedName != "":
		return w.Node.ComputedName, nil
	}
	return w.Node.Name, nil
}
