// Package config loads the server and agent YAML configs. Secrets are never stored
// in the server config itself: it names the env vars that hold them.
package config

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// HostName is the allowed shape of a host name in configs and reports.
var HostName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

var versionName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// Server is the config of `mpinfra serve`. Sections for later phases (tls, tailscale,
// jenkins, alerts) are accepted and ignored until their phase lands.
type Server struct {
	UIAddr          string        `yaml:"ui_addr"`
	ReportAddr      string        `yaml:"report_addr"`
	DB              string        `yaml:"db"`
	StaleAfter      time.Duration `yaml:"stale_after"`
	Hosts           []Host        `yaml:"hosts"`
	ReportTokensEnv string        `yaml:"report_tokens_env"`

	// BaseURL is the UI's address as viewers reach it, for links in alerts.
	BaseURL       string        `yaml:"base_url"`
	ProbeInterval time.Duration `yaml:"probe_interval"`
	// ScanPorts is the TCP port list scanned on every host's public IP.
	ScanPorts  []int        `yaml:"scan_ports"`
	Thresholds Thresholds   `yaml:"thresholds"`
	TLS        []TLSTarget  `yaml:"tls"`
	DNS        []DNSTarget  `yaml:"dns"`
	HTTP       []HTTPTarget `yaml:"http"`
	TCP        []TCPTarget  `yaml:"tcp"`
	Tailscale  Tailscale    `yaml:"tailscale"`
	Jenkins    Jenkins      `yaml:"jenkins"`
	DO         DigitalOcean `yaml:"digitalocean"`
	Notion     Notion       `yaml:"notion"`
	Alerts     Alerts       `yaml:"alerts"`
}

type Host struct {
	Name                string `yaml:"name"`
	PublicIP            string `yaml:"public_ip"`
	ExpectedPublicPorts []int  `yaml:"expected_public_ports"`
	// NotOnTailnet skips the Tailscale checks (p4-game until it joins).
	NotOnTailnet bool `yaml:"not_on_tailnet"`
	// NoReport marks a host that runs no agent, so it never goes stale.
	NoReport bool `yaml:"no_report"`
}

// Thresholds for server-side checks. Zero values take the spec defaults.
type Thresholds struct {
	TSOnlineWarn        time.Duration `yaml:"ts_online_warn"`
	TSOnlineCrit        time.Duration `yaml:"ts_online_crit"`
	TSKeyExpiryDays     float64       `yaml:"ts_key_expiry_days"`
	TSDeviceUnseenDays  float64       `yaml:"ts_device_unseen_days"`
	JenkinsOfflineGrace time.Duration `yaml:"jenkins_offline_grace"`
	BreakglassMaxAge    time.Duration `yaml:"breakglass_max_age"`
	TLSWarnDays         float64       `yaml:"tls_warn_days"`
	TLSCritDays         float64       `yaml:"tls_crit_days"`
	SnapshotWarnDays    float64       `yaml:"snapshot_warn_days"`
	SnapshotCritDays    float64       `yaml:"snapshot_crit_days"`
	UpdatesCritAge      time.Duration `yaml:"updates_crit_age"`
}

type TLSTarget struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
}

type DNSTarget struct {
	Name     string   `yaml:"name"`
	Host     string   `yaml:"host"`
	Expected []string `yaml:"expected"`
}

type HTTPTarget struct {
	Name   string `yaml:"name"`
	URL    string `yaml:"url"`
	Status int    `yaml:"status"` // expected status; 0 means any 2xx/3xx
}

type TCPTarget struct {
	Name string `yaml:"name"`
	Addr string `yaml:"addr"`
}

type Tailscale struct {
	ClientIDEnv     string `yaml:"client_id_env"`
	ClientSecretEnv string `yaml:"client_secret_env"`
	Tailnet         string `yaml:"tailnet"` // "-" = the OAuth client's tailnet
	// Devices maps a host name to its Tailscale device hostname when they differ.
	Devices map[string]string `yaml:"devices"`
	// ExpectedDevices are device hostnames that may be on the tailnet besides the
	// hosts (laptops, phones). Anything else shows up in ts.devices.
	ExpectedDevices []string `yaml:"expected_devices"`
	APIURL          string   `yaml:"api_url"`
}

type Jenkins struct {
	URL      string   `yaml:"url"`
	User     string   `yaml:"user"`
	TokenEnv string   `yaml:"token_env"`
	Agents   []string `yaml:"agents"`
	// AgentHosts files an agent's check under a host row (windows -> jenkins-win).
	AgentHosts map[string]string `yaml:"agent_hosts"`
	// BreakglassJob is checked for a recent SUCCESS. With BreakglassMonthly, serve
	// also starts an ACTION=status build when the last success is 28 days old.
	BreakglassJob     string `yaml:"breakglass_job"`
	BreakglassHost    string `yaml:"breakglass_host"`
	BreakglassMonthly bool   `yaml:"breakglass_monthly"`
}

type DigitalOcean struct {
	TokenEnv string    `yaml:"token_env"`
	Droplets []Droplet `yaml:"droplets"`
	APIURL   string    `yaml:"api_url"`
}

type Droplet struct {
	Name string `yaml:"name"`
	ID   int64  `yaml:"id"`
}

// Notion counts open items in the OpSec checklist database.
type Notion struct {
	TokenEnv     string `yaml:"token_env"`
	DatabaseID   string `yaml:"database_id"`
	DoneProperty string `yaml:"done_property"` // a checkbox property; open = unchecked
	APIURL       string `yaml:"api_url"`
}

type Alerts struct {
	SlackWebhookEnv string        `yaml:"slack_webhook_env"`
	SMTPHost        string        `yaml:"smtp_host"`
	SMTPPort        int           `yaml:"smtp_port"`
	SMTPUser        string        `yaml:"smtp_user"`
	SMTPPasswordEnv string        `yaml:"smtp_password_env"`
	MailFrom        string        `yaml:"mail_from"`
	MailTo          []string      `yaml:"mail_to"`
	DeadmanURLEnv   string        `yaml:"deadman_url_env"`
	CritReminder    time.Duration `yaml:"crit_reminder"`
	DigestAt        string        `yaml:"digest_at"` // HH:MM, server local time
}

// LoadServer reads and validates a server config.
func LoadServer(path string) (*Server, error) {
	var c Server
	if err := load(path, &c); err != nil {
		return nil, err
	}
	if c.StaleAfter == 0 {
		c.StaleAfter = 15 * time.Minute
	}
	if c.StaleAfter < time.Minute {
		return nil, fmt.Errorf("%s: stale_after %s is too short", path, c.StaleAfter)
	}
	c.ApplyDefaults()
	if c.Alerts.DigestAt != "" {
		if _, err := time.Parse("15:04", c.Alerts.DigestAt); err != nil {
			return nil, fmt.Errorf("%s: digest_at must be HH:MM", path)
		}
	}
	seen := map[string]bool{}
	for _, h := range c.Hosts {
		if !HostName.MatchString(h.Name) {
			return nil, fmt.Errorf("%s: invalid host name %q", path, h.Name)
		}
		if h.Name == ServeHost {
			return nil, fmt.Errorf("%s: host name %q is reserved", path, h.Name)
		}
		if seen[h.Name] {
			return nil, fmt.Errorf("%s: duplicate host %q", path, h.Name)
		}
		seen[h.Name] = true
	}
	return &c, nil
}

// ServeHost is the pseudo-host that holds checks not tied to one host (certs, DNS,
// snapshots, the Tailscale device list, the dead-man ping).
const ServeHost = "serve"

// DefaultScanPorts is scanned on each public IP when scan_ports is not set.
var DefaultScanPorts = []int{21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 1666, 2375, 3306,
	3389, 5432, 5900, 5985, 5986, 6379, 8080, 8098, 8099, 8443, 9000, 9200, 11211, 27017, 50000, 50001}

// ApplyDefaults fills zero values with the spec defaults. LoadServer calls it.
func (c *Server) ApplyDefaults() {
	def := func(d *time.Duration, v time.Duration) {
		if *d == 0 {
			*d = v
		}
	}
	deff := func(f *float64, v float64) {
		if *f == 0 {
			*f = v
		}
	}
	def(&c.ProbeInterval, 5*time.Minute)
	t := &c.Thresholds
	def(&t.TSOnlineWarn, 5*time.Minute)
	def(&t.TSOnlineCrit, 15*time.Minute)
	deff(&t.TSKeyExpiryDays, 14)
	deff(&t.TSDeviceUnseenDays, 30)
	def(&t.JenkinsOfflineGrace, 5*time.Minute)
	def(&t.BreakglassMaxAge, 35*24*time.Hour)
	deff(&t.TLSWarnDays, 21)
	deff(&t.TLSCritDays, 7)
	deff(&t.SnapshotWarnDays, 35)
	deff(&t.SnapshotCritDays, 60)
	def(&t.UpdatesCritAge, 14*24*time.Hour)
	def(&c.Alerts.CritReminder, 12*time.Hour)
	if c.Alerts.SMTPPort == 0 {
		c.Alerts.SMTPPort = 587
	}
	if len(c.ScanPorts) == 0 {
		c.ScanPorts = DefaultScanPorts
	}
	if c.Tailscale.Tailnet == "" {
		c.Tailscale.Tailnet = "-"
	}
	if c.Tailscale.APIURL == "" {
		c.Tailscale.APIURL = "https://api.tailscale.com"
	}
	if c.DO.APIURL == "" {
		c.DO.APIURL = "https://api.digitalocean.com"
	}
	if c.Notion.APIURL == "" {
		c.Notion.APIURL = "https://api.notion.com"
	}
	if c.Jenkins.BreakglassHost == "" {
		c.Jenkins.BreakglassHost = "jenkins-win"
	}
}

// Env returns the value of the env var named by name, or "" when name is empty.
func Env(name string) string {
	if name == "" {
		return ""
	}
	return strings.TrimSpace(os.Getenv(name))
}

// HasHost reports whether name is a configured host.
func (c *Server) HasHost(name string) bool {
	for _, h := range c.Hosts {
		if h.Name == name {
			return true
		}
	}
	return false
}

// Tokens maps host name to the SHA-256 of that host's report token.
type Tokens map[string][]byte

// ReportTokens reads the per-host token hashes from the env var named by
// report_tokens_env. Format: "host=sha256hex,host=sha256hex". Every host must be
// configured. An unset variable yields no tokens, so every report is rejected.
func (c *Server) ReportTokens() (Tokens, error) {
	t := Tokens{}
	if c.ReportTokensEnv == "" {
		return t, nil
	}
	raw := strings.TrimSpace(os.Getenv(c.ReportTokensEnv))
	if raw == "" {
		return t, nil
	}
	for _, pair := range strings.Split(raw, ",") {
		host, hash, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if !ok {
			return nil, fmt.Errorf("%s: entry without '=' (want host=sha256hex)", c.ReportTokensEnv)
		}
		if !c.HasHost(host) {
			return nil, fmt.Errorf("%s: token for unknown host %q", c.ReportTokensEnv, host)
		}
		sum, err := hex.DecodeString(hash)
		if err != nil || len(sum) != 32 {
			return nil, fmt.Errorf("%s: token hash for %q is not 64 hex chars", c.ReportTokensEnv, host)
		}
		if _, dup := t[host]; dup {
			return nil, fmt.Errorf("%s: duplicate token for %q", c.ReportTokensEnv, host)
		}
		t[host] = sum
	}
	return t, nil
}

// Lookup returns the host whose token hash equals sum. It compares against every
// entry in constant time so the timing does not reveal which host matched.
func (t Tokens) Lookup(sum []byte) (string, bool) {
	found := ""
	for host, h := range t {
		if subtle.ConstantTimeCompare(h, sum) == 1 {
			found = host
		}
	}
	return found, found != ""
}

// Agent is the config of `mpinfra report` and `mpinfra check`.
type Agent struct {
	Host      string `yaml:"host"`
	ServerURL string `yaml:"server_url"`
	// Token may be set inline (agent.yaml is root/SYSTEM-only) or via TokenEnv.
	// TokenEnv wins when both are set.
	Token    string `yaml:"token"`
	TokenEnv string `yaml:"token_env"`

	// Collectors. host.uptime always runs; each other one runs when configured.
	Disks           []string       `yaml:"disks"` // mount points; "C:\\" on Windows
	DiskWarnPct     float64        `yaml:"disk_warn_pct"`
	DiskCritPct     float64        `yaml:"disk_crit_pct"`
	Checkpoint      *FileAge       `yaml:"checkpoint"`
	OfflineDB       *FileAge       `yaml:"offline_db"`
	P4License       *Command       `yaml:"p4_license"`
	Firewall        *Command       `yaml:"firewall"`
	SecurityUpdates string         `yaml:"security_updates"` // dnf, apt or windows
	Versions        []Version      `yaml:"versions"`
	AuthFailures    *AuthFailures  `yaml:"auth_failures"`
	Windows         *WindowsChecks `yaml:"windows"`
}

// FileAge points a collector at a log file or directory and the age at which it
// turns crit.
type FileAge struct {
	Path   string        `yaml:"path"`
	MaxAge time.Duration `yaml:"max_age"`
}

// Command is an argv (no shell) plus extra environment.
type Command struct {
	Cmd []string          `yaml:"cmd"`
	Env map[string]string `yaml:"env"`
}

// Version reports the version of one package, taken from a command's output.
type Version struct {
	Name    string            `yaml:"name"`
	Cmd     []string          `yaml:"cmd"`
	Env     map[string]string `yaml:"env"`
	Pattern string            `yaml:"pattern"` // first submatch is the version
	Min     string            `yaml:"min"`
}

// AuthFailures counts failed logins in command output, one source per service.
type AuthFailures struct {
	Warn    int          `yaml:"warn"` // total failures that turn the check warn; 0 = never
	Sources []AuthSource `yaml:"sources"`
}

type AuthSource struct {
	Name    string            `yaml:"name"`
	Cmd     []string          `yaml:"cmd"`
	Env     map[string]string `yaml:"env"`
	Pattern string            `yaml:"pattern"` // a match is one failure; named group "ip" is the source
}

// WindowsChecks configures the jenkins-win collectors.
type WindowsChecks struct {
	TailscaleService string   `yaml:"tailscale_service"` // default "Tailscale"
	FirewallAllow    []string `yaml:"firewall_allow"`    // rule Names accepted with RemoteAddress Any
}

// LoadAgent reads and validates an agent config.
func LoadAgent(path string) (*Agent, error) {
	var c Agent
	if err := load(path, &c); err != nil {
		return nil, err
	}
	if !HostName.MatchString(c.Host) {
		return nil, fmt.Errorf("%s: invalid host %q", path, c.Host)
	}
	if c.ServerURL != "" {
		u, err := url.Parse(c.ServerURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("%s: server_url must be an http(s) URL", path)
		}
	}
	if c.DiskWarnPct == 0 {
		c.DiskWarnPct = 80
	}
	if c.DiskCritPct == 0 {
		c.DiskCritPct = 90
	}
	for _, fa := range []*FileAge{c.Checkpoint, c.OfflineDB} {
		if fa != nil && fa.MaxAge == 0 {
			fa.MaxAge = 26 * time.Hour
		}
	}
	switch c.SecurityUpdates {
	case "", "dnf", "apt", "windows":
	default:
		return nil, fmt.Errorf("%s: security_updates must be dnf, apt or windows", path)
	}
	for _, v := range c.Versions {
		if !versionName.MatchString(v.Name) || len(v.Cmd) == 0 {
			return nil, fmt.Errorf("%s: version %q needs a name ([a-z0-9-]) and a cmd", path, v.Name)
		}
		if _, err := regexp.Compile(v.Pattern); err != nil {
			return nil, fmt.Errorf("%s: version %s: %w", path, v.Name, err)
		}
	}
	if c.AuthFailures != nil {
		for _, src := range c.AuthFailures.Sources {
			if len(src.Cmd) == 0 || src.Pattern == "" {
				return nil, fmt.Errorf("%s: auth source %q needs cmd and pattern", path, src.Name)
			}
			if _, err := regexp.Compile(src.Pattern); err != nil {
				return nil, fmt.Errorf("%s: auth source %s: %w", path, src.Name, err)
			}
		}
	}
	for _, cmd := range []*Command{c.P4License, c.Firewall} {
		if cmd != nil && len(cmd.Cmd) == 0 {
			return nil, fmt.Errorf("%s: p4_license and firewall need a cmd", path)
		}
	}
	if c.Windows != nil && c.Windows.TailscaleService == "" {
		c.Windows.TailscaleService = "Tailscale"
	}
	return &c, nil
}

// ReportToken returns the agent's report token.
func (c *Agent) ReportToken() (string, error) {
	tok := c.Token
	if c.TokenEnv != "" {
		tok = os.Getenv(c.TokenEnv)
	}
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return "", errors.New("no report token: set token or token_env in the agent config")
	}
	return tok, nil
}

func load(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}
