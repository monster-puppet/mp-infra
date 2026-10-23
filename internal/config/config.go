// Package config loads the server and agent YAML configs. Secrets are never stored
// in the server config itself: it names the env vars that hold them.
package config

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// HostName is the allowed shape of a host name in configs and reports.
var HostName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

var versionName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// Server is the config of `mpinfra serve`. Sections for later phases (tls, tailscale,
// jenkins, alerts) are accepted and ignored until their phase lands.
type Server struct {
	UIAddr     string        `yaml:"ui_addr"`
	ReportAddr string        `yaml:"report_addr"`
	DB         string        `yaml:"db"`
	StaleAfter time.Duration `yaml:"stale_after"`
	Hosts      []Host        `yaml:"hosts"`
	// Links are the connections hosts make to each other, drawn on the network map.
	Links           []Link `yaml:"links"`
	ReportTokensEnv string `yaml:"report_tokens_env"`
	// MCPTokensEnv names the env var holding the MCP clients' token hashes. Unset or
	// empty: no /mcp endpoint.
	MCPTokensEnv string `yaml:"mcp_tokens_env"`

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
	// Notices reads vendors' public security feeds (see Notices).
	Notices Notices `yaml:"notices"`
	Alerts  Alerts  `yaml:"alerts"`
	// GoogleLogin, when client_id is set, puts the UI behind Google sign-in on top
	// of the tailnet. /healthz and /api/status.json stay open on the tailnet.
	GoogleLogin GoogleLogin `yaml:"google_login"`
}

// GoogleLogin configures Google (OpenID Connect) sign-in for the UI. The redirect
// URI registered with Google is base_url + "/auth/callback".
type GoogleLogin struct {
	ClientID        string `yaml:"client_id"`
	ClientSecretEnv string `yaml:"client_secret_env"`
	// SessionKeyEnv names the env var holding the key that signs session cookies
	// (at least 32 characters, e.g. from `mpinfra token`).
	SessionKeyEnv string `yaml:"session_key_env"`
	// AllowedDomain admits any verified account of that Google Workspace domain.
	AllowedDomain string `yaml:"allowed_domain"`
	// AllowedEmails admits these addresses as well, whatever their domain.
	AllowedEmails []string      `yaml:"allowed_emails"`
	SessionTTL    time.Duration `yaml:"session_ttl"`
}

// Enabled reports whether Google sign-in is configured.
func (g GoogleLogin) Enabled() bool { return g.ClientID != "" }

type Host struct {
	// Name is the host's identity: report tokens, agent configs, check ids and the
	// database all use it, so it never changes. Label is what the UI shows instead.
	Name  string `yaml:"name"`
	Label string `yaml:"label"`
	// OS picks the icon next to the host in the UI. One of OSNames, or empty.
	OS                  string `yaml:"os"`
	PublicIP            string `yaml:"public_ip"`
	ExpectedPublicPorts []int  `yaml:"expected_public_ports"`
	// NotOnTailnet skips the Tailscale checks (p4-game until it joins).
	NotOnTailnet bool `yaml:"not_on_tailnet"`
	// NoReport marks a host that runs no agent, so it never goes stale.
	NoReport bool `yaml:"no_report"`
}

// Link is a connection one host is known to make to another. It is declared, not
// observed: the map draws it whether or not traffic flows, and colours it from
// Check when set.
type Link struct {
	From  string `yaml:"from"`
	To    string `yaml:"to"`
	Port  int    `yaml:"port"`
	Label string `yaml:"label"` // shown on the line instead of the port
	// Public: the connection goes over the internet, not the tailnet.
	Public bool `yaml:"public"`
	// Check is the id of a check on either end, or on serve, that says whether the
	// link works (jenkins.agent.windows for jenkins-win -> jenkins).
	Check string `yaml:"check"`
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
	// BruteForceActive is how many new failed logins between two reports of a
	// host (normally 5 minutes apart) make an active brute force.
	BruteForceActive int `yaml:"bruteforce_active"`
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
	// ExpectedDevices are devices that may be on the tailnet besides the hosts
	// (laptops, phones), by hostname or by their name in Tailscale. Anything else
	// shows up in ts.devices.
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

// Notices turns vendors' public security feeds into notice.<name> checks on serve.
// Off unless enabled. With no feeds listed, DefaultNoticeFeeds are read.
type Notices struct {
	Enabled bool         `yaml:"enabled"`
	Feeds   []NoticeFeed `yaml:"feeds"`
	// Interval is how often a feed is fetched (default 1 h); the CISA catalogue
	// and the Jenkins update centre are fetched every SlowInterval (default 6 h).
	Interval     time.Duration `yaml:"interval"`
	SlowInterval time.Duration `yaml:"slow_interval"`
	// KEV is CISA's Known Exploited Vulnerabilities catalogue; entries whose vendor
	// or product contains one of KEVProducts (whole words) become notice.kev.
	KEVDisabled bool     `yaml:"kev_disabled"`
	KEVURL      string   `yaml:"kev_url"`
	KEVProducts []string `yaml:"kev_products"`
	// JenkinsWarnings matches the Jenkins update centre's security warnings
	// against the core and plugins installed (needs the jenkins section).
	JenkinsWarnings bool   `yaml:"jenkins_warnings"`
	UpdateCenterURL string `yaml:"update_center_url"`
}

// NoticeFeed is one RSS or Atom feed of security notices.
type NoticeFeed struct {
	Name string `yaml:"name"` // check id notice.<name>
	URL  string `yaml:"url"`
	// State is what unaccepted notices make the check: warn or crit.
	State string `yaml:"state"`
	// Tag keeps only items with this category, term or php:tag.
	Tag string `yaml:"tag"`
	// Title keeps only items whose title matches this regular expression.
	Title string `yaml:"title"`
}

// DefaultNoticeFeeds are read when notices.feeds is empty. exe.dev and Tailscale
// are crit: rare, and always about something we run.
var DefaultNoticeFeeds = []NoticeFeed{
	{Name: "exe-dev", URL: "https://exe.dev/security/atom.xml", State: "crit"},
	{Name: "tailscale", URL: "https://tailscale.com/security-bulletins/index.xml", State: "crit"},
	{Name: "jenkins", URL: "https://www.jenkins.io/security/advisories/rss.xml", State: "warn"},
	{Name: "php", URL: "https://www.php.net/releases/feed.php", State: "warn", Tag: "security", Title: `^PHP 8\.3\.`},
	{Name: "letsencrypt", URL: "https://community.letsencrypt.org/c/incidents/16.rss", State: "warn"},
	{Name: "digitalocean", URL: "https://www.digitalocean.com/blog/rss", State: "warn", Tag: "trust-security"},
}

// DefaultKEVProducts is matched against KEV vendorProject and product.
var DefaultKEVProducts = []string{"jenkins", "perforce", "php", "apache http server", "nginx", "openssh", "tailscale", "let's encrypt", "digitalocean"}

func (n *Notices) check() error {
	seen := map[string]bool{}
	for _, f := range n.Feeds {
		if !versionName.MatchString(f.Name) || f.Name == "kev" || strings.HasPrefix(f.Name, "jenkins.") {
			return fmt.Errorf("notices: invalid feed name %q", f.Name)
		}
		if seen[f.Name] {
			return fmt.Errorf("notices: duplicate feed %q", f.Name)
		}
		seen[f.Name] = true
		if u, err := url.Parse(f.URL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return fmt.Errorf("notices: feed %s: url must be http(s)", f.Name)
		}
		if f.State != "warn" && f.State != "crit" {
			return fmt.Errorf("notices: feed %s: state must be warn or crit", f.Name)
		}
		if _, err := regexp.Compile(f.Title); err != nil {
			return fmt.Errorf("notices: feed %s: title: %w", f.Name, err)
		}
	}
	return nil
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
	if err := c.checkGoogle(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := c.Notices.check(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
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
		if err := CheckHostMeta(h.Label, h.OS); err != nil {
			return nil, fmt.Errorf("%s: host %s: %w", path, h.Name, err)
		}
	}
	for i, l := range c.Links {
		if err := l.check(seen); err != nil {
			return nil, fmt.Errorf("%s: links[%d]: %w", path, i, err)
		}
	}
	return &c, nil
}

func (l Link) check(hosts map[string]bool) error {
	switch {
	case !hosts[l.From] || !hosts[l.To]:
		return fmt.Errorf("from %q and to %q must both be listed under hosts", l.From, l.To)
	case l.From == l.To:
		return errors.New("from and to are the same host")
	case l.Port < 0 || l.Port > 65535:
		return fmt.Errorf("bad port %d", l.Port)
	case utf8.RuneCountInString(l.Label) > 12:
		return errors.New("label must be at most 12 characters")
	}
	return CheckHostMeta(l.Label, "")
}

// MaxLabel is the longest host label, in characters.
const MaxLabel = 40

// CheckHostMeta validates a host label and os, from the config or the UI.
func CheckHostMeta(label, os string) error {
	if utf8.RuneCountInString(label) > MaxLabel || strings.TrimSpace(label) != label || !utf8.ValidString(label) {
		return fmt.Errorf("label must be at most %d characters, without surrounding spaces", MaxLabel)
	}
	for _, r := range label {
		if unicode.IsControl(r) {
			return errors.New("label must not contain control characters")
		}
	}
	if os != "" && OSNames[os] == "" {
		return fmt.Errorf("unknown os %q", os)
	}
	return nil
}

// OSList is the os values in the order the UI offers them.
var OSList = []string{"rocky", "centos", "ubuntu", "debian", "dsm", "linux", "windows"}

// OSNames maps the allowed values of a host's os to the name the UI shows.
var OSNames = map[string]string{
	"linux":   "Linux",
	"rocky":   "Rocky Linux",
	"centos":  "CentOS Stream",
	"ubuntu":  "Ubuntu",
	"debian":  "Debian",
	"dsm":     "Synology DSM",
	"windows": "Windows Server",
}

// OSFamily is the icon family of an os value: "linux", "windows" or "".
func OSFamily(os string) string {
	switch os {
	case "windows", "":
		return os
	}
	return "linux"
}

// DisplayName is the host's label, or its name when it has none.
func (h Host) DisplayName() string {
	if h.Label != "" {
		return h.Label
	}
	return h.Name
}

// checkGoogle validates google_login. Google accepts an http redirect URI only on
// localhost, so anything else must be https (e.g. a ts.net name from tailscale serve).
func (c *Server) checkGoogle() error {
	g := c.GoogleLogin
	if !g.Enabled() {
		return nil
	}
	if g.ClientSecretEnv == "" || g.SessionKeyEnv == "" {
		return errors.New("google_login needs client_secret_env and session_key_env")
	}
	if g.AllowedDomain == "" && len(g.AllowedEmails) == 0 {
		return errors.New("google_login needs allowed_domain or allowed_emails")
	}
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.Host == "" || u.Path != "" && u.Path != "/" {
		return errors.New("google_login needs base_url as scheme://host[:port], with no path")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1")) {
		return errors.New("google_login needs an https base_url (Google allows http only for localhost)")
	}
	return nil
}

// ServeHost is the pseudo-host that holds checks not tied to one host (certs, DNS,
// snapshots, the Tailscale device list, the dead-man ping).
const ServeHost = "serve"

// DefaultScanPorts is scanned on each public IP when scan_ports is not set.
// 1999 is the SDP p4broker and 9090 Cockpit, both enabled in firewalld on Rocky.
var DefaultScanPorts = []int{21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 1666, 1999, 2375, 3306,
	3389, 5432, 5900, 5985, 5986, 6379, 8080, 8098, 8099, 8443, 9000, 9090, 9200, 11211, 27017, 50000, 50001}

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
	if t.BruteForceActive <= 0 {
		t.BruteForceActive = 30
	}
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
	if c.GoogleLogin.SessionTTL == 0 {
		c.GoogleLogin.SessionTTL = 7 * 24 * time.Hour
	}
	if c.Jenkins.BreakglassHost == "" {
		c.Jenkins.BreakglassHost = "jenkins-win"
	}
	n := &c.Notices
	if len(n.Feeds) == 0 {
		n.Feeds = DefaultNoticeFeeds
	}
	def(&n.Interval, time.Hour)
	def(&n.SlowInterval, 6*time.Hour)
	if n.KEVURL == "" {
		n.KEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	}
	if len(n.KEVProducts) == 0 {
		n.KEVProducts = DefaultKEVProducts
	}
	if n.UpdateCenterURL == "" {
		n.UpdateCenterURL = "https://updates.jenkins.io/current/update-center.actual.json"
	}
}

// Env returns the value of the env var named by name, or "" when name is empty.
func Env(name string) string {
	if name == "" {
		return ""
	}
	return strings.TrimSpace(os.Getenv(name))
}

// HostByName returns the configured host called name.
func (c *Server) HostByName(name string) (Host, bool) {
	for _, h := range c.Hosts {
		if h.Name == name {
			return h, true
		}
	}
	return Host{}, false
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

// Tokens maps a host (or MCP client) name to the SHA-256 of its token.
type Tokens map[string][]byte

// ReportTokens reads the per-host token hashes from the env var named by
// report_tokens_env. Format: "host=sha256hex,host=sha256hex". Every host must be
// configured. An unset variable yields no tokens, so every report is rejected.
func (c *Server) ReportTokens() (Tokens, error) {
	return parseTokens(c.ReportTokensEnv, "host", func(host string) error {
		if !c.HasHost(host) {
			return fmt.Errorf("%s: token for unknown host %q", c.ReportTokensEnv, host)
		}
		return nil
	})
}

// MCPTokens reads the MCP clients' token hashes from the env var named by
// mcp_tokens_env. Format: "client=sha256hex,client=sha256hex"; the client name only
// labels the log lines. No tokens: the /mcp endpoint is off.
func (c *Server) MCPTokens() (Tokens, error) {
	return parseTokens(c.MCPTokensEnv, "client", func(name string) error {
		if !HostName.MatchString(name) {
			return fmt.Errorf("%s: client name %q must be lower case letters, digits and '-'", c.MCPTokensEnv, name)
		}
		return nil
	})
}

func parseTokens(env, what string, check func(name string) error) (Tokens, error) {
	t := Tokens{}
	if env == "" {
		return t, nil
	}
	raw := strings.TrimSpace(os.Getenv(env))
	if raw == "" {
		return t, nil
	}
	for _, pair := range strings.Split(raw, ",") {
		name, hash, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if !ok {
			return nil, fmt.Errorf("%s: entry without '=' (want %s=sha256hex)", env, what)
		}
		if err := check(name); err != nil {
			return nil, err
		}
		sum, err := hex.DecodeString(hash)
		if err != nil || len(sum) != 32 {
			return nil, fmt.Errorf("%s: token hash for %q is not 64 hex chars", env, name)
		}
		if _, dup := t[name]; dup {
			return nil, fmt.Errorf("%s: duplicate token for %q", env, name)
		}
		t[name] = sum
	}
	return t, nil
}

// Lookup returns the name whose token hash equals sum. It compares against every
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
	SSHD            *Command       `yaml:"sshd"`             // ssh.auth: `sshd -T`, keys only or passwords too
	SecurityUpdates string         `yaml:"security_updates"` // dnf, apt or windows
	Versions        []Version      `yaml:"versions"`
	AuthFailures    *AuthFailures  `yaml:"auth_failures"`
	Logins          *Logins        `yaml:"logins"`
	Accounts        bool           `yaml:"accounts"`  // sec.accounts: admins, sudoers, SSH keys
	Listeners       bool           `yaml:"listeners"` // sec.listeners: listening TCP ports
	RAID            *RAID          `yaml:"raid"`      // raid.<host>: Linux md arrays from /proc/mdstat
	SMART           *SMART         `yaml:"smart"`     // smart.<host>: drive health from smartctl
	Fail2ban        *Fail2ban      `yaml:"fail2ban"`  // sec.fail2ban.<host>: running, banned now, bans in 24 h
	Windows         *WindowsChecks `yaml:"windows"`
}

// Fail2ban reads fail2ban's state; `fail2ban: {}` takes the defaults.
type Fail2ban struct {
	Client []string `yaml:"client"` // default ["fail2ban-client"]
	Log    string   `yaml:"log"`    // default /var/log/fail2ban.log
}

// RAID reads the Linux md arrays (Synology SHR and RAID are md arrays too).
type RAID struct {
	Path string `yaml:"path"` // default /proc/mdstat
	// System lists arrays that hold only an OS copy on every disk (Synology md0
	// and md1). A missing member there warns instead of crit: the data is intact.
	System []string `yaml:"system"`
}

// SMART runs Cmd with each device appended and reads smartctl's health verdict
// and the sector counters.
type SMART struct {
	Cmd     []string `yaml:"cmd"`     // default ["smartctl", "-H", "-A", "-i"]
	Devices []string `yaml:"devices"` // e.g. /dev/sata1 on Synology, /dev/sda elsewhere
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
	Warn      int          `yaml:"warn"`        // total failures that turn the check warn; 0 = never
	WarnPerIP int          `yaml:"warn_per_ip"` // failures from one IP that turn it warn; 0 = never
	Sources   []AuthSource `yaml:"sources"`
	// Ignore lists CIDRs whose failures are not counted (the office LAN, where a
	// stale saved password is noise, not an attack). Reported as "ignored".
	Ignore []string `yaml:"ignore"`

	IgnoreNets []netip.Prefix `yaml:"-"` // Ignore, parsed
}

// Logins lists successful logins, one source per service. A login from an address
// outside Allow is crit. The tailnet and loopback are always allowed.
type Logins struct {
	Allow   []string     `yaml:"allow"`   // extra CIDRs, e.g. an office IP
	Sources []AuthSource `yaml:"sources"` // pattern needs a named group "ip"; "user" is optional

	Nets []netip.Prefix `yaml:"-"` // Allow plus the defaults, parsed
}

// DefaultLoginNets are always allowed: the Tailscale ranges and loopback.
var DefaultLoginNets = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
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
		for _, a := range c.AuthFailures.Ignore {
			p, err := netip.ParsePrefix(a)
			if err != nil {
				return nil, fmt.Errorf("%s: auth_failures ignore %q: want a CIDR such as 192.168.1.0/24", path, a)
			}
			c.AuthFailures.IgnoreNets = append(c.AuthFailures.IgnoreNets, p.Masked())
		}
		for _, src := range c.AuthFailures.Sources {
			if len(src.Cmd) == 0 || src.Pattern == "" {
				return nil, fmt.Errorf("%s: auth source %q needs cmd and pattern", path, src.Name)
			}
			if _, err := regexp.Compile(src.Pattern); err != nil {
				return nil, fmt.Errorf("%s: auth source %s: %w", path, src.Name, err)
			}
		}
	}
	if l := c.Logins; l != nil {
		l.Nets = append([]netip.Prefix{}, DefaultLoginNets...)
		for _, a := range l.Allow {
			p, err := netip.ParsePrefix(a)
			if err != nil {
				return nil, fmt.Errorf("%s: logins allow %q: want a CIDR such as 192.0.2.10/32", path, a)
			}
			l.Nets = append(l.Nets, p.Masked())
		}
		for _, src := range l.Sources {
			if len(src.Cmd) == 0 || src.Pattern == "" {
				return nil, fmt.Errorf("%s: login source %q needs cmd and pattern", path, src.Name)
			}
			re, err := regexp.Compile(src.Pattern)
			if err != nil {
				return nil, fmt.Errorf("%s: login source %s: %w", path, src.Name, err)
			}
			if re.SubexpIndex("ip") < 0 {
				return nil, fmt.Errorf("%s: login source %s: pattern needs a named group (?P<ip>...)", path, src.Name)
			}
		}
	}
	for _, cmd := range []*Command{c.P4License, c.Firewall, c.SSHD} {
		if cmd != nil && len(cmd.Cmd) == 0 {
			return nil, fmt.Errorf("%s: p4_license, firewall and sshd need a cmd", path)
		}
	}
	if f := c.Fail2ban; f != nil {
		if len(f.Client) == 0 {
			f.Client = []string{"fail2ban-client"}
		}
		if f.Log == "" {
			f.Log = "/var/log/fail2ban.log"
		}
	}
	if c.RAID != nil && c.RAID.Path == "" {
		c.RAID.Path = "/proc/mdstat"
	}
	if s := c.SMART; s != nil {
		if len(s.Cmd) == 0 {
			s.Cmd = []string{"smartctl", "-H", "-A", "-i"}
		}
		if len(s.Devices) == 0 {
			return nil, fmt.Errorf("%s: smart needs devices", path)
		}
		for _, d := range s.Devices {
			if !strings.HasPrefix(d, "/dev/") {
				return nil, fmt.Errorf("%s: smart device %q must be a /dev path", path, d)
			}
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
