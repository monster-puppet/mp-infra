package config

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadServerExample(t *testing.T) {
	c, err := LoadServer("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Hosts) != 3 || c.StaleAfter != 15*time.Minute {
		t.Fatalf("got %d hosts, stale_after %s", len(c.Hosts), c.StaleAfter)
	}
	if len(c.Links) != 2 || !c.Links[1].Public || c.Links[1].Check != "jenkins.agent.windows" {
		t.Fatalf("links: %+v", c.Links)
	}
	if h, _ := c.HostByName("jenkins-win"); h.DisplayName() != "Windows build agent" || OSFamily(h.OS) != "windows" {
		t.Fatalf("jenkins-win: %+v", h)
	}
	if OSFamily("rocky") != "linux" || (Host{Name: "x"}).DisplayName() != "x" {
		t.Fatal("OSFamily or DisplayName fallback")
	}
}

func TestLoadServerRejects(t *testing.T) {
	for _, body := range []string{
		"hosts: [{name: A}]",
		"hosts: [{name: a}, {name: a}]",
		"stale_after: 10s",
		"hosts: [{name: a, os: beos}]",
		"hosts: [{name: a, label: ' padded'}]",
		"hosts: [{name: a, label: " + strings.Repeat("x", 41) + "}]",
		// links: unknown host, a loop, a bad port, a long label
		"hosts: [{name: a}]\nlinks: [{from: a, to: b}]",
		"hosts: [{name: a}]\nlinks: [{from: a, to: a}]",
		"hosts: [{name: a}, {name: b}]\nlinks: [{from: a, to: b, port: 70000}]",
		"hosts: [{name: a}, {name: b}]\nlinks: [{from: a, to: b, label: thirteen-char}]",
		// google_login: missing env names, no allow list, http base_url, base_url with a path
		"base_url: https://ui.example.ts.net\ngoogle_login: {client_id: x, allowed_domain: example.com}",
		"base_url: https://ui.example.ts.net\ngoogle_login: {client_id: x, client_secret_env: S, session_key_env: K}",
		"base_url: http://100.64.0.1:8098\ngoogle_login: {client_id: x, client_secret_env: S, session_key_env: K, allowed_domain: example.com}",
		"base_url: https://ui.example.ts.net/mp\ngoogle_login: {client_id: x, client_secret_env: S, session_key_env: K, allowed_domain: example.com}",
		// notices: bad state, reserved or bad names, a non-http url, a bad title regexp, duplicates
		"notices: {feeds: [{name: a, url: 'https://x', state: info}]}",
		"notices: {feeds: [{name: kev, url: 'https://x', state: warn}]}",
		"notices: {feeds: [{name: jenkins.installed, url: 'https://x', state: warn}]}",
		"notices: {feeds: [{name: A, url: 'https://x', state: warn}]}",
		"notices: {feeds: [{name: a, url: 'ftp://x', state: warn}]}",
		"notices: {feeds: [{name: a, url: 'https://x', state: warn, title: '('}]}",
		"notices: {feeds: [{name: a, url: 'https://x', state: warn}, {name: a, url: 'https://y', state: crit}]}",
		// admins: must be logins, so the "local" or address viewer never matches
		"admins: [local]",
		"admins: ['100.64.0.1']",
		"admins: [' marcus@example.com']",
	} {
		if _, err := LoadServer(write(t, body)); err == nil {
			t.Errorf("LoadServer(%q) = nil error", body)
		}
	}
}

func TestLoadServerGoogle(t *testing.T) {
	for _, base := range []string{"https://ui.example.ts.net", "https://ui.example.ts.net/", "http://localhost:8098"} {
		c, err := LoadServer(write(t, "base_url: "+base+"\ngoogle_login: {client_id: x, client_secret_env: S, session_key_env: K, allowed_emails: [a@example.com]}"))
		if err != nil {
			t.Fatalf("%s: %v", base, err)
		}
		if !c.GoogleLogin.Enabled() || c.GoogleLogin.SessionTTL != 7*24*time.Hour {
			t.Fatalf("%s: %+v", base, c.GoogleLogin)
		}
	}
}

func TestReportTokens(t *testing.T) {
	sum := sha256.Sum256([]byte("secret-a"))
	hexA := hex.EncodeToString(sum[:])
	c := &Server{
		Hosts:           []Host{{Name: "a"}, {Name: "b"}},
		ReportTokensEnv: "MPINFRA_TEST_TOKENS",
	}
	cases := []struct {
		env string
		ok  bool
		n   int
	}{
		{"", true, 0},
		{"a=" + hexA, true, 1},
		{"a=" + hexA + ", b=" + hexA, true, 2},
		{"c=" + hexA, false, 0},
		{"a=" + hexA + ",a=" + hexA, false, 0},
		{"a=abc", false, 0},
		{"a", false, 0},
	}
	for _, tc := range cases {
		t.Setenv("MPINFRA_TEST_TOKENS", tc.env)
		got, err := c.ReportTokens()
		if (err == nil) != tc.ok || len(got) != tc.n {
			t.Errorf("env %q: got %d tokens, err %v", tc.env, len(got), err)
		}
	}

	t.Setenv("MPINFRA_TEST_TOKENS", "a="+hexA)
	tok, _ := c.ReportTokens()
	if h, ok := tok.Lookup(sum[:]); !ok || h != "a" {
		t.Errorf("Lookup = %q, %v", h, ok)
	}
	other := sha256.Sum256([]byte("secret-b"))
	if _, ok := tok.Lookup(other[:]); ok {
		t.Error("Lookup matched a wrong token")
	}
}

func TestMCPTokens(t *testing.T) {
	sum := sha256.Sum256([]byte("secret-a"))
	hexA := hex.EncodeToString(sum[:])
	c := &Server{Hosts: []Host{{Name: "a"}}, MCPTokensEnv: "MPINFRA_TEST_MCP"}
	cases := []struct {
		env string
		ok  bool
		n   int
	}{
		{"", true, 0},
		{"ops-agent=" + hexA, true, 1},
		{"ops-agent=" + hexA + ",laptop=" + hexA, true, 2},
		{"Ops Agent=" + hexA, false, 0},
		{"ops-agent=" + hexA + ",ops-agent=" + hexA, false, 0},
		{"ops-agent=abc", false, 0},
	}
	for _, tc := range cases {
		t.Setenv("MPINFRA_TEST_MCP", tc.env)
		got, err := c.MCPTokens()
		if (err == nil) != tc.ok || len(got) != tc.n {
			t.Errorf("env %q: got %d tokens, err %v", tc.env, len(got), err)
		}
	}
	if got, err := (&Server{}).MCPTokens(); err != nil || len(got) != 0 {
		t.Errorf("no mcp_tokens_env: %d tokens, err %v", len(got), err)
	}
}

func TestLoadAgent(t *testing.T) {
	c, err := LoadAgent(write(t, "host: jenkins\nserver_url: http://100.64.0.1:8099\ntoken_env: MPINFRA_TEST_TOK\ntoken: inline\n"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("MPINFRA_TEST_TOK", "from-env")
	if tok, _ := c.ReportToken(); tok != "from-env" {
		t.Errorf("token_env should win, got %q", tok)
	}
	for _, body := range []string{
		"host: ''",
		"host: a\nserver_url: ftp://x",
		"host: a\nserver_url: not a url",
		"host: a\nlogins: {allow: [192.0.2.1], sources: [{name: ssh, cmd: [x], pattern: '(?P<ip>.*)'}]}",
		"host: a\nlogins: {sources: [{name: ssh, cmd: [x], pattern: 'from (\\S+)'}]}",
	} {
		if _, err := LoadAgent(write(t, body)); err == nil {
			t.Errorf("LoadAgent(%q) = nil error", body)
		}
	}
}

func TestLoadAgentLogins(t *testing.T) {
	c, err := LoadAgent(write(t, "host: a\nlogins: {allow: [192.0.2.7/24], sources: [{name: ssh, cmd: [x], pattern: 'from (?P<ip>\\S+)'}]}"))
	if err != nil {
		t.Fatal(err)
	}
	if n := c.Logins.Nets; len(n) != len(DefaultLoginNets)+1 || n[len(n)-1].String() != "192.0.2.0/24" {
		t.Errorf("nets = %v", n)
	}
}

func TestLoadAgentExamples(t *testing.T) {
	paths, _ := filepath.Glob("../../examples/agent-*.yaml")
	if len(paths) == 0 {
		t.Fatal("no examples")
	}
	for _, p := range paths {
		c, err := LoadAgent(p)
		if err != nil {
			t.Errorf("%s: %v", p, err)
			continue
		}
		if c.Path != p {
			t.Errorf("%s: path %q", p, c.Path)
		}
		if f := c.Fail2ban; f != nil && !f.Unban {
			t.Errorf("%s: the example should show fail2ban: {unban: true}", p)
		}
	}
}

func TestAdmins(t *testing.T) {
	c, err := LoadServer(write(t, "admins: [marcus@example.com]"))
	if err != nil {
		t.Fatal(err)
	}
	for v, want := range map[string]bool{"marcus@example.com": true, "Marcus@Example.com": true, "other@example.com": false, "local": false, "": false, "100.64.0.1": false} {
		if c.IsAdmin(v) != want {
			t.Errorf("IsAdmin(%q) = %v", v, !want)
		}
	}
	if (&Server{}).IsAdmin("marcus@example.com") {
		t.Error("admin without an admins list")
	}
}

func TestLoadAgentDefender(t *testing.T) {
	c, err := LoadAgent(write(t, "host: jenkins-win\nwindows: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Windows.Defender == nil || !*c.Windows.Defender {
		t.Error("defender not on by default")
	}
	c, err = LoadAgent(write(t, "host: jenkins-win\nwindows: {defender: false}\n"))
	if err != nil || *c.Windows.Defender {
		t.Errorf("defender: false ignored: %v", err)
	}
}
