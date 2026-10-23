package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/report"
)

func TestCheckBind(t *testing.T) {
	cases := []struct {
		addr     string
		insecure bool
		ok       bool
	}{
		{"127.0.0.1:8098", false, true},
		{"100.114.1.2:8098", false, true},
		{"0.0.0.0:8098", false, false},
		{":8098", false, false},
		{"203.0.113.5:8098", false, false},
		{"0.0.0.0:8098", true, true},
	}
	for _, c := range cases {
		err := checkBind(c.addr, c.insecure)
		if (err == nil) != c.ok {
			t.Errorf("checkBind(%q, %v) = %v, want ok=%v", c.addr, c.insecure, err, c.ok)
		}
	}
}

func TestCheckAddrs(t *testing.T) {
	if err := checkAddrs("127.0.0.1:8098", "127.0.0.1:8099", false); err != nil {
		t.Error(err)
	}
	if err := checkAddrs("127.0.0.1:8098", "127.0.0.1:8098", false); err == nil {
		t.Error("same address accepted")
	}
	if err := checkAddrs("127.0.0.1:8098", "0.0.0.0:8099", false); err == nil {
		t.Error("public report address accepted")
	}
}

func TestTokenCmd(t *testing.T) {
	var b strings.Builder
	if err := tokenCmd(&b); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(b.String(), "\n")
	tok := strings.TrimSpace(strings.TrimPrefix(lines[0], "token:"))
	sum := strings.TrimSpace(strings.TrimPrefix(lines[1], "sha256:"))
	h := sha256.Sum256([]byte(tok))
	if len(tok) != 64 || hex.EncodeToString(h[:]) != sum {
		t.Errorf("token %q sum %q", tok, sum)
	}
}

func TestAfterReportUnban(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Agent{Host: "jenkins", Path: filepath.Join(dir, "agent.yaml"), Fail2ban: &config.Fail2ban{Client: []string{"fail2ban-client"}}}
	file := report.UnbanResultsFile(cfg.Path)
	var asked [][]string
	unban := func(_ context.Context, client, ips []string) ([]report.UnbanResult, error) {
		asked = append(asked, append(append([]string{}, client...), ips...))
		var rs []report.UnbanResult
		for _, ip := range ips {
			rs = append(rs, report.UnbanResult{IP: ip, OK: true, Msg: "1"})
		}
		return rs, nil
	}
	ctx := context.Background()
	reply := &report.Reply{Unban: []string{"192.0.2.7"}}

	// unban: false (the default): the reply is ignored, nothing runs.
	if err := afterReport(ctx, cfg, reply, unban); err != nil || len(asked) != 0 {
		t.Fatalf("unban off: %v, ran %v", err, asked)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Errorf("results file written with unban off")
	}
	// No fail2ban section at all: the same.
	if err := afterReport(ctx, &config.Agent{Host: "jenkins", Path: cfg.Path}, reply, unban); err != nil || len(asked) != 0 {
		t.Fatalf("no fail2ban: %v, ran %v", err, asked)
	}

	cfg.Fail2ban.Unban = true
	if err := afterReport(ctx, cfg, reply, unban); err != nil || len(asked) != 1 || strings.Join(asked[0], " ") != "fail2ban-client 192.0.2.7" {
		t.Fatalf("unban on: %v, ran %v", err, asked)
	}
	b, err := os.ReadFile(file)
	if err != nil || !strings.Contains(string(b), `"ip":"192.0.2.7","ok":true`) {
		t.Fatalf("results file: %v %s", err, b)
	}
	// The next report carried the results: the file goes.
	if err := afterReport(ctx, cfg, nil, unban); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Errorf("results file kept after the report that carried it")
	}
	// A refused list is an error and writes nothing.
	refuse := func(context.Context, []string, []string) ([]report.UnbanResult, error) {
		return nil, errors.New("not an IP address")
	}
	if err := afterReport(ctx, cfg, reply, refuse); err == nil {
		t.Error("refused list not reported")
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Errorf("results file written for a refused list")
	}
}
