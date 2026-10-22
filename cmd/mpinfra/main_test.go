package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
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
