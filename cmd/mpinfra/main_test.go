package main

import "testing"

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
