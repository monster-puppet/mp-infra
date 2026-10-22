package report

import (
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 22, 14, 5, 0, 0, time.UTC)

func TestDecode(t *testing.T) {
	good := `{"host":"monster-p4","agent_version":"0.1.0","collected_at":"2026-10-22T14:05:00Z",
		"checks":[{"id":"host.uptime","state":"ok","summary":"up 3d","data":{"seconds":1}}]}`
	p, err := Decode(strings.NewReader(good), now)
	if err != nil {
		t.Fatal(err)
	}
	if p.Host != "monster-p4" || len(p.Checks) != 1 {
		t.Fatalf("%+v", p)
	}

	bad := map[string]string{
		"unknown field":   `{"host":"a","agent_version":"1","collected_at":"2026-10-22T14:05:00Z","checks":[],"x":1}`,
		"trailing":        `{"host":"a","agent_version":"1","collected_at":"2026-10-22T14:05:00Z","checks":[]}{}`,
		"bad host":        `{"host":"A B","agent_version":"1","collected_at":"2026-10-22T14:05:00Z","checks":[]}`,
		"no time":         `{"host":"a","agent_version":"1","checks":[]}`,
		"clock":           `{"host":"a","agent_version":"1","collected_at":"2026-10-25T14:05:00Z","checks":[]}`,
		"bad id":          `{"host":"a","agent_version":"1","collected_at":"2026-10-22T14:05:00Z","checks":[{"id":"../x","state":"ok","summary":""}]}`,
		"reserved id":     `{"host":"a","agent_version":"1","collected_at":"2026-10-22T14:05:00Z","checks":[{"id":"ts.online.a","state":"ok","summary":""}]}`,
		"dup id":          `{"host":"a","agent_version":"1","collected_at":"2026-10-22T14:05:00Z","checks":[{"id":"x","state":"ok","summary":""},{"id":"x","state":"ok","summary":""}]}`,
		"stale state":     `{"host":"a","agent_version":"1","collected_at":"2026-10-22T14:05:00Z","checks":[{"id":"x","state":"stale","summary":""}]}`,
		"newline summary": `{"host":"a","agent_version":"1","collected_at":"2026-10-22T14:05:00Z","checks":[{"id":"x","state":"ok","summary":"a\nb"}]}`,
		"data array":      `{"host":"a","agent_version":"1","collected_at":"2026-10-22T14:05:00Z","checks":[{"id":"x","state":"ok","summary":"","data":[1]}]}`,
	}
	for name, body := range bad {
		if _, err := Decode(strings.NewReader(body), now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestClip(t *testing.T) {
	if got := Clip("a\nbé", 5); got != "a bé" {
		t.Errorf("Clip = %q", got)
	}
	if got := Clip("aé", 2); got != "a" {
		t.Errorf("Clip split a rune: %q", got)
	}
}
