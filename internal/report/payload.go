// Package report holds the report payload, its validation, the agent-side
// collectors and the client that sends a report to serve.
package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
	"unicode"

	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/eval"
)

// Limits on what a report may contain. A report body is untrusted input.
const (
	MaxBody     = 256 << 10
	MaxChecks   = 200
	MaxSummary  = 300
	MaxData     = 16 << 10
	MaxVersion  = 64
	maxClockGap = 24 * time.Hour
)

// Payload is one report from one host.
type Payload struct {
	Host         string    `json:"host"`
	AgentVersion string    `json:"agent_version"`
	CollectedAt  time.Time `json:"collected_at"`
	Checks       []Check   `json:"checks"`
}

// Check is one locally collected fact.
type Check struct {
	ID      string          `json:"id"`
	State   eval.State      `json:"state"`
	Summary string          `json:"summary"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Decode parses and validates a report body. now is the server clock, used to
// reject a collected_at far from it.
func Decode(r io.Reader, now time.Time) (*Payload, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	var p Payload
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if dec.More() {
		return nil, errors.New("trailing data after report")
	}
	if err := p.Validate(now); err != nil {
		return nil, err
	}
	return &p, nil
}

// Validate checks a payload against the limits and allowed shapes.
func (p *Payload) Validate(now time.Time) error {
	if !config.HostName.MatchString(p.Host) {
		return fmt.Errorf("invalid host %q", p.Host)
	}
	if len(p.AgentVersion) > MaxVersion || !printable(p.AgentVersion) {
		return errors.New("invalid agent_version")
	}
	if p.CollectedAt.IsZero() {
		return errors.New("missing collected_at")
	}
	if d := p.CollectedAt.Sub(now); d > maxClockGap || d < -maxClockGap {
		return fmt.Errorf("collected_at %s is more than %s from server time", p.CollectedAt.Format(time.RFC3339), maxClockGap)
	}
	if len(p.Checks) > MaxChecks {
		return fmt.Errorf("%d checks, limit %d", len(p.Checks), MaxChecks)
	}
	seen := map[string]bool{}
	for i, c := range p.Checks {
		if !eval.CheckID.MatchString(c.ID) {
			return fmt.Errorf("check %d: invalid id", i)
		}
		if eval.ServerOwned(c.ID) {
			return fmt.Errorf("check %s: id is reserved for server probes", c.ID)
		}
		if seen[c.ID] {
			return fmt.Errorf("check %s: duplicate id", c.ID)
		}
		seen[c.ID] = true
		if !c.State.Valid() {
			return fmt.Errorf("check %s: invalid state", c.ID)
		}
		if len(c.Summary) > MaxSummary || !printable(c.Summary) {
			return fmt.Errorf("check %s: summary too long or has control characters", c.ID)
		}
		if len(c.Data) > MaxData {
			return fmt.Errorf("check %s: data larger than %d bytes", c.ID, MaxData)
		}
		if len(c.Data) > 0 {
			d := bytes.TrimSpace(c.Data)
			if len(d) == 0 || d[0] != '{' || !json.Valid(d) {
				return fmt.Errorf("check %s: data must be a JSON object", c.ID)
			}
		}
	}
	return nil
}

// printable rejects control characters (newlines included): summaries end up in
// mail subjects and Slack messages.
func printable(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			return false
		}
	}
	return true
}

// Clip shortens s to n bytes on a rune boundary and replaces control characters,
// so collector output always passes Validate.
func Clip(s string, n int) string {
	b := make([]rune, 0, len(s))
	size := 0
	for _, r := range s {
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			r = ' '
		}
		l := len(string(r))
		if size+l > n {
			break
		}
		size += l
		b = append(b, r)
	}
	return string(b)
}
