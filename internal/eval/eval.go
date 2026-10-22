// Package eval turns facts into check states, decides staleness and which state
// changes alert.
package eval

import (
	"regexp"
	"strings"
	"time"
)

// State is the state of one check.
type State string

const (
	OK    State = "ok"
	Warn  State = "warn"
	Crit  State = "crit"
	Stale State = "stale"
)

// Valid reports whether s is a state an agent may send. Agents never send stale:
// only the server decides that.
func (s State) Valid() bool {
	return s == OK || s == Warn || s == Crit
}

// Bad reports whether s alerts: crit, or stale which alerts like crit.
func (s State) Bad() bool { return s == Crit || s == Stale }

// Severity orders states for sorting: higher is worse. Stale alerts like crit, so it
// ranks with it.
func (s State) Severity() int {
	switch s {
	case OK:
		return 0
	case Warn:
		return 1
	}
	return 2
}

// Worst returns the worse of a and b. On a tie crit wins over stale.
func Worst(a, b State) State {
	if a == "" || b.Severity() > a.Severity() || (b.Severity() == a.Severity() && b == Crit) {
		return b
	}
	return a
}

// IsStale reports whether a host whose last report arrived at last is stale at now.
// A zero last means the host never reported.
func IsStale(last, now time.Time, after time.Duration) bool {
	return last.IsZero() || now.Sub(last) > after
}

// Higher maps a value where higher is worse (disk %, age) onto a state.
// A threshold of 0 disables that level.
func Higher(v, warn, crit float64) State {
	switch {
	case crit > 0 && v >= crit:
		return Crit
	case warn > 0 && v >= warn:
		return Warn
	}
	return OK
}

// Lower maps a value where lower is worse (days to certificate expiry) onto a state.
func Lower(v, warn, crit float64) State {
	switch {
	case v < crit:
		return Crit
	case v < warn:
		return Warn
	}
	return OK
}

// AlertKind says whether a transition sends an alert.
type AlertKind string

const (
	NoAlert  AlertKind = ""
	Problem  AlertKind = "problem"
	Recovery AlertKind = "recovery"
	Reminder AlertKind = "reminder"
)

// Classify decides whether a transition from old to new alerts. Alerts go out on
// transitions into crit or stale, and on recovery from them. A new check that starts
// ok or warn is quiet.
func Classify(old, new State) AlertKind {
	switch {
	case old == new:
		return NoAlert
	case new.Bad():
		return Problem
	case old.Bad():
		return Recovery
	}
	return NoAlert
}

// CheckID is the allowed shape of a check id.
var CheckID = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

// serverOwned are check id prefixes only the server may set. A report that carries
// one is rejected, so a host cannot override a probe that watches it.
var serverOwned = []string{
	"ts.", "jenkins.", "ports.", "tls.", "dns.", "http.", "tcp.", "snapshot.",
	"serve.", "opsec.", "report.", "win.breakglass",
}

// ServerOwned reports whether id belongs to a server-side probe.
func ServerOwned(id string) bool {
	for _, p := range serverOwned {
		if strings.HasPrefix(id, p) {
			return true
		}
	}
	return false
}

// MaxCritAck is the longest a crit state may be acknowledged.
const MaxCritAck = 24 * time.Hour

// AckLimit returns the longest acknowledgement allowed for a state, or 0 when the
// state cannot be acknowledged.
func AckLimit(s State) time.Duration {
	switch s {
	case Warn:
		return 90 * 24 * time.Hour
	case Crit, Stale:
		return MaxCritAck
	}
	return 0
}
