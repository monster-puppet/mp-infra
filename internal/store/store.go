// Package store keeps reports, current check state and state transitions in SQLite.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/monster-puppet/mp-infra/internal/eval"
)

const schema = `
CREATE TABLE IF NOT EXISTS reports (
	id          INTEGER PRIMARY KEY,
	host        TEXT    NOT NULL,
	received_at INTEGER NOT NULL,
	body        TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS reports_host_time ON reports(host, received_at);
CREATE INDEX IF NOT EXISTS reports_time ON reports(received_at);

CREATE TABLE IF NOT EXISTS checks (
	host       TEXT    NOT NULL,
	id         TEXT    NOT NULL,
	state      TEXT    NOT NULL,
	summary    TEXT    NOT NULL,
	data       TEXT    NOT NULL DEFAULT '{}',
	updated_at INTEGER NOT NULL,
	since      INTEGER NOT NULL,
	PRIMARY KEY (host, id)
);

CREATE TABLE IF NOT EXISTS transitions (
	id        INTEGER PRIMARY KEY,
	host      TEXT    NOT NULL,
	check_id  TEXT    NOT NULL,
	old_state TEXT    NOT NULL,
	new_state TEXT    NOT NULL,
	summary   TEXT    NOT NULL,
	at        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS transitions_check ON transitions(host, check_id, at);
CREATE INDEX IF NOT EXISTS transitions_time ON transitions(at);

CREATE TABLE IF NOT EXISTS alerts_sent (
	id            INTEGER PRIMARY KEY,
	transition_id INTEGER,
	host          TEXT    NOT NULL,
	check_id      TEXT    NOT NULL,
	channel       TEXT    NOT NULL,
	kind          TEXT    NOT NULL,
	at            INTEGER NOT NULL,
	error         TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS alerts_check ON alerts_sent(host, check_id, at);

CREATE TABLE IF NOT EXISTS acks (
	host     TEXT    NOT NULL,
	check_id TEXT    NOT NULL,
	state    TEXT    NOT NULL,
	until    INTEGER NOT NULL,
	by       TEXT    NOT NULL,
	note     TEXT    NOT NULL,
	at       INTEGER NOT NULL,
	PRIMARY KEY (host, check_id)
);

-- Accepted values for drift checks (fw.rules.*): the hash the team last accepted.
CREATE TABLE IF NOT EXISTS baselines (
	host     TEXT    NOT NULL,
	check_id TEXT    NOT NULL,
	value    TEXT    NOT NULL,
	at       INTEGER NOT NULL,
	by       TEXT    NOT NULL,
	PRIMARY KEY (host, check_id)
);

-- First time an item (a pending security advisory) was seen, per host and check.
CREATE TABLE IF NOT EXISTS seen (
	host       TEXT    NOT NULL,
	check_id   TEXT    NOT NULL,
	key        TEXT    NOT NULL,
	first_seen INTEGER NOT NULL,
	PRIMARY KEY (host, check_id, key)
);

-- Label and OS of a host as set in the UI. A row replaces both config values.
CREATE TABLE IF NOT EXISTS host_meta (
	host  TEXT    PRIMARY KEY,
	label TEXT    NOT NULL,
	os    TEXT    NOT NULL,
	by    TEXT    NOT NULL,
	at    INTEGER NOT NULL
);

-- Unban requests from the UI, one row per address per host. The host's next
-- report fetches it (sent_at); the report after that carries the result (done_at).
-- A row that waits longer than an hour is expired: done_at set, sent_at 0.
CREATE TABLE IF NOT EXISTS unbans (
	id           INTEGER PRIMARY KEY,
	ip           TEXT    NOT NULL,
	host         TEXT    NOT NULL,
	requested_by TEXT    NOT NULL,
	requested_at INTEGER NOT NULL,
	sent_at      INTEGER NOT NULL DEFAULT 0,
	done_at      INTEGER NOT NULL DEFAULT 0,
	ok           INTEGER NOT NULL DEFAULT 0,
	msg          TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS unbans_host ON unbans(host, sent_at, done_at);

CREATE TABLE IF NOT EXISTS kv (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
`

// Store is a handle on the mp-infra database.
type Store struct {
	db *sql.DB
}

// Open opens (and creates) the database at path in WAL mode.
func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One writer at a time keeps SQLite simple; the load here is a few requests a minute.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// Check is one check as stored.
type Check struct {
	Host      string
	ID        string
	State     eval.State
	Summary   string
	Data      string // JSON
	UpdatedAt time.Time
	Since     time.Time

	// Set when an acknowledgement is on file. It lapses at AckUntil and is
	// deleted when the state changes.
	AckUntil time.Time
	AckBy    string
	AckNote  string
}

// Acked reports whether the check is acknowledged at now.
func (c Check) Acked(now time.Time) bool { return now.Before(c.AckUntil) }

// Transition is one recorded state change.
type Transition struct {
	ID       int64
	Host     string
	CheckID  string
	OldState eval.State
	NewState eval.State
	Summary  string
	At       time.Time
}

// SaveReport stores a raw report and applies its checks. It returns the transitions
// it recorded. Checks are always written under host, never under a host named in
// the body.
func (s *Store) SaveReport(ctx context.Context, host string, at time.Time, body []byte, checks []Check) ([]Transition, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO reports(host, received_at, body) VALUES (?, ?, ?)`,
		host, at.Unix(), string(body)); err != nil {
		return nil, err
	}
	var out []Transition
	for _, c := range checks {
		c.Host = host
		t, err := upsert(ctx, tx, c, at)
		if err != nil {
			return nil, err
		}
		if t != nil {
			out = append(out, *t)
		}
	}
	return out, tx.Commit()
}

// PutCheck applies one server-side check (a probe result) under host.
func (s *Store) PutCheck(ctx context.Context, c Check, at time.Time) (*Transition, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	t, err := upsert(ctx, tx, c, at)
	if err != nil {
		return nil, err
	}
	return t, tx.Commit()
}

func upsert(ctx context.Context, tx *sql.Tx, c Check, at time.Time) (*Transition, error) {
	if c.Data == "" {
		c.Data = "{}"
	}
	var old string
	var since int64
	err := tx.QueryRowContext(ctx, `SELECT state, since FROM checks WHERE host = ? AND id = ?`, c.Host, c.ID).Scan(&old, &since)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		old = ""
		since = at.Unix()
	case err != nil:
		return nil, err
	}
	changed := old != string(c.State)
	if changed {
		since = at.Unix()
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO checks(host, id, state, summary, data, updated_at, since) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(host, id) DO UPDATE SET state = excluded.state, summary = excluded.summary,
			data = excluded.data, updated_at = excluded.updated_at, since = excluded.since`,
		c.Host, c.ID, string(c.State), c.Summary, c.Data, at.Unix(), since); err != nil {
		return nil, err
	}
	if !changed {
		return nil, nil
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM acks WHERE host = ? AND check_id = ?`, c.Host, c.ID); err != nil {
		return nil, err
	}
	return insertTransition(ctx, tx, c.Host, c.ID, eval.State(old), c.State, c.Summary, at)
}

func insertTransition(ctx context.Context, tx *sql.Tx, host, id string, old, new eval.State, summary string, at time.Time) (*Transition, error) {
	res, err := tx.ExecContext(ctx, `INSERT INTO transitions(host, check_id, old_state, new_state, summary, at) VALUES (?, ?, ?, ?, ?, ?)`,
		host, id, string(old), string(new), summary, at.Unix())
	if err != nil {
		return nil, err
	}
	tid, _ := res.LastInsertId()
	return &Transition{ID: tid, Host: host, CheckID: id, OldState: old, NewState: new, Summary: summary, At: at.Truncate(time.Second)}, nil
}

// MarkStale sets every check of host for which isReported is true to stale (unless
// it already is) and records the transitions. Server-side probe checks are left alone.
func (s *Store) MarkStale(ctx context.Context, host string, at time.Time, isReported func(id string) bool) ([]Transition, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id, state FROM checks WHERE host = ? AND state != 'stale'`, host)
	if err != nil {
		return nil, err
	}
	type row struct{ id, state string }
	var todo []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.state); err != nil {
			rows.Close()
			return nil, err
		}
		if isReported(r.id) {
			todo = append(todo, r)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var out []Transition
	for _, r := range todo {
		summary := "no report from " + host
		if _, err := tx.ExecContext(ctx, `UPDATE checks SET state = 'stale', since = ? WHERE host = ? AND id = ?`,
			at.Unix(), host, r.id); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM acks WHERE host = ? AND check_id = ?`, host, r.id); err != nil {
			return nil, err
		}
		t, err := insertTransition(ctx, tx, host, r.id, eval.State(r.state), eval.Stale, summary, at)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, tx.Commit()
}

// LastReports returns the time of the newest report per host.
func (s *Store) LastReports(ctx context.Context) (map[string]time.Time, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT host, MAX(received_at) FROM reports GROUP BY host`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var h string
		var t int64
		if err := rows.Scan(&h, &t); err != nil {
			return nil, err
		}
		out[h] = time.Unix(t, 0).UTC()
	}
	return out, rows.Err()
}

// ReportSample is a stored report body and when it was received.
type ReportSample struct {
	At   time.Time
	Body string
}

// SampleReports returns the newest report of host in each step-long slot since
// since, oldest first, for charts over many days without reading every report.
func (s *Store) SampleReports(ctx context.Context, host string, since time.Time, step time.Duration) ([]ReportSample, error) {
	sec := max(int64(step.Seconds()), 1)
	rows, err := s.db.QueryContext(ctx, `SELECT received_at, body FROM reports WHERE id IN (
		SELECT MAX(id) FROM reports WHERE host = ? AND received_at >= ? GROUP BY received_at / ?)
		ORDER BY received_at`, host, since.Unix(), sec)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReportSample
	for rows.Next() {
		var t int64
		var r ReportSample
		if err := rows.Scan(&t, &r.Body); err != nil {
			return nil, err
		}
		r.At = time.Unix(t, 0).UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}

// Checks returns all current checks ordered by host and id.
func (s *Store) Checks(ctx context.Context) ([]Check, error) {
	return s.queryChecks(ctx, checkSelect+` ORDER BY c.host, c.id`)
}

// Check returns one check, or nil when it does not exist.
func (s *Store) Check(ctx context.Context, host, id string) (*Check, error) {
	cs, err := s.queryChecks(ctx, checkSelect+` WHERE c.host = ? AND c.id = ?`, host, id)
	if err != nil || len(cs) == 0 {
		return nil, err
	}
	return &cs[0], nil
}

const checkSelect = `SELECT c.host, c.id, c.state, c.summary, c.data, c.updated_at, c.since,
	COALESCE(a.until, 0), COALESCE(a.by, ''), COALESCE(a.note, '')
	FROM checks c LEFT JOIN acks a ON a.host = c.host AND a.check_id = c.id`

func (s *Store) queryChecks(ctx context.Context, q string, args ...any) ([]Check, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Check
	for rows.Next() {
		var c Check
		var state string
		var upd, since, until int64
		if err := rows.Scan(&c.Host, &c.ID, &state, &c.Summary, &c.Data, &upd, &since, &until, &c.AckBy, &c.AckNote); err != nil {
			return nil, err
		}
		c.State = eval.State(state)
		c.UpdatedAt = time.Unix(upd, 0).UTC()
		c.Since = time.Unix(since, 0).UTC()
		if until > 0 {
			c.AckUntil = time.Unix(until, 0).UTC()
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Transitions returns the newest transitions first. Empty host or checkID match all.
func (s *Store) Transitions(ctx context.Context, host, checkID string, limit int) ([]Transition, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, host, check_id, old_state, new_state, summary, at FROM transitions
		WHERE (? = '' OR host = ?) AND (? = '' OR check_id = ?)
		ORDER BY at DESC, id DESC LIMIT ?`, host, host, checkID, checkID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Transition
	for rows.Next() {
		var t Transition
		var old, new string
		var at int64
		if err := rows.Scan(&t.ID, &t.Host, &t.CheckID, &old, &new, &t.Summary, &at); err != nil {
			return nil, err
		}
		t.OldState, t.NewState = eval.State(old), eval.State(new)
		t.At = time.Unix(at, 0).UTC()
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteCheck forgets a check and its acknowledgement, for a probe target that
// was removed from the config. Its transitions stay as history.
func (s *Store) DeleteCheck(ctx context.Context, host, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{`DELETE FROM checks WHERE host = ? AND id = ?`, `DELETE FROM acks WHERE host = ? AND check_id = ?`} {
		if _, err := tx.ExecContext(ctx, q, host, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// PruneReports deletes raw reports received before cutoff.
func (s *Store) PruneReports(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM reports WHERE received_at < ?`, cutoff.Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
