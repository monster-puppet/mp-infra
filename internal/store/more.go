package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/monster-puppet/mp-infra/internal/eval"
)

// Ack acknowledges the current state of a check until the given time. It fails when
// the check no longer has the state the viewer saw, so a click on a stale page
// cannot acknowledge a newer, worse state.
func (s *Store) Ack(ctx context.Context, host, id string, state eval.State, until time.Time, by, note string, at time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var cur string
	err = tx.QueryRowContext(ctx, `SELECT state FROM checks WHERE host = ? AND id = ?`, host, id).Scan(&cur)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("no check %s/%s", host, id)
	}
	if err != nil {
		return err
	}
	if eval.State(cur) != state {
		return fmt.Errorf("check is %s now, not %s", cur, state)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO acks(host, check_id, state, until, by, note, at) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(host, check_id) DO UPDATE SET state = excluded.state, until = excluded.until,
			by = excluded.by, note = excluded.note, at = excluded.at`,
		host, id, string(state), until.Unix(), by, note, at.Unix()); err != nil {
		return err
	}
	return tx.Commit()
}

// Unack removes an acknowledgement.
func (s *Store) Unack(ctx context.Context, host, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM acks WHERE host = ? AND check_id = ?`, host, id)
	return err
}

// HostMeta is a host's label and OS as set in the UI.
type HostMeta struct {
	Label, OS, By string
	At            time.Time
}

// HostMetas returns every host's UI-set label and OS, by host.
func (s *Store) HostMetas(ctx context.Context) (map[string]HostMeta, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT host, label, os, by, at FROM host_meta`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]HostMeta{}
	for rows.Next() {
		var host string
		var m HostMeta
		var at int64
		if err := rows.Scan(&host, &m.Label, &m.OS, &m.By, &at); err != nil {
			return nil, err
		}
		m.At = time.Unix(at, 0).UTC()
		out[host] = m
	}
	return out, rows.Err()
}

// SetHostMeta stores a host's label and OS.
func (s *Store) SetHostMeta(ctx context.Context, host string, m HostMeta) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO host_meta(host, label, os, by, at) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(host) DO UPDATE SET label = excluded.label, os = excluded.os, by = excluded.by, at = excluded.at`,
		host, m.Label, m.OS, m.By, m.At.Unix())
	return err
}

// Baseline returns the accepted value of a drift check.
func (s *Store) Baseline(ctx context.Context, host, id string) (value string, at time.Time, ok bool, err error) {
	var ts int64
	err = s.db.QueryRowContext(ctx, `SELECT value, at FROM baselines WHERE host = ? AND check_id = ?`, host, id).Scan(&value, &ts)
	if errors.Is(err, sql.ErrNoRows) {
		return "", time.Time{}, false, nil
	}
	if err != nil {
		return "", time.Time{}, false, err
	}
	return value, time.Unix(ts, 0).UTC(), true, nil
}

// SetBaseline accepts value as the expected value of a drift check.
func (s *Store) SetBaseline(ctx context.Context, host, id, value, by string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO baselines(host, check_id, value, at, by) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(host, check_id) DO UPDATE SET value = excluded.value, at = excluded.at, by = excluded.by`,
		host, id, value, at.Unix(), by)
	return err
}

// SyncSeen records keys as present for host/id and returns when each was first
// seen. Keys no longer present are forgotten, so an item that comes back starts
// a fresh clock.
func (s *Store) SyncSeen(ctx context.Context, host, id string, keys []string, now time.Time) (map[string]time.Time, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `CREATE TEMP TABLE IF NOT EXISTS cur_keys (key TEXT PRIMARY KEY)`); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM cur_keys`); err != nil {
		return nil, err
	}
	for _, k := range keys {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO cur_keys(key) VALUES (?)`, k); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO seen(host, check_id, key, first_seen) VALUES (?, ?, ?, ?)`,
			host, id, k, now.Unix()); err != nil {
			return nil, err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM seen WHERE host = ? AND check_id = ? AND key NOT IN (SELECT key FROM cur_keys)`, host, id); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT key, first_seen FROM seen WHERE host = ? AND check_id = ?`, host, id)
	if err != nil {
		return nil, err
	}
	out := map[string]time.Time{}
	for rows.Next() {
		var k string
		var ts int64
		if err := rows.Scan(&k, &ts); err != nil {
			rows.Close()
			return nil, err
		}
		out[k] = time.Unix(ts, 0).UTC()
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, tx.Commit()
}

// Get reads a value from the key-value table; "" when absent.
func (s *Store) Get(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM kv WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// Set writes a value to the key-value table.
func (s *Store) Set(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO kv(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// Alert is one alert sent (or attempted) on one channel.
type Alert struct {
	TransitionID int64
	Host         string
	CheckID      string
	Channel      string
	Kind         eval.AlertKind
	At           time.Time
	Error        string
}

// RecordAlert logs an alert attempt.
func (s *Store) RecordAlert(ctx context.Context, a Alert) error {
	var tid any
	if a.TransitionID != 0 {
		tid = a.TransitionID
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO alerts_sent(transition_id, host, check_id, channel, kind, at, error) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		tid, a.Host, a.CheckID, a.Channel, string(a.Kind), a.At.Unix(), a.Error)
	return err
}

// LastAlert returns when the newest alert for a check was attempted.
func (s *Store) LastAlert(ctx context.Context, host, id string) (time.Time, error) {
	var ts sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT MAX(at) FROM alerts_sent WHERE host = ? AND check_id = ?`, host, id).Scan(&ts)
	if err != nil || !ts.Valid {
		return time.Time{}, err
	}
	return time.Unix(ts.Int64, 0).UTC(), nil
}

// Backup writes a consistent copy of the database to path, replacing any older copy.
func (s *Store) Backup(ctx context.Context, path string) error {
	tmp := path + ".tmp"
	os.Remove(tmp)
	if _, err := s.db.ExecContext(ctx, `VACUUM INTO ?`, tmp); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Unban is one row of the unbans table: one address on one host.
type Unban struct {
	ID          int64
	IP          string
	Host        string
	RequestedBy string
	RequestedAt time.Time
	SentAt      time.Time // zero until the host's report fetched it
	DoneAt      time.Time // zero until the host reported the result, or it expired
	OK          bool
	Msg         string
}

// State is waiting, sent, done, failed or expired.
func (u Unban) State() string {
	switch {
	case u.DoneAt.IsZero() && u.SentAt.IsZero():
		return "waiting"
	case u.DoneAt.IsZero():
		return "sent"
	case u.SentAt.IsZero():
		return "expired"
	case u.OK:
		return "done"
	}
	return "failed"
}

// RequestUnban queues ip for each host.
func (s *Store) RequestUnban(ctx context.Context, ip string, hosts []string, by string, at time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, h := range hosts {
		if _, err := tx.ExecContext(ctx, `INSERT INTO unbans(ip, host, requested_by, requested_at) VALUES (?, ?, ?, ?)`,
			ip, h, by, at.Unix()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// TakeUnbans returns up to limit distinct addresses waiting for host and marks
// their rows sent. Rows that waited since before oldest are expired first.
func (s *Store) TakeUnbans(ctx context.Context, host string, oldest, now time.Time, limit int) ([]string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE unbans SET done_at = ?, msg = 'expired: the host did not report within the hour'
		WHERE sent_at = 0 AND done_at = 0 AND requested_at < ?`, now.Unix(), oldest.Unix()); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT ip FROM unbans WHERE host = ? AND sent_at = 0 AND done_at = 0
		GROUP BY ip ORDER BY MIN(id) LIMIT ?`, host, limit)
	if err != nil {
		return nil, err
	}
	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			rows.Close()
			return nil, err
		}
		ips = append(ips, ip)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if _, err := tx.ExecContext(ctx, `UPDATE unbans SET sent_at = ? WHERE host = ? AND ip = ? AND sent_at = 0 AND done_at = 0`,
			now.Unix(), host, ip); err != nil {
			return nil, err
		}
	}
	return ips, tx.Commit()
}

// FinishUnban records the result host reported for ip, on host's own sent rows only.
func (s *Store) FinishUnban(ctx context.Context, host, ip string, ok bool, msg string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE unbans SET done_at = ?, ok = ?, msg = ?
		WHERE host = ? AND ip = ? AND sent_at > 0 AND done_at = 0`, at.Unix(), ok, msg, host, ip)
	return err
}

// Unbans returns the rows of the newest limit requests (one request: one
// address, one viewer, one moment, all hosts), newest first.
func (s *Store) Unbans(ctx context.Context, limit int) ([]Unban, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, ip, host, requested_by, requested_at, sent_at, done_at, ok, msg FROM unbans
		WHERE (ip, requested_by, requested_at) IN (
			SELECT ip, requested_by, requested_at FROM unbans
			GROUP BY ip, requested_by, requested_at ORDER BY MAX(id) DESC LIMIT ?)
		ORDER BY id DESC`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Unban
	for rows.Next() {
		var u Unban
		var req, sent, done int64
		if err := rows.Scan(&u.ID, &u.IP, &u.Host, &u.RequestedBy, &req, &sent, &done, &u.OK, &u.Msg); err != nil {
			return nil, err
		}
		u.RequestedAt = time.Unix(req, 0).UTC()
		if sent > 0 {
			u.SentAt = time.Unix(sent, 0).UTC()
		}
		if done > 0 {
			u.DoneAt = time.Unix(done, 0).UTC()
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
