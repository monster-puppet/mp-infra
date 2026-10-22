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
