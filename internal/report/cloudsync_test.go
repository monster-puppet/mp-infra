package report

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/eval"
)

// The NAS's connection_table on 2026-10-28, cut to the columns read: two Google
// Drive connections running and the Dropbox one stopped since 2026-08-19.
func cloudSyncDB(t *testing.T, dropboxStatus, dropboxError int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.sqlite")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{
		`CREATE TABLE connection_table (id INTEGER PRIMARY KEY, client_type INTEGER, task_name TEXT, access_token TEXT, status INTEGER, error INTEGER)`,
		`INSERT INTO connection_table VALUES (1, 1, 'monsterpuppet', 'secret', 1, 0), (2, 1, 'personal', 'secret', 1, 0)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO connection_table VALUES (3, 2, 'Dropbox', 'secret', ?, ?)`, dropboxStatus, dropboxError); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCloudSyncCheck(t *testing.T) {
	for _, c := range []struct {
		name          string
		status, errno int
		ignore        []string
		want          eval.State
		summary       string
	}{
		{"all running", 1, 0, nil, eval.OK, "3 Cloud Sync connection(s) running"},
		{"dropbox stopped", 0, -6, nil, eval.Crit, "Dropbox (status 0, error -6)"},
		{"error while running", 1, -6, nil, eval.Crit, "1 of 3"},
		{"ignored", 0, -6, []string{"Dropbox"}, eval.OK, "2 Cloud Sync connection(s) running"},
	} {
		conns, err := readCloudSync(context.Background(), cloudSyncDB(t, c.status, c.errno))
		if err != nil {
			t.Fatalf("%s: read: %v", c.name, err)
		}
		got := cloudSyncCheck("cloudsync.nas", conns, &config.CloudSync{Ignore: c.ignore})
		if got.State != c.want || !strings.Contains(got.Summary, c.summary) {
			t.Errorf("%s: %s %q", c.name, got.State, got.Summary)
		}
		if strings.Contains(string(got.Data), "secret") {
			t.Errorf("%s: token leaked into check data", c.name)
		}
	}
}

func TestCloudSyncNone(t *testing.T) {
	got := cloudSyncCheck("cloudsync.nas", nil, &config.CloudSync{})
	if got.State != eval.Warn {
		t.Errorf("no connections: %s %q", got.State, got.Summary)
	}
}

func TestReadCloudSyncMissing(t *testing.T) {
	if _, err := readCloudSync(context.Background(), filepath.Join(t.TempDir(), "nope.sqlite")); err == nil {
		t.Error("want an error for a missing database")
	}
}
