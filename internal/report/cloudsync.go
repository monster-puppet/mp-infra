package report

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"

	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/eval"
	_ "modernc.org/sqlite"
)

// --- cloudsync.<host> ---
//
// Synology Cloud Sync keeps its connections in an SQLite file. A connection whose
// cloud login breaks (the NAS↔Dropbox link, 2026-08-19) stops with an error code
// and stays stopped without any alert in DSM, so the agent reads that table.

// cloudSyncConn is one row of Cloud Sync's connection_table.
type cloudSyncConn struct {
	Task   string `json:"task"`
	Status int    `json:"status"` // 1 = running; 0 = stopped (seen with error -6)
	Error  int    `json:"error"`  // 0 = none
}

// readCloudSync lists the connections, read-only.
func readCloudSync(ctx context.Context, path string) ([]cloudSyncConn, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx, `SELECT task_name, status, error FROM connection_table ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []cloudSyncConn
	for rows.Next() {
		var c cloudSyncConn
		var task sql.NullString
		if err := rows.Scan(&task, &c.Status, &c.Error); err != nil {
			return nil, err
		}
		c.Task = Clip(task.String, 64)
		out = append(out, c)
	}
	return out, rows.Err()
}

// cloudSyncCheck is crit when a watched connection is not running or has an error.
func cloudSyncCheck(id string, conns []cloudSyncConn, cfg *config.CloudSync) Check {
	c := Check{ID: id, State: eval.OK, Data: mustJSON(map[string]any{"connections": conns})}
	var bad []string
	watched := 0
	for _, conn := range conns {
		if slices.Contains(cfg.Ignore, conn.Task) {
			continue
		}
		watched++
		if conn.Status != 1 || conn.Error != 0 {
			bad = append(bad, fmt.Sprintf("%s (status %d, error %d)", conn.Task, conn.Status, conn.Error))
		}
	}
	switch {
	case watched == 0:
		c.State, c.Summary = eval.Warn, "no Cloud Sync connections to watch"
	case len(bad) > 0:
		c.State = eval.Crit
		c.Summary = fmt.Sprintf("%d of %d Cloud Sync connection(s) stopped: %s. Re-link it in DSM → Cloud Sync",
			len(bad), watched, strings.Join(bad, ", "))
	default:
		c.Summary = fmt.Sprintf("%d Cloud Sync connection(s) running", watched)
	}
	return c
}
