package report

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/eval"
)

// collector produces checks. onError is the state a failure to collect maps to:
// crit for lockout and silent-failure checks, warn for informational ones.
type collector struct {
	id      string
	onError eval.State
	run     func(ctx context.Context) ([]Check, error)
}

const collectTimeout = 2 * time.Minute

// Collect runs every configured collector and returns the report payload. A
// collector that fails becomes a check in its onError state, so a broken collector
// is visible instead of silent.
func Collect(ctx context.Context, cfg *config.Agent, version string) *Payload {
	p := &Payload{Host: cfg.Host, AgentVersion: Clip(version, MaxVersion)}
	for _, c := range collectors(cfg) {
		cctx, cancel := context.WithTimeout(ctx, collectTimeout)
		checks, err := safeRun(cctx, c)
		cancel()
		if err != nil {
			p.Checks = append(p.Checks, Check{ID: c.id, State: c.onError, Summary: Clip("collector failed: "+err.Error(), MaxSummary)})
			continue
		}
		for _, ch := range checks {
			ch.Summary = Clip(ch.Summary, MaxSummary)
			p.Checks = append(p.Checks, ch)
		}
	}
	p.CollectedAt = time.Now().UTC().Truncate(time.Second)
	return p
}

func safeRun(ctx context.Context, c collector) (out []Check, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return c.run(ctx)
}

func collectors(cfg *config.Agent) []collector {
	cs := []collector{{id: "host.uptime", onError: eval.Warn, run: func(context.Context) ([]Check, error) {
		s, err := uptimeSeconds()
		if err != nil {
			return nil, err
		}
		return []Check{uptimeCheck(s)}, nil
	}}}
	for _, m := range cfg.Disks {
		m := m
		id := diskID(cfg.Host, m)
		cs = append(cs, collector{id: id, onError: eval.Warn, run: func(context.Context) ([]Check, error) {
			total, free, err := diskUsage(m)
			if err != nil {
				return nil, err
			}
			return []Check{diskCheck(id, m, total, free, cfg.DiskWarnPct, cfg.DiskCritPct)}, nil
		}})
	}
	if fa := cfg.Checkpoint; fa != nil {
		cs = append(cs, collector{id: "p4.checkpoint", onError: eval.Crit, run: func(context.Context) ([]Check, error) {
			c, err := checkpointCheck(fa.Path, fa.MaxAge, time.Now())
			return []Check{c}, err
		}})
	}
	if fa := cfg.OfflineDB; fa != nil {
		cs = append(cs, collector{id: "p4.offline_db", onError: eval.Crit, run: func(context.Context) ([]Check, error) {
			c, err := offlineDBCheck(fa.Path, fa.MaxAge, time.Now())
			return []Check{c}, err
		}})
	}
	if cmd := cfg.P4License; cmd != nil {
		cs = append(cs, collector{id: "p4.licence", onError: eval.Warn, run: func(ctx context.Context) ([]Check, error) {
			out, err := run(ctx, cmd.Cmd, cmd.Env)
			if err != nil {
				return nil, err
			}
			c, err := licenceCheck(out)
			return []Check{c}, err
		}})
	}
	if cmd := cfg.Firewall; cmd != nil {
		id := "fw.rules." + cfg.Host
		cs = append(cs, collector{id: id, onError: eval.Warn, run: func(ctx context.Context) ([]Check, error) {
			out, err := run(ctx, cmd.Cmd, cmd.Env)
			if err != nil {
				return nil, err
			}
			return []Check{firewallCheck(id, out)}, nil
		}})
	}
	if src := cfg.SecurityUpdates; src != "" {
		id := "os.security_updates." + cfg.Host
		cs = append(cs, collector{id: id, onError: eval.Warn, run: func(ctx context.Context) ([]Check, error) {
			items, err := securityUpdates(ctx, src)
			if err != nil {
				return nil, err
			}
			return []Check{updatesCheck(id, src, items)}, nil
		}})
	}
	for _, v := range cfg.Versions {
		v := v
		id := "pkg.version." + v.Name
		cs = append(cs, collector{id: id, onError: eval.Warn, run: func(ctx context.Context) ([]Check, error) {
			out, err := run(ctx, v.Cmd, v.Env)
			if err != nil {
				return nil, err
			}
			c, err := versionCheck(id, v, out)
			return []Check{c}, err
		}})
	}
	if af := cfg.AuthFailures; af != nil {
		id := "auth.failures." + cfg.Host
		cs = append(cs, collector{id: id, onError: eval.Warn, run: func(ctx context.Context) ([]Check, error) {
			c, err := authCheck(ctx, id, af)
			return []Check{c}, err
		}})
	}
	if l := cfg.Logins; l != nil {
		id := "auth.logins." + cfg.Host
		cs = append(cs, collector{id: id, onError: eval.Warn, run: func(ctx context.Context) ([]Check, error) {
			outs := make([]string, len(l.Sources))
			errs := make([]error, len(l.Sources))
			for i, src := range l.Sources {
				outs[i], errs[i] = run(ctx, src.Cmd, src.Env)
			}
			return []Check{evalLogins(id, l, outs, errs, time.Now())}, nil
		}})
	}
	if cfg.Accounts {
		id := "sec.accounts." + cfg.Host
		cs = append(cs, collector{id: id, onError: eval.Warn, run: func(ctx context.Context) ([]Check, error) {
			items, err := localAccounts(ctx)
			if err != nil {
				return nil, err
			}
			return []Check{itemsCheck(id, "accounts and SSH keys", items)}, nil
		}})
	}
	if cfg.Listeners {
		id := "sec.listeners." + cfg.Host
		cs = append(cs, collector{id: id, onError: eval.Warn, run: func(ctx context.Context) ([]Check, error) {
			items, err := localListeners(ctx)
			if err != nil {
				return nil, err
			}
			return []Check{itemsCheck(id, "listening ports", items)}, nil
		}})
	}
	if w := cfg.Windows; w != nil {
		cs = append(cs, windowsCollectors(w)...)
	}
	return cs
}

const maxOutput = 8 << 20

// run executes argv directly, without a shell, so no login noise (SDP's
// "Enter password" banner on monster-p4) is mixed into the output. stderr is
// returned in the error only.
func run(ctx context.Context, argv []string, env map[string]string) (string, error) {
	if len(argv) == 0 {
		return "", fmt.Errorf("empty command")
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	if len(env) > 0 {
		cmd.Env = os.Environ()
		for k, v := range env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}
	var stdout, stderr limitedBuffer
	stdout.max, stderr.max = maxOutput, 4<<10
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return stdout.String(), fmt.Errorf("%s: %v: %s", argv[0], err, msg)
		}
		return stdout.String(), fmt.Errorf("%s: %v", argv[0], err)
	}
	return stdout.String(), nil
}

type limitedBuffer struct {
	bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.Len(); room < len(p) {
		if room > 0 {
			b.Buffer.Write(p[:room])
		}
		return len(p), nil
	}
	return b.Buffer.Write(p)
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return b
}
