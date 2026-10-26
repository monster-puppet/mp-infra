//go:build windows

package report

import (
	"context"
	"fmt"
	"time"

	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/eval"
)

func windowsCollectors(host string, w *config.WindowsChecks) []collector {
	cs := []collector{
		{id: "win.tailscale_service", onError: eval.Crit, run: func(ctx context.Context) ([]Check, error) {
			out, err := powershell(ctx, fmt.Sprintf(tailscaleServiceScript, w.TailscaleService))
			if err != nil {
				return nil, err
			}
			c, err := evalTailscaleService(out)
			return []Check{c}, err
		}},
		{id: "win.fw.allow_any", onError: eval.Crit, run: func(ctx context.Context) ([]Check, error) {
			out, err := powershell(ctx, firewallAnyScript)
			if err != nil {
				return nil, err
			}
			c, err := evalFirewallAny(out, w.FirewallAllow)
			return []Check{c}, err
		}},
	}
	if w.Defender != nil && *w.Defender {
		id := "av.defender." + host
		cs = append(cs, collector{id: id, onError: eval.Warn, run: func(ctx context.Context) ([]Check, error) {
			out, err := powershell(ctx, defenderScript)
			if err != nil {
				return nil, err
			}
			c, err := evalDefender(id, out, time.Now())
			return []Check{c}, err
		}})
	}
	return cs
}
