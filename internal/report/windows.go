//go:build windows

package report

import (
	"context"
	"fmt"

	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/eval"
)

func windowsCollectors(w *config.WindowsChecks) []collector {
	return []collector{
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
}
