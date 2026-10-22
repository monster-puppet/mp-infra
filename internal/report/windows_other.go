//go:build !windows

package report

import (
	"context"
	"errors"

	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/eval"
)

// windowsCollectors reports a configuration error: the windows section only works
// in the Windows build.
func windowsCollectors(*config.WindowsChecks) []collector {
	return []collector{{id: "win.config", onError: eval.Warn, run: func(context.Context) ([]Check, error) {
		return nil, errors.New("windows checks are configured but this agent is not a Windows build")
	}}}
}
