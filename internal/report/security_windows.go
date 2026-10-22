//go:build windows

package report

import "context"

func localAccounts(ctx context.Context) ([]string, error) {
	out, err := powershell(ctx, windowsAccountsScript)
	if err != nil {
		return nil, err
	}
	return parseWindowsAccounts(out), nil
}

func localListeners(ctx context.Context) ([]string, error) {
	out, err := powershell(ctx, windowsListenersScript)
	if err != nil {
		return nil, err
	}
	return parseWindowsListeners(out), nil
}
