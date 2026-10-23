package server

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/monster-puppet/mp-infra/internal/report"
	"github.com/monster-puppet/mp-infra/internal/store"
)

// Unban: an admin pastes an address in the UI, and each host whose agent allows
// it (fail2ban.unban, reported as "unban": true in sec.fail2ban.<host>) gets it
// in the reply to its next report. The server sends only addresses, never
// commands; the agent checks them again and runs one fixed command.

// UnbanMaxAge is how long a request waits for its host's next report.
const UnbanMaxAge = time.Hour

// f2bData is the part of a sec.fail2ban.<host> check the unban feature reads.
type f2bData struct {
	Unban     bool                 `json:"unban"`
	BannedIPs []string             `json:"banned_ips"`
	Results   []report.UnbanResult `json:"unban_results"`
}

// UnbanHosts returns the hosts whose latest fail2ban data allows unbans, and the
// banned addresses each one reported.
func (s *Server) UnbanHosts(ctx context.Context) (hosts []string, banned map[string][]string, err error) {
	checks, err := s.Store.Checks(ctx)
	if err != nil {
		return nil, nil, err
	}
	banned = map[string][]string{}
	for _, c := range checks {
		if !s.Cfg.HasHost(c.Host) || s.Cfg.IsEndpoint(c.Host) || c.ID != "sec.fail2ban."+c.Host {
			continue
		}
		var d f2bData
		if json.Unmarshal([]byte(c.Data), &d) != nil {
			continue
		}
		banned[c.Host] = d.BannedIPs
		if d.Unban {
			hosts = append(hosts, c.Host)
		}
	}
	return hosts, banned, nil
}

// ErrNoUnbanHosts is returned by RequestUnban when no host accepts unbans.
var ErrNoUnbanHosts = errors.New("no host accepts unbans: set fail2ban: {unban: true} in a host's agent.yaml")

// RequestUnban queues ip on every host that accepts unbans and returns them.
// The caller has checked that by is an admin.
func (s *Server) RequestUnban(ctx context.Context, ip, by string) ([]string, error) {
	a, err := report.ParseUnbanIP(ip)
	if err != nil {
		return nil, err
	}
	hosts, _, err := s.UnbanHosts(ctx)
	if err != nil {
		return nil, err
	}
	if len(hosts) == 0 {
		return nil, ErrNoUnbanHosts
	}
	if err := s.Store.RequestUnban(ctx, a.String(), hosts, by, s.Now()); err != nil {
		return nil, err
	}
	return hosts, nil
}

// TakeUnbans returns the addresses waiting for host and marks them sent; the
// report handler puts them in its reply. Nothing while no admin is configured.
func (s *Server) TakeUnbans(ctx context.Context, host string) ([]string, error) {
	if len(s.Cfg.Admins) == 0 {
		return nil, nil
	}
	now := s.Now()
	return s.Store.TakeUnbans(ctx, host, now.Add(-UnbanMaxAge), now, report.MaxUnbans)
}

// unbanResults records the unban results a report carries. They update host's
// own rows only; an address that is not one is ignored.
func (s *Server) unbanResults(ctx context.Context, host string, p *report.Payload, now time.Time) {
	for _, c := range p.Checks {
		if c.ID != "sec.fail2ban."+host {
			continue
		}
		var d f2bData
		if json.Unmarshal(c.Data, &d) != nil {
			return
		}
		for i, r := range d.Results {
			if i == report.MaxUnbans {
				break
			}
			a, err := report.ParseUnbanIP(r.IP)
			if err != nil {
				continue
			}
			if err := s.Store.FinishUnban(ctx, host, a.String(), r.OK, report.Clip(r.Msg, 200), now); err != nil {
				log.Printf("unban result %s %s: %v", host, a, err)
			}
		}
	}
}

// Unbans returns the newest requests for the UI.
func (s *Server) Unbans(ctx context.Context, limit int) ([]store.Unban, error) {
	return s.Store.Unbans(ctx, limit)
}
