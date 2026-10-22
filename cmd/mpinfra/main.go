// Command mpinfra is Monster Puppet's infrastructure watch. See docs/spec.md.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/monster-puppet/mp-infra/internal/config"
	"github.com/monster-puppet/mp-infra/internal/report"
	"github.com/monster-puppet/mp-infra/internal/server"
	"github.com/monster-puppet/mp-infra/internal/store"
	"github.com/monster-puppet/mp-infra/internal/web"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "report":
		err = reportCmd(os.Args[2:], true)
	case "check":
		err = reportCmd(os.Args[2:], false)
	case "token":
		err = tokenCmd(os.Stdout)
	case "version":
		fmt.Println(version)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "mpinfra "+os.Args[1]+": "+err.Error())
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: mpinfra <command> [flags]

  serve   -config FILE   UI, report API, probes and alerts
  report  -config FILE   collect local facts and send them to serve
  check   -config FILE   collect local facts and print the JSON; send nothing
  token                  print a new report token and the hash for MPINFRA_REPORT_TOKENS
  version`)
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/mp-infra/config.yaml", "config file")
	addr := fs.String("addr", "", "UI listen address (overrides ui_addr)")
	reportAddr := fs.String("report-addr", "", "report API listen address (overrides report_addr)")
	dbPath := fs.String("db", "", "SQLite database (overrides db)")
	insecure := fs.Bool("insecure-bind", false, "allow binding to a non-tailnet, non-loopback address")
	fs.Parse(args)

	cfg, err := config.LoadServer(*cfgPath)
	if err != nil {
		return err
	}
	if *addr != "" {
		cfg.UIAddr = *addr
	}
	if *reportAddr != "" {
		cfg.ReportAddr = *reportAddr
	}
	if *dbPath != "" {
		cfg.DB = *dbPath
	}
	if cfg.UIAddr == "" || cfg.ReportAddr == "" || cfg.DB == "" {
		return errors.New("ui_addr, report_addr and db must be set")
	}
	if err := checkAddrs(cfg.UIAddr, cfg.ReportAddr, *insecure); err != nil {
		return err
	}
	tokens, err := cfg.ReportTokens()
	if err != nil {
		return err
	}
	if len(tokens) == 0 {
		log.Printf("warning: no report tokens in %s; every report will be refused", cfg.ReportTokensEnv)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.DB), 0o750); err != nil {
		return err
	}
	st, err := store.Open(cfg.DB)
	if err != nil {
		return err
	}
	defer st.Close()

	srv := server.New(cfg, st, tokens, version)
	var who web.Whoiser
	if _, err := os.Stat(web.DefaultTailscaleSocket); err == nil {
		who = web.NewTailscaleWhois(web.DefaultTailscaleSocket)
	} else {
		log.Printf("tailscaled socket not found; viewers are shown by address")
	}
	w := web.New(srv, who)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errc := make(chan error, 2)
	servers := []*http.Server{
		{Addr: cfg.UIAddr, Handler: w.UI()},
		{Addr: cfg.ReportAddr, Handler: w.Reports()},
	}
	for _, hs := range servers {
		hs.ReadHeaderTimeout = 10 * time.Second
		hs.ReadTimeout = 30 * time.Second
		hs.WriteTimeout = 30 * time.Second
		hs.IdleTimeout = 2 * time.Minute
		hs.MaxHeaderBytes = 16 << 10
		go func(hs *http.Server) {
			if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}(hs)
	}
	log.Printf("mpinfra %s: UI on %s, reports on %s, db %s", version, cfg.UIAddr, cfg.ReportAddr, cfg.DB)
	go srv.Run(ctx)

	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, hs := range servers {
		hs.Shutdown(sctx)
	}
	return err
}

// checkAddrs applies the bind check to both listeners and keeps them apart, so
// the untrusted agent that may reach the report port never reaches the UI.
func checkAddrs(ui, rep string, insecure bool) error {
	if err := checkBind(ui, insecure); err != nil {
		return err
	}
	if err := checkBind(rep, insecure); err != nil {
		return err
	}
	if ui == rep {
		return fmt.Errorf("ui_addr and report_addr must differ (both %s)", ui)
	}
	return nil
}

// tailnet is Tailscale's CGNAT range.
var tailnet = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// checkBind refuses any listen address that is not loopback or on the tailnet,
// so a config mistake cannot expose the UI publicly.
func checkBind(addr string, insecure bool) error {
	if insecure {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || !(ip.IsLoopback() || tailnet.Contains(ip)) {
		return fmt.Errorf("refusing to bind %s: not loopback or tailnet (pass -insecure-bind to override)", addr)
	}
	return nil
}

func reportCmd(args []string, send bool) error {
	name := "check"
	if send {
		name = "report"
	}
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/mp-infra/agent.yaml", "agent config file")
	fs.Parse(args)
	cfg, err := config.LoadAgent(*cfgPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	p := report.Collect(ctx, cfg, version)
	if !send {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(p)
	}
	if cfg.ServerURL == "" {
		return errors.New("server_url is not set")
	}
	tok, err := cfg.ReportToken()
	if err != nil {
		return err
	}
	return report.Send(ctx, nil, cfg.ServerURL, tok, p)
}

// tokenCmd prints a fresh random token for agent.yaml and its SHA-256 for the
// server's MPINFRA_REPORT_TOKENS.
func tokenCmd(w io.Writer) error {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	tok := hex.EncodeToString(b)
	sum := sha256.Sum256([]byte(tok))
	fmt.Fprintf(w, "token:  %s\nsha256: %s\n", tok, hex.EncodeToString(sum[:]))
	fmt.Fprintln(w, strings.TrimSpace(`
Put the token in the host's agent.yaml (token: ...) and add host=<sha256> to
MPINFRA_REPORT_TOKENS on the server. Do not store the token anywhere else.`))
	return nil
}
