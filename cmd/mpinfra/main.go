// Command mpinfra is Monster Puppet's infrastructure watch.
//
// This is the phase 0 skeleton: subcommand wiring and a placeholder page.
// See docs/spec.md for the build plan.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		serve(os.Args[2:])
	case "report", "check":
		fmt.Fprintln(os.Stderr, os.Args[1]+": not implemented yet (spec phase 0)")
		os.Exit(1)
	case "version":
		fmt.Println(version)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: mpinfra serve|report|check|version [flags]")
}

func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8098", "UI listen address (tailnet IP in production)")
	_ = fs.String("config", "config.example.yaml", "config file")
	insecure := fs.Bool("insecure-bind", false, "allow binding to a non-tailnet, non-loopback address")
	fs.Parse(args)

	if err := checkBind(*addr, *insecure); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "mp-infra %s: nothing to show yet\n", version)
	})
	log.Printf("mpinfra %s listening on %s", version, *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
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
