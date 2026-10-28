// Command edr-center is the audit operations center: it ingests signed events
// from agents, stores them per host, checks chain continuity, and serves
// aggregated queries.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"edr/internal/center"
)

var version = "v2.0.0-m8"

func main() {
	listen := flag.String("listen", "127.0.0.1:7080", "listen address")
	dataDir := flag.String("data-dir", "/var/lib/edr-center", "event store directory")
	secret := flag.String("shared-secret", "", "shared secret for HMAC request auth (required)")
	secretFile := flag.String("shared-secret-file", "", "read the shared secret from this file (preferred over --shared-secret)")
	flag.Parse()

	if *secret == "" && *secretFile != "" {
		raw, err := os.ReadFile(*secretFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "edr-center:", err)
			os.Exit(1)
		}
		*secret = strings.TrimSpace(string(raw))
	}
	if *secret == "" {
		fmt.Fprintln(os.Stderr, "edr-center: a shared secret (--shared-secret or --shared-secret-file) is required")
		os.Exit(1)
	}
	store, err := center.Open(*dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "edr-center:", err)
		os.Exit(1)
	}
	cases, err := center.OpenCases(*dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "edr-center:", err)
		os.Exit(1)
	}
	actions, err := center.OpenActions(*dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "edr-center:", err)
		os.Exit(1)
	}
	srv := center.NewServer(store, []byte(*secret)).WithCases(cases).WithActions(actions)
	fmt.Fprintf(os.Stderr, "edr-center %s listening on %s (data=%s)\n", version, *listen, *dataDir)
	if err := http.ListenAndServe(*listen, srv.Handler()); err != nil {
		fmt.Fprintln(os.Stderr, "edr-center:", err)
		os.Exit(1)
	}
}
