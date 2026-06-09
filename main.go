// NetAnchor — a simple, web-based certificate authority written in pure Go.
//
// Everything is backed by the Go standard library: net/http for the GUI,
// crypto/x509 for the PKI work, crypto/pbkdf2 + crypto/aes for passphrase and
// password protection, crypto/hmac for sessions, and crypto/tls for HTTPS. No
// external dependencies, single static binary, data stored as PEM/JSON on disk.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	addr := flag.String("addr", envOr("NETANCHOR_ADDR", "127.0.0.1:8443"),
		"address to listen on (env NETANCHOR_ADDR)")
	dataDir := flag.String("data", envOr("NETANCHOR_DATA", "./netanchor-data"),
		"directory to store data (env NETANCHOR_DATA)")
	health := flag.Bool("health", false, "probe a running server's /healthz and exit (for container HEALTHCHECK)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("NetAnchor " + version)
		return
	}

	tlsEnabled := !strings.EqualFold(envOr("NETANCHOR_TLS", "on"), "off")

	if *health {
		os.Exit(runHealthCheck(*addr, tlsEnabled))
	}

	store, err := OpenStore(*dataDir)
	if err != nil {
		log.Fatalf("opening store: %v", err)
	}

	authEnabled := !envBool("NETANCHOR_DISABLE_AUTH")

	auth, err := NewAuth(store, tlsEnabled, authEnabled)
	if err != nil {
		log.Fatalf("initializing auth: %v", err)
	}

	srv := NewServer(store, auth)
	httpServer := &http.Server{
		Addr:              *addr,
		Handler:           auth.Middleware(srv.Routes()),
		ReadHeaderTimeout: 10 * time.Second,
	}

	scheme := "http"
	var certFile, keyFile string
	if tlsEnabled {
		hosts := splitComma(envOr("NETANCHOR_TLS_HOSTS", "localhost,127.0.0.1"))
		var descr string
		certFile, keyFile, descr, err = ensureServerCert(store, hosts, envOr("NETANCHOR_CA_PASSPHRASE", ""))
		if err != nil {
			log.Fatalf("preparing TLS certificate: %v", err)
		}
		scheme = "https"
		log.Printf("TLS enabled — server certificate: %s (hosts: %s)", descr, strings.Join(hosts, ", "))
	}

	errc := make(chan error, 1)
	go func() {
		if tlsEnabled {
			errc <- httpServer.ListenAndServeTLS(certFile, keyFile)
		} else {
			errc <- httpServer.ListenAndServe()
		}
	}()

	log.Printf("NetAnchor %s — listening on %s://%s  (data dir: %s)", version, scheme, *addr, *dataDir)
	if authEnabled {
		log.Printf("Authentication is ON. First run: open %s://%s to create the admin account.", scheme, *addr)
	} else {
		log.Printf("Authentication is OFF (NETANCHOR_DISABLE_AUTH set). Do not expose this beyond a trusted host.")
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errc:
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	case sig := <-stop:
		log.Printf("received %s, shutting down...", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(ctx); err != nil {
			log.Printf("graceful shutdown failed: %v", err)
		}
	}
}

// runHealthCheck probes /healthz on the local server and returns a process exit
// code (0 healthy, 1 unhealthy). It is used by the container HEALTHCHECK so the
// image needs no extra tools, and it tolerates the self-signed TLS certificate.
func runHealthCheck(addr string, tlsEnabled bool) int {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host, port = "127.0.0.1", "8443"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	scheme := "http"
	client := &http.Client{Timeout: 3 * time.Second}
	if tlsEnabled {
		scheme = "https"
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	resp, err := client.Get(scheme + "://" + host + ":" + port + "/healthz")
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return 0
	}
	return 1
}

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func envBool(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
