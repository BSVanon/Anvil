package main

import (
	"crypto/tls"
	"net/http"
	"time"
)

// apiIdleTimeout bounds how long a kept-alive API or TLS connection may sit
// open between requests. ReadHeaderTimeout alone only covers a connection
// mid-request; with no IdleTimeout a connection that finished a request,
// including one routeguard refused, and then sends nothing more stays open
// until the client or the OS gives up. ReadTimeout is deliberately left
// unset here, not just defaulted: it would cut an open SSE stream short,
// and would otherwise have to exceed the 120s BEEF submit window.
const apiIdleTimeout = 120 * time.Second

// newAPIServer builds a plain-HTTP API or mesh server with the timeouts
// every one of Anvil's public listeners needs.
func newAPIServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       apiIdleTimeout,
	}
}

// newTLSAPIServer is newAPIServer with a minimum TLS version set.
func newTLSAPIServer(addr string, handler http.Handler) *http.Server {
	srv := newAPIServer(addr, handler)
	srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return srv
}
