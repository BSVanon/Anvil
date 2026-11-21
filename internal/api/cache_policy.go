package api

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"strings"
)

type cachePolicyKey struct{}

// contentCachePolicy preserves content's cache policy unless a token gate is
// configured, when its response can depend on a credential.
func contentCachePolicy(s *Server, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		policy := func() bool { return s.tokenGate != nil }
		next(w, r.WithContext(context.WithValue(r.Context(), cachePolicyKey{}, policy)))
	}
}

// credentialDependentRead prevents a shared cache from reusing any response
// whose representation can vary with the node operator credential.
func credentialDependentRead(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if policy, ok := r.Context().Value(cachePolicyKey{}).(func() bool); ok && !policy() {
			next(w, r)
			return
		}
		cw := &credentialCacheWriter{ResponseWriter: w}
		cw.apply()
		next(cw, r)
	}
}

type credentialCacheWriter struct {
	http.ResponseWriter
}

func (w *credentialCacheWriter) apply() {
	h := w.Header()
	h.Set("Cache-Control", "private, no-store")
	addVary(h, "Authorization")
	addVary(h, "X-Anvil-Auth")
}

func (w *credentialCacheWriter) WriteHeader(status int) {
	w.apply()
	w.ResponseWriter.WriteHeader(status)
}

func (w *credentialCacheWriter) Write(p []byte) (int, error) {
	w.apply()
	return w.ResponseWriter.Write(p)
}

func (w *credentialCacheWriter) Flush() {
	w.apply()
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *credentialCacheWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return h.Hijack()
}

func (w *credentialCacheWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func addVary(h http.Header, name string) {
	for _, line := range h.Values("Vary") {
		for _, field := range strings.Split(line, ",") {
			if strings.EqualFold(strings.TrimSpace(field), name) {
				return
			}
		}
	}
	h.Add("Vary", name)
}
