package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestDoctorBRC121 checks the doctor's BRC-121 line against the operator's
// /stats view: a full journal is an issue; a journal under its cap, BRC-121
// off, a missing token or an older node are not.
func TestDoctorBRC121(t *testing.T) {
	cases := []struct {
		name, body, token string
		issues            int
	}{
		{"journal full", `{"brc121":{"offered":true,"journal":{"entries":4096,"cap":4096,"oldest_age_secs":120}}}`, "tok", 1},
		{"journal under its cap", `{"brc121":{"offered":true,"journal":{"entries":3,"cap":4096,"oldest_age_secs":120}}}`, "tok", 0},
		{"not offered", `{"brc121":{"offered":false,"reason":"no ARC client"}}`, "tok", 0},
		{"failed stats read", `{}`, "tok", 1},
		{"setup failure", `{"brc121":{"offered":false,"reason":"open journal: permission denied"}}`, "tok", 1},
		{"no token", `{}`, "", 0},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/stats" || r.Header.Get("Authorization") != "Bearer tok" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(tc.body))
		}))
		if got := doctorBRC121(srv.URL, tc.token); got != tc.issues {
			t.Errorf("%s: %d issues, want %d", tc.name, got, tc.issues)
		}
		srv.Close()
	}
}
