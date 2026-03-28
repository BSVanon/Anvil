package main

import "testing"

func TestIsValidPublicIPv4(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		// Valid IPv4
		{"89.144.47.58", true},
		{"212.56.43.191", true},
		{"1.2.3.4", true},

		// IPv6 — must reject
		{"2a0f:85c1:b73:5dd::a", false},
		{"::1", false},
		{"fe80::1%eth0", false},

		// Empty / garbage
		{"", false},
		{"not-an-ip", false},
		{"<html>error</html>", false},

		// Localhost — technically valid IPv4, but parseable
		{"127.0.0.1", true},

		// IPv4-mapped IPv6 — contains colon, rejected
		{"::ffff:89.144.47.58", false},
	}
	for _, tt := range tests {
		got := isValidPublicIPv4(tt.input)
		if got != tt.want {
			t.Errorf("isValidPublicIPv4(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
