package main

import "testing"

func TestParseVersion(t *testing.T) {
	tests := []struct {
		input string
		want  [3]int
	}{
		{"0.5.0", [3]int{0, 5, 0}},
		{"v0.5.0", [3]int{0, 5, 0}},
		{"1.2.3", [3]int{1, 2, 3}},
		{"v10.0.1", [3]int{10, 0, 1}},
		{"0.0.0", [3]int{0, 0, 0}},
		{"", [3]int{0, 0, 0}},
	}
	for _, tt := range tests {
		got := parseVersion(tt.input)
		if got != tt.want {
			t.Errorf("parseVersion(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestVersionNewerOrEqual(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"0.5.0", "0.5.0", true},   // equal
		{"0.5.0", "0.4.1", true},   // newer minor
		{"0.5.0", "0.4.9", true},   // newer minor beats patch
		{"0.5.0", "0.6.0", false},  // older minor
		{"1.0.0", "0.9.9", true},   // newer major
		{"0.4.1", "0.5.0", false},  // older
		{"0.5.1", "0.5.0", true},   // newer patch
		{"0.5.0", "0.5.1", false},  // older patch
		{"v0.5.0", "0.5.0", true},  // v prefix handled
		{"0.5.0", "v0.5.0", true},  // v prefix on b
	}
	for _, tt := range tests {
		got := versionNewerOrEqual(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("versionNewerOrEqual(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestBinaryName(t *testing.T) {
	name := binaryName()
	if name != "anvil-linux-amd64" && name != "anvil-linux-arm64" {
		t.Errorf("unexpected binary name: %s", name)
	}
}
