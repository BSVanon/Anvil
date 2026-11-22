package wallet

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
)

const testWalletToolboxVersion = "v0.183.6"

func walletBuildInfo(version string, replacement *debug.Module) walletBuildInfoReader {
	return func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{Deps: []*debug.Module{{
			Path:    walletToolboxModulePath,
			Version: version,
			Replace: replacement,
		}}}, true
	}
}

func readWalletVersionFile(t *testing.T, dir string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, walletToolboxVersionFile))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestMatchingWalletVersionDoesNotRecordMigration(t *testing.T) {
	dir := t.TempDir()
	versionPath := filepath.Join(dir, walletToolboxVersionFile)
	if err := os.WriteFile(versionPath, []byte(testWalletToolboxVersion+"\n"), 0640); err != nil {
		t.Fatal(err)
	}
	state, err := prepareWalletMigrationVersion(
		dir,
		false,
		slog.Default(),
		walletBuildInfo(testWalletToolboxVersion, nil),
		[]func(string) error{func(name string) error {
			t.Fatalf("matching version recorded migration %q", name)
			return nil
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := migrateWalletStorage(func() error { return nil }, state); err != nil {
		t.Fatal(err)
	}
	if got := readWalletVersionFile(t, dir); got != testWalletToolboxVersion+"\n" {
		t.Fatalf("version file = %q", got)
	}
}

func TestExistingWalletVersionChangeRecordsBeforeMigrationAndUpdatesAfterSuccess(t *testing.T) {
	tests := []struct {
		name     string
		previous string
	}{
		{name: "different", previous: "v0.182.0\n"},
		{name: "missing"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			versionPath := filepath.Join(dir, walletToolboxVersionFile)
			if test.previous != "" {
				if err := os.WriteFile(versionPath, []byte(test.previous), 0640); err != nil {
					t.Fatal(err)
				}
			}
			var events []string
			state, err := prepareWalletMigrationVersion(
				dir,
				false,
				slog.Default(),
				walletBuildInfo(testWalletToolboxVersion, nil),
				[]func(string) error{func(name string) error {
					events = append(events, name)
					return nil
				}},
			)
			if err != nil {
				t.Fatal(err)
			}
			if err := migrateWalletStorage(func() error {
				events = append(events, "migrate")
				raw, readErr := os.ReadFile(versionPath)
				if test.previous == "" && errors.Is(readErr, os.ErrNotExist) {
					return nil
				}
				if readErr != nil {
					return readErr
				}
				if string(raw) != test.previous {
					return errors.New("version file changed before migration completed")
				}
				return nil
			}, state); err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(events, ","); got != walletSchemaMigration+",migrate" {
				t.Fatalf("events = %s", got)
			}
			if got := readWalletVersionFile(t, dir); got != testWalletToolboxVersion+"\n" {
				t.Fatalf("updated version file = %q", got)
			}
		})
	}
}

func TestFailedWalletMigrationLeavesVersionFileUnchanged(t *testing.T) {
	dir := t.TempDir()
	versionPath := filepath.Join(dir, walletToolboxVersionFile)
	const previous = "v0.182.0\n"
	if err := os.WriteFile(versionPath, []byte(previous), 0640); err != nil {
		t.Fatal(err)
	}
	state, err := prepareWalletMigrationVersion(
		dir, false, slog.Default(), walletBuildInfo(testWalletToolboxVersion, nil),
		[]func(string) error{func(string) error { return nil }},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := migrateWalletStorage(func() error { return errors.New("migration failed") }, state); err == nil {
		t.Fatal("failed migration returned nil")
	}
	if got := readWalletVersionFile(t, dir); got != previous {
		t.Fatalf("version file = %q, want %q", got, previous)
	}
}

func TestNewWalletWritesVersionAfterFirstMigrationWithoutMarker(t *testing.T) {
	dir := t.TempDir()
	versionPath := filepath.Join(dir, walletToolboxVersionFile)
	state, err := prepareWalletMigrationVersion(
		dir,
		true,
		slog.Default(),
		walletBuildInfo(testWalletToolboxVersion, nil),
		[]func(string) error{func(name string) error {
			t.Fatalf("new wallet recorded migration %q", name)
			return nil
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := migrateWalletStorage(func() error {
		if _, statErr := os.Stat(versionPath); !errors.Is(statErr, os.ErrNotExist) {
			return errors.New("version file exists before first migration completed")
		}
		return nil
	}, state); err != nil {
		t.Fatal(err)
	}
	if got := readWalletVersionFile(t, dir); got != testWalletToolboxVersion+"\n" {
		t.Fatalf("version file = %q", got)
	}
}

func TestMissingWalletBuildVersionWarnsWithoutTracking(t *testing.T) {
	dir := t.TempDir()
	versionPath := filepath.Join(dir, walletToolboxVersionFile)
	const previous = "v0.182.0\n"
	if err := os.WriteFile(versionPath, []byte(previous), 0640); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	state, err := prepareWalletMigrationVersion(
		dir,
		false,
		logger,
		walletBuildInfo("", nil),
		[]func(string) error{func(name string) error {
			t.Fatalf("missing build version recorded migration %q", name)
			return nil
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := migrateWalletStorage(func() error { return nil }, state); err != nil {
		t.Fatal(err)
	}
	if got := readWalletVersionFile(t, dir); got != previous {
		t.Fatalf("version file = %q, want %q", got, previous)
	}
	if count := strings.Count(logs.String(), walletVersionUnavailableLog); count != 1 {
		t.Fatalf("warning count = %d, logs = %q", count, logs.String())
	}
}

func TestWalletBuildVersionUsesReplacement(t *testing.T) {
	tests := []struct {
		name        string
		replacement *debug.Module
		want        string
		available   bool
	}{
		{
			name:        "module version",
			replacement: &debug.Module{Path: walletToolboxModulePath, Version: "v0.184.1"},
			want:        "v0.184.1",
			available:   true,
		},
		{
			name:        "fork version",
			replacement: &debug.Module{Path: "example.com/wallet-toolbox", Version: "v0.184.1"},
			want:        "example.com/wallet-toolbox@v0.184.1",
			available:   true,
		},
		{
			name:        "local replacement",
			replacement: &debug.Module{Path: "../wallet-toolbox"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			version, ok := walletToolboxBuildVersion(walletBuildInfo(testWalletToolboxVersion, test.replacement))
			if ok != test.available || version != test.want {
				t.Fatalf("replacement version = %q, available = %v", version, ok)
			}
		})
	}
}
