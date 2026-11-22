// Package migrationmarker records startup data migrations for upgrade safety.
package migrationmarker

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FileName is the append-only marker stored directly under a node's data_dir.
const FileName = "migration-started.log"

type syncWriteCloser interface {
	io.Writer
	Sync() error
	Close() error
}

// Recorder returns a function that durably records the start of a migration.
func Recorder(dataDir, binaryVersion string) func(string) error {
	return func(migration string) error {
		return Record(dataDir, binaryVersion, migration)
	}
}

// Record appends and syncs a migration-start record before returning.
func Record(dataDir, binaryVersion, migration string) error {
	path := filepath.Join(dataDir, FileName)
	line := fmt.Sprintf("%s\t%s\t%s\n",
		time.Now().UTC().Format(time.RFC3339Nano), markerField(binaryVersion), markerField(migration))
	return appendAndSync(path, []byte(line), func() (syncWriteCloser, error) {
		return os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	})
}

func appendAndSync(path string, line []byte, open func() (syncWriteCloser, error)) error {
	f, err := open()
	if err != nil {
		return fmt.Errorf("open migration marker %s: %w", path, err)
	}
	if n, err := f.Write(line); err != nil {
		_ = f.Close()
		return fmt.Errorf("write migration marker %s: %w", path, err)
	} else if n != len(line) {
		_ = f.Close()
		return fmt.Errorf("write migration marker %s: %w", path, io.ErrShortWrite)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync migration marker %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close migration marker %s: %w", path, err)
	}

	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open migration marker directory: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync migration marker directory: %w", err)
	}
	return nil
}

func markerField(value string) string {
	return strings.NewReplacer("\t", "_", "\r", "_", "\n", "_").Replace(value)
}
