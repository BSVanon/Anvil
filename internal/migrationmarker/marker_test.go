package migrationmarker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type orderedMarkerFile struct {
	events []string
}

func (f *orderedMarkerFile) Write(p []byte) (int, error) {
	f.events = append(f.events, "write")
	return len(p), nil
}

func (f *orderedMarkerFile) Sync() error {
	f.events = append(f.events, "sync")
	return nil
}

func (f *orderedMarkerFile) Close() error {
	f.events = append(f.events, "close")
	return nil
}

func TestAppendWritesThenSyncsBeforeReturning(t *testing.T) {
	f := &orderedMarkerFile{}
	if err := appendAndSync(filepath.Join(t.TempDir(), FileName), []byte("line\n"), func() (syncWriteCloser, error) {
		return f, nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.events, ","); got != "write,sync,close" {
		t.Fatalf("marker operations = %s, want write,sync,close", got)
	}
}

func TestRecordAppendsVersionedMigrationLines(t *testing.T) {
	dir := t.TempDir()
	if err := Record(dir, "3.5.2", "messagebox-v1-to-v2"); err != nil {
		t.Fatal(err)
	}
	if err := Record(dir, "3.5.2", "legacy-overlay-v2-to-v3"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "\t3.5.2\tmessagebox-v1-to-v2") ||
		!strings.Contains(lines[1], "\t3.5.2\tlegacy-overlay-v2-to-v3") {
		t.Fatalf("marker lines = %q", lines)
	}
}
