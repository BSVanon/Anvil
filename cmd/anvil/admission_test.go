package main

import (
	"fmt"
	"io/fs"
	"math"
	"runtime/debug"
	"strings"
	"testing"
)

// files is a fake file system for chooseMemoryLimit.
type files map[string]string

func (f files) read(name string) ([]byte, error) {
	if s, ok := f[name]; ok {
		return []byte(s), nil
	}
	return nil, fs.ErrNotExist
}

const meminfo8G = "MemTotal:        8388608 kB\nMemFree:         1234 kB\n"

// TestChooseMemoryLimit: 70% of the least memory.max on the process's cgroup
// v2 path, or of the host's MemTotal when that is less or no cgroup sets a
// limit; nothing when neither can be read.
func TestChooseMemoryLimit(t *testing.T) {
	const service = "/sys/fs/cgroup/system.slice/anvil.service/memory.max"
	const slice = "/sys/fs/cgroup/system.slice/memory.max"
	for _, c := range []struct {
		name  string
		files files
		want  int64
		from  string
	}{
		{"the service's limit", files{"/proc/self/cgroup": "0::/system.slice/anvil.service\n", service: "2147483648\n", slice: "max\n", "/proc/meminfo": meminfo8G}, 2 << 30 / 100 * 70, service},
		{"a parent's lower limit", files{"/proc/self/cgroup": "0::/system.slice/anvil.service\n", service: "2147483648\n", slice: "1073741824\n", "/proc/meminfo": meminfo8G}, 1 << 30 / 100 * 70, slice},
		{"a container's root", files{"/proc/self/cgroup": "0::/\n", "/sys/fs/cgroup/memory.max": "536870912\n", "/proc/meminfo": meminfo8G}, 512 << 20 / 100 * 70, "/sys/fs/cgroup/memory.max"},
		{"no limit set", files{"/proc/self/cgroup": "0::/system.slice/anvil.service\n", service: "max\n", "/proc/meminfo": meminfo8G}, 8 << 30 / 100 * 70, "host"},
		{"a limit over the host's memory", files{"/proc/self/cgroup": "0::/user.slice\n", "/sys/fs/cgroup/user.slice/memory.max": "68719476736\n", "/proc/meminfo": meminfo8G}, 8 << 30 / 100 * 70, "host"},
		{"cgroup v1 only", files{"/proc/self/cgroup": "12:memory:/user.slice\n1:name=systemd:/user.slice\n", "/proc/meminfo": meminfo8G}, 8 << 30 / 100 * 70, "host"},
		{"no /proc/self/cgroup", files{"/proc/meminfo": meminfo8G}, 8 << 30 / 100 * 70, "host"},
		{"nothing readable", files{}, 0, ""},
		{"an unreadable meminfo", files{"/proc/meminfo": "MemTotal: lots\n"}, 0, ""},
	} {
		got, of := chooseMemoryLimit(c.files.read)
		if got != c.want || !strings.Contains(of, c.from) {
			t.Errorf("%s: %d from %q, want %d from %q", c.name, got, of, c.want, c.from)
		}
	}
}

// TestApplyMemoryLimit: unset, GOMEMLIMIT is chosen, applied and logged; set,
// it wins, and the limit the runtime took from it is left alone.
func TestApplyMemoryLimit(t *testing.T) {
	orig := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(orig) })
	fake := files{"/proc/meminfo": meminfo8G}
	var logged []string
	logf := func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }

	applyMemoryLimit(func(string) string { return "" }, fake.read, logf)
	want := int64(8 << 30 / 100 * 70)
	if got := debug.SetMemoryLimit(-1); got != want {
		t.Fatalf("unset GOMEMLIMIT: the limit is %d, want %d", got, want)
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "5.60 GiB, 70% of the host's memory (8.00 GiB)") {
		t.Fatalf("logged %q", logged)
	}

	debug.SetMemoryLimit(math.MaxInt64)
	logged = nil
	applyMemoryLimit(func(k string) string {
		if k == "GOMEMLIMIT" {
			return "off"
		}
		return ""
	}, fake.read, logf)
	if got := debug.SetMemoryLimit(-1); got != math.MaxInt64 {
		t.Fatalf("GOMEMLIMIT=off: the limit was changed to %d", got)
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "off, from GOMEMLIMIT") {
		t.Fatalf("logged %q", logged)
	}

	logged = nil
	applyMemoryLimit(func(string) string { return "" }, files{}.read, logf)
	if got := debug.SetMemoryLimit(-1); got != math.MaxInt64 || len(logged) != 1 || !strings.Contains(logged[0], "none") {
		t.Fatalf("nothing readable: limit %d, logged %q", got, logged)
	}
}
