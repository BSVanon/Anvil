package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"path"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/BSVanon/Anvil/internal/config"
	"github.com/BSVanon/Anvil/internal/overlay/routeguard"
)

// memoryLimitPercent is the share of the memory the process may use that its
// soft memory limit is set to when GOMEMLIMIT is not set: the route guard's
// budgets count what requests hold live, and only a memory limit makes the
// collector reclaim what they leave behind before the process runs out
// (routeguard.MemoryBudget). The rest is left to what the limit does not
// cover: memory outside the Go heap and the kernel's caches.
const memoryLimitPercent = 70

// configureAdmission sets what the overlay routes' admission takes from the
// process and its configuration: the soft memory limit, and the API's
// trust_proxy settings, by which the route guard finds each request's client
// as the API's rate limits do.
func configureAdmission(cfg *config.Config) {
	applyMemoryLimit(os.Getenv, os.ReadFile, log.Printf)
	routeguard.Default().TrustProxy(cfg.API.TrustProxy, cfg.API.TrustProxyHops)
}

// applyMemoryLimit sets the process's soft memory limit to memoryLimitPercent
// of the memory it may use (chooseMemoryLimit) and logs it, unless GOMEMLIMIT
// is set: the runtime has applied that value already, and it always wins.
func applyMemoryLimit(getenv func(string) string, readFile func(string) ([]byte, error), logf func(string, ...any)) {
	if v := getenv("GOMEMLIMIT"); v != "" {
		logf("  gomemlimit: %s, from GOMEMLIMIT", v)
		return
	}
	limit, of := chooseMemoryLimit(readFile)
	if limit <= 0 {
		logf("  gomemlimit: none: neither a cgroup v2 memory.max nor /proc/meminfo could be read")
		return
	}
	debug.SetMemoryLimit(limit)
	logf("  gomemlimit: %s, %d%% of %s", gib(limit), memoryLimitPercent, of)
}

// chooseMemoryLimit is memoryLimitPercent of the memory the process may use,
// and a description of where that figure came from: the least memory.max of
// the process's cgroup v2 and the cgroups above it, or the host's MemTotal in
// /proc/meminfo when that is less or no cgroup sets a limit. It is 0 when it
// can read neither.
func chooseMemoryLimit(readFile func(string) ([]byte, error)) (int64, string) {
	total, of := cgroupMemoryMax(readFile)
	if host := memTotal(readFile); host > 0 && (total <= 0 || host < total) {
		total, of = host, "the host's memory"
	}
	if total <= 0 {
		return 0, ""
	}
	return total / 100 * memoryLimitPercent, fmt.Sprintf("%s (%s)", of, gib(total))
}

// cgroupMemoryMax is the least memory.max set on the process's cgroup v2 or
// a cgroup above it, and the file it came from; 0 when none sets one.
func cgroupMemoryMax(readFile func(string) ([]byte, error)) (int64, string) {
	data, err := readFile("/proc/self/cgroup")
	if err != nil {
		return 0, ""
	}
	group := ""
	for line := range strings.SplitSeq(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			group = path.Clean("/" + rest)
			break
		}
	}
	if group == "" {
		return 0, "" // cgroup v1 only
	}
	var least int64
	var of string
	for dir := group; ; dir = path.Dir(dir) {
		file := path.Join("/sys/fs/cgroup", dir, "memory.max")
		if b, err := readFile(file); err == nil {
			if n, err := strconv.ParseInt(string(bytes.TrimSpace(b)), 10, 64); err == nil && n > 0 && (least == 0 || n < least) {
				least, of = n, "cgroup "+file
			}
		}
		if dir == "/" {
			return least, of
		}
	}
}

// memTotal is the host's MemTotal from /proc/meminfo, in bytes; 0 when it
// cannot be read.
func memTotal(readFile func(string) ([]byte, error)) int64 {
	data, err := readFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "MemTotal:"); ok {
			kb, err := strconv.ParseInt(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(rest), "kB")), 10, 64)
			if err != nil {
				return 0
			}
			return kb << 10
		}
	}
	return 0
}

// gib formats n bytes in GiB.
func gib(n int64) string { return fmt.Sprintf("%.2f GiB", float64(n)/(1<<30)) }
