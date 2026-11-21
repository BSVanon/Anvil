package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"path"
	"runtime/debug"
	"slices"
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

// budgetFloor is the heap the overlay guard may hold reserved at once: the
// route guard's own MemoryBudget plus the execution slot's ExecAllowance,
// read from routeguard rather than repeated here so the two figures can
// never drift apart (about 484 MiB at the budgets in internal/overlay/routeguard).
var budgetFloor = routeguard.MemoryBudget + routeguard.ExecAllowance

// applyMemoryLimit sets the process's soft memory limit to memoryLimitPercent
// of the memory it may use (chooseMemoryLimit) and logs it, unless GOMEMLIMIT
// is set: the runtime has applied that value already, and it always wins.
// Either way, a limit under budgetFloor is warned about once: the collector
// would then not be made to reclaim fast enough to keep what the guard admits
// within what the process may use.
func applyMemoryLimit(getenv func(string) string, readFile func(string) ([]byte, error), logf func(string, ...any)) {
	if v := getenv("GOMEMLIMIT"); v != "" {
		logf("  gomemlimit: %s, from GOMEMLIMIT", v)
		warnBelowBudget(debug.SetMemoryLimit(-1), logf)
		return
	}
	limit, of := chooseMemoryLimit(readFile)
	if limit <= 0 {
		logf("  gomemlimit: none: neither a cgroup v2 memory.max, cgroup v1's memory.limit_in_bytes, nor /proc/meminfo could be read")
		return
	}
	debug.SetMemoryLimit(limit)
	logf("  gomemlimit: %s, %d%% of %s", gib(limit), memoryLimitPercent, of)
	warnBelowBudget(limit, logf)
}

// warnBelowBudget logs once when limit is set (positive) but under
// budgetFloor, whichever path chose it.
func warnBelowBudget(limit int64, logf func(string, ...any)) {
	if limit > 0 && limit < budgetFloor {
		logf("  gomemlimit: %s is below the overlay guard's own budget of %s (MemoryBudget + ExecAllowance); it may be killed under load rather than refuse requests", gib(limit), gib(budgetFloor))
	}
}

// chooseMemoryLimit is memoryLimitPercent of the memory the process may use,
// and a description of where that figure came from: the least memory limit
// of the process's cgroup v2 or v1 and the cgroups above it, or the host's
// MemTotal in /proc/meminfo when that is less or no cgroup sets a limit. It
// is 0 when it can read neither.
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

// cgroupV1Unlimited is cgroup v1's sentinel for "no limit" on
// memory.limit_in_bytes: a value near the signed 64-bit maximum, rounded
// down to a page boundary, which varies by kernel and page size. Anything at
// least 2^60 bytes (1 EiB) is far past any real limit, so it is treated as
// unlimited, the same as v2's "max".
const cgroupV1Unlimited = int64(1) << 60

// cgroupMemoryMax is the least memory.max set on the process's cgroup v2 path
// and the cgroups above it ("max" ignored), and the file it came from; or,
// when v2 sets none, the least memory.limit_in_bytes on its cgroup v1 memory
// path and above (the "unlimited" sentinel ignored); 0, "" when neither can
// be read.
func cgroupMemoryMax(readFile func(string) ([]byte, error)) (int64, string) {
	data, err := readFile("/proc/self/cgroup")
	if err != nil {
		return 0, ""
	}
	v2, v1 := "", ""
	for line := range strings.SplitSeq(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			v2 = path.Clean("/" + rest)
			continue
		}
		if _, rest, ok := strings.Cut(line, ":"); ok {
			if controllers, cgpath, ok := strings.Cut(rest, ":"); ok && slices.Contains(strings.Split(controllers, ","), "memory") {
				v1 = path.Clean("/" + cgpath)
			}
		}
	}
	if v2 != "" {
		if n, of := leastCgroupLimit(readFile, "/sys/fs/cgroup", v2, "memory.max", 0); n > 0 {
			return n, of
		}
	}
	if v1 != "" {
		if n, of := leastCgroupLimit(readFile, "/sys/fs/cgroup/memory", v1, "memory.limit_in_bytes", cgroupV1Unlimited); n > 0 {
			return n, of
		}
	}
	return 0, ""
}

// leastCgroupLimit is the least positive integer in file on group and the
// cgroups above it under root, and the file it came from; 0, "" when none
// has one. A value at or past ignoreAt, when ignoreAt is over 0, is treated
// as no limit, as v2's "max" already is by failing to parse.
func leastCgroupLimit(readFile func(string) ([]byte, error), root, group, file string, ignoreAt int64) (int64, string) {
	var least int64
	var of string
	for dir := group; ; dir = path.Dir(dir) {
		f := path.Join(root, dir, file)
		if b, err := readFile(f); err == nil {
			if n, err := strconv.ParseInt(string(bytes.TrimSpace(b)), 10, 64); err == nil && n > 0 &&
				(ignoreAt <= 0 || n < ignoreAt) && (least == 0 || n < least) {
				least, of = n, "cgroup "+f
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
