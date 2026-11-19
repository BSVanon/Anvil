package legacyshim_test

import (
	"bufio"
	"bytes"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/netguard/bodyread"
	"github.com/BSVanon/Anvil/internal/overlay/routeguard"
	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/BSVanon/Anvil/internal/refusallog"
)

// legacyLogs is a buffer the routes' goroutines may write while a test reads
// it.
type legacyLogs struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *legacyLogs) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *legacyLogs) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// watchRefusals makes the process-wide refusal logger, for the rest of the
// test, one that writes to the buffer returned.
func watchRefusals(t *testing.T) *legacyLogs {
	t.Helper()
	b := &legacyLogs{}
	prev := refusallog.SetDefault(refusallog.New(time.Hour, slog.New(slog.NewTextHandler(b, nil))))
	t.Cleanup(func() { refusallog.SetDefault(prev) })
	return b
}

// assertLogged fails unless the refusal log holds a line for status and
// reason on route, with the client's address.
func (b *legacyLogs) assertLogged(t *testing.T, status int, reason refusallog.Reason, route string) {
	t.Helper()
	want := []string{"status=" + strconv.Itoa(status), "reason=" + string(reason), "route=" + route, "remote_addr=127.0.0.1:"}
	for _, line := range strings.Split(b.String(), "\n") {
		ok := strings.Contains(line, "refused request")
		for _, w := range want {
			ok = ok && strings.Contains(line, w)
		}
		if ok {
			return
		}
	}
	t.Errorf("the refusal log has no line with %q:\n%s", want, b.String())
}

// TestLegacySubmit_LogsASlowBody: a submit whose body never comes is answered
// 408 once its grace has passed, and logged.
func TestLegacySubmit_LogsASlowBody(t *testing.T) {
	logs := watchRefusals(t)
	url := guardedShimServer(t, newWiredShim(t), routeguard.New(testPool, routeguard.CPUSlots, routeguard.JSONSlots, routeguard.Wait))
	conn, err := net.Dial("tcp", strings.TrimPrefix(url, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(bodyread.ReadGrace + 5*time.Second))
	if _, err := conn.Write([]byte("POST /overlay/submit HTTP/1.1\r\nHost: anvil.test\r\nContent-Type: application/octet-stream\r\nX-Topics: [\"" + topics.UHRPTopicName + "\"]\r\nContent-Length: 1024\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusRequestTimeout {
		t.Fatalf("a body that never comes: %d, want 408", resp.StatusCode)
	}
	logs.assertLogged(t, http.StatusRequestTimeout, refusallog.ReasonSlowBody, "/overlay/submit")
}

// TestLegacySubmit_LogsABodyOverItsCap: a body over the route's cap is
// answered 400 and logged under its own reason.
func TestLegacySubmit_LogsABodyOverItsCap(t *testing.T) {
	logs := watchRefusals(t)
	shim := newWiredShim(t)
	shim.MaxBodyBytes = 1 << 10
	url := guardedShimServer(t, shim, routeguard.New(testPool, routeguard.CPUSlots, routeguard.JSONSlots, routeguard.Wait))
	if code, raw := submitUHRP(t, url, make([]byte, 4<<10)); code != http.StatusBadRequest {
		t.Fatalf("a body over the cap: %d %s, want 400", code, raw)
	}
	logs.assertLogged(t, http.StatusBadRequest, refusallog.ReasonBodyRejected, "/overlay/submit")
}
