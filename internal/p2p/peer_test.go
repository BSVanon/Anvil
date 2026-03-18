package p2p

import (
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/libsv/go-p2p/wire"
)

// mockBSVNode runs a minimal Bitcoin P2P handshake server on a random port.
// It responds to version with version+verack, completing the handshake.
func mockBSVNode(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))

		// Read client's version
		msg, _, err := wire.ReadMessage(conn, protocolVersion, wire.MainNet)
		if err != nil {
			return
		}
		if msg.Command() != wire.CmdVersion {
			return
		}

		// Send our version
		us := wire.NewNetAddress(&net.TCPAddr{IP: net.IPv4zero, Port: 0}, 0)
		them := wire.NewNetAddress(&net.TCPAddr{IP: net.IPv4zero, Port: 0}, wire.SFNodeNetwork)
		ver := wire.NewMsgVersion(us, them, 12345, 0)
		ver.ProtocolVersion = int32(protocolVersion)
		wire.WriteMessage(conn, ver, protocolVersion, wire.MainNet)

		// Send verack
		wire.WriteMessage(conn, wire.NewMsgVerAck(), protocolVersion, wire.MainNet)

		// Read client's verack
		for {
			msg, _, err = wire.ReadMessage(conn, protocolVersion, wire.MainNet)
			if err != nil {
				return
			}
			if msg.Command() == wire.CmdVerAck {
				break
			}
		}

		// Stay alive briefly so the client can do things
		time.Sleep(500 * time.Millisecond)
	}()

	return ln.Addr().String()
}

func TestConnectAndHandshake(t *testing.T) {
	addr := mockBSVNode(t)

	peer, err := Connect(addr, wire.MainNet, slog.Default())
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer peer.Close()

	if peer.addr != addr {
		t.Fatalf("expected addr=%s, got %s", addr, peer.addr)
	}
	if peer.conn == nil {
		t.Fatal("expected non-nil conn")
	}

	t.Logf("handshake succeeded with mock node at %s", addr)
}

func TestConnectRefused(t *testing.T) {
	// Connect to a port that's definitely not listening
	_, err := Connect("127.0.0.1:1", wire.MainNet, slog.Default())
	if err == nil {
		t.Fatal("expected error connecting to closed port")
	}
}

func TestConnectBadHandshake(t *testing.T) {
	// Server that accepts TCP but sends garbage
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.Write([]byte("not a bitcoin message"))
		time.Sleep(100 * time.Millisecond)
	}()

	_, err := Connect(ln.Addr().String(), wire.MainNet, slog.Default())
	if err == nil {
		t.Fatal("expected error for bad handshake")
	}
}

func TestRequestHeadersAndRead(t *testing.T) {
	// Server that completes handshake then responds to getheaders with empty headers
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))

		// Complete handshake
		wire.ReadMessage(conn, protocolVersion, wire.MainNet)
		us := wire.NewNetAddress(&net.TCPAddr{IP: net.IPv4zero, Port: 0}, 0)
		them := wire.NewNetAddress(&net.TCPAddr{IP: net.IPv4zero, Port: 0}, 0)
		ver := wire.NewMsgVersion(us, them, 99, 0)
		ver.ProtocolVersion = int32(protocolVersion)
		wire.WriteMessage(conn, ver, protocolVersion, wire.MainNet)
		wire.WriteMessage(conn, wire.NewMsgVerAck(), protocolVersion, wire.MainNet)

		// Wait for verack
		for {
			msg, _, err := wire.ReadMessage(conn, protocolVersion, wire.MainNet)
			if err != nil {
				return
			}
			if msg.Command() == wire.CmdVerAck {
				break
			}
		}

		// Read getheaders
		msg, _, err := wire.ReadMessage(conn, protocolVersion, wire.MainNet)
		if err != nil || msg.Command() != wire.CmdGetHeaders {
			return
		}

		// Send empty headers response
		wire.WriteMessage(conn, wire.NewMsgHeaders(), protocolVersion, wire.MainNet)
	}()

	peer, err := Connect(ln.Addr().String(), wire.MainNet, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	// Request headers with no locators
	err = peer.RequestHeaders(nil, nil)
	if err != nil {
		t.Fatalf("RequestHeaders: %v", err)
	}

	headers, err := peer.ReadHeaders()
	if err != nil {
		t.Fatalf("ReadHeaders: %v", err)
	}
	if len(headers) != 0 {
		t.Fatalf("expected 0 headers, got %d", len(headers))
	}

	t.Log("getheaders/headers round-trip succeeded")
}
