package client

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/ncode/MarcoZero/pkg/twamp/common"
	"github.com/ncode/MarcoZero/pkg/twamp/messages"
)

// mockServer implements a minimal TWAMP server for testing
type mockServer struct {
	listener      net.Listener
	mode          common.Mode
	stopChan      chan struct{}
	greetingSent  bool
	setupReceived bool
}

func newMockServer(t *testing.T, mode common.Mode) *mockServer {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start mock server: %v", err)
	}

	server := &mockServer{
		listener: l,
		mode:     mode,
		stopChan: make(chan struct{}),
	}

	go server.serve(t)
	return server
}

func (s *mockServer) serve(t *testing.T) {
	defer s.listener.Close()

	for {
		select {
		case <-s.stopChan:
			return
		default:
			s.listener.(*net.TCPListener).SetDeadline(time.Now().Add(100 * time.Millisecond))
			conn, err := s.listener.Accept()
			if err != nil {
				if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
					continue
				}
				t.Logf("Error accepting connection: %v", err)
				continue
			}

			go s.handleConnection(t, conn)
		}
	}
}

func (s *mockServer) handleConnection(t *testing.T, conn net.Conn) {
	defer conn.Close()

	// Send ServerGreeting
	greeting := messages.ServerGreeting{
		Modes:     uint32(s.mode),
		Challenge: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Salt:      [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
		Count:     1024,
	}

	data, err := greeting.Marshal()
	if err != nil {
		t.Logf("Failed to marshal greeting: %v", err)
		return
	}

	_, err = conn.Write(data)
	if err != nil {
		t.Logf("Failed to send greeting: %v", err)
		return
	}
	s.greetingSent = true

	// Read setup response
	buf := make([]byte, 164)
	_, err = conn.Read(buf)
	if err != nil {
		t.Logf("Failed to read setup response: %v", err)
		return
	}
	s.setupReceived = true

	// Send ServerStart
	serverStart := messages.ServerStart{
		Accept:    common.AcceptOK,
		ServerIV:  [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		StartTime: common.Now(),
	}

	data, err = serverStart.Marshal()
	if err != nil {
		t.Logf("Failed to marshal server start: %v", err)
		return
	}

	_, err = conn.Write(data)
	if err != nil {
		t.Logf("Failed to send server start: %v", err)
		return
	}

	// Simple keep-alive loop
	for {
		conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		_, err := conn.Read(buf)
		if err != nil {
			return
		}
	}
}

func (s *mockServer) addr() string {
	return s.listener.Addr().String()
}

func (s *mockServer) stop() {
	close(s.stopChan)
}

func TestConnect(t *testing.T) {
	// Start mock server
	server := newMockServer(t, common.ModeUnauthenticated)
	defer server.stop()

	// Create client with minimal config
	cfg := ClientConfig{
		ServerAddress: server.addr(),
		PreferredMode: common.ModeUnauthenticated,
		Timeout:       2 * time.Second,
	}

	client := NewClient(cfg)

	// Connect to mock server
	ctx := context.Background()
	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Verify server received our connection
	if !server.greetingSent || !server.setupReceived {
		t.Fatal("Server did not complete handshake")
	}

	// Verify client state
	if client.mode != common.ModeUnauthenticated {
		t.Errorf("Expected client mode to be %d, got %d", common.ModeUnauthenticated, client.mode)
	}
}

func TestConnectAuthenticated(t *testing.T) {
	// Skip full test since we'd need a more complex mock server
	// to properly handle authentication
	t.Skip("Skipping authenticated mode test that requires full crypto implementation")
}

func TestConnectTimeout(t *testing.T) {
	// Create client with non-routable address to force timeout
	cfg := ClientConfig{
		ServerAddress: "192.0.2.1:862", // TEST-NET-1 address that should not respond
		PreferredMode: common.ModeUnauthenticated,
		Timeout:       500 * time.Millisecond, // Short timeout for test
	}

	client := NewClient(cfg)

	// Try to connect
	ctx := context.Background()
	err := client.Connect(ctx)

	// Should fail with timeout
	if err == nil {
		t.Fatal("Expected connection to fail with timeout, but it succeeded")
	}
}

func TestConnectContextCancel(t *testing.T) {
	// Create client with non-routable address
	cfg := ClientConfig{
		ServerAddress: "192.0.2.1:862",
		PreferredMode: common.ModeUnauthenticated,
		Timeout:       5 * time.Second,
	}

	client := NewClient(cfg)

	// Create a context that will be canceled immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Try to connect with canceled context
	err := client.Connect(ctx)

	// Should fail with context canceled
	if err == nil {
		t.Fatal("Expected connection to fail due to canceled context, but it succeeded")
	}
}
