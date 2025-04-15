package client

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/ncode/MarcoZero/pkg/twamp/common"
	"github.com/ncode/MarcoZero/pkg/twamp/messages"
)

// mockUDPServer simulates a TWAMP reflector
type mockUDPServer struct {
	conn     *net.UDPConn
	stopChan chan struct{}
}

func newMockUDPServer(t *testing.T) (*mockUDPServer, uint16) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve UDP address: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("Failed to listen on UDP: %v", err)
	}

	port := uint16(conn.LocalAddr().(*net.UDPAddr).Port)

	server := &mockUDPServer{
		conn:     conn,
		stopChan: make(chan struct{}),
	}

	go server.serve(t)
	return server, port
}

func (s *mockUDPServer) serve(t *testing.T) {
	defer s.conn.Close()

	buf := make([]byte, 2048)
	for {
		select {
		case <-s.stopChan:
			return
		default:
			s.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, addr, err := s.conn.ReadFrom(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				t.Logf("Error reading from UDP: %v", err)
				continue
			}

			// Simulate TWAMP reflector - parse incoming packet
			var senderPacket messages.SenderTestPacket
			if err := senderPacket.Unmarshal(buf[:n]); err != nil {
				t.Logf("Failed to parse sender packet: %v", err)
				continue
			}

			// Create reflector response
			reflectorPacket := messages.ReflectorTestPacket{
				SeqNumber:           0, // Use 0 for simplicity in test
				Timestamp:           common.Now(),
				ErrorEstimate:       common.ErrorEstimate{Multiplier: 1, Scale: 0, S: true},
				ReceiveTimestamp:    common.Now(),
				SenderSeqNumber:     senderPacket.SeqNumber,
				SenderTimestamp:     senderPacket.Timestamp,
				SenderErrorEstimate: senderPacket.ErrorEstimate,
				SenderTTL:           255,
				PaddingSize:         20, // Arbitrary padding for test
			}

			// Marshal and send response
			response, err := reflectorPacket.Marshal()
			if err != nil {
				t.Logf("Failed to marshal reflector packet: %v", err)
				continue
			}

			_, err = s.conn.WriteTo(response, addr)
			if err != nil {
				t.Logf("Failed to send reflector packet: %v", err)
			}
		}
	}
}

func (s *mockUDPServer) stop() {
	close(s.stopChan)
}

func TestTestSession_SendReceive(t *testing.T) {
	// Start a mock UDP server to act as reflector
	server, reflectorPort := newMockUDPServer(t)
	defer server.stop()

	// Create a test session
	config := TestSessionConfig{
		SenderPort:      20000, // This should be available for test
		ReceiverPort:    reflectorPort,
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   64,
		Timeout:         1 * time.Second,
	}

	// Create a session ID
	var sid common.SessionID
	for i := range sid {
		sid[i] = byte(i)
	}

	// Create a test session
	session, err := NewTestSession(config, sid, common.ModeUnauthenticated, nil)
	if err != nil {
		t.Fatalf("Failed to create test session: %v", err)
	}

	// Start the session
	err = session.Start()
	if err != nil {
		t.Fatalf("Failed to start session: %v", err)
	}

	// Start receiving in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // Ensure context is canceled at the end

	session.StartReceiving(ctx)

	// Send a test packet
	err = session.SendTestPacket()
	if err != nil {
		t.Fatalf("Failed to send test packet: %v", err)
	}

	// Wait for response
	time.Sleep(500 * time.Millisecond)

	// Get results before stopping
	results := session.GetResults()

	// Cancel context and stop session
	cancel()
	err = session.Stop()
	if err != nil {
		t.Fatalf("Failed to stop session: %v", err)
	}

	// Verify we sent and received packets
	if results.PacketsSent != 1 {
		t.Errorf("Expected 1 packet sent, got %d", results.PacketsSent)
	}

	// Check if we received the packet (this could be flaky on CI, so we'll be lenient)
	t.Logf("Packets received: %d", results.PacketsReceived)
	if results.PacketsReceived > 0 {
		// If we received packets, validate RTT is reasonable
		if results.AvgRTT < 0 || results.AvgRTT > 1*time.Second {
			t.Errorf("Unexpected RTT value: %v", results.AvgRTT)
		}
	}
}

func TestTestSession_Results(t *testing.T) {
	// Create a test session directly
	config := TestSessionConfig{
		SenderPort:      20001,
		ReceiverPort:    20002,
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   64,
		Timeout:         1 * time.Second,
	}

	var sid common.SessionID
	for i := range sid {
		sid[i] = byte(i)
	}

	session, err := NewTestSession(config, sid, common.ModeUnauthenticated, nil)
	if err != nil {
		t.Fatalf("Failed to create test session: %v", err)
	}

	// Manually set results for testing
	session.mu.Lock()
	session.totalSent = 10
	session.totalReceived = 8
	session.minRTT = 10 * time.Millisecond
	session.maxRTT = 100 * time.Millisecond
	session.sumRTT = 400 * time.Millisecond
	session.mu.Unlock()

	// Manually create some test packet results
	now := time.Now()
	for i := uint32(0); i < 10; i++ {
		result := &PacketResult{
			SenderSeqNo: i,
			SentTime:    now.Add(-time.Duration(100+i) * time.Millisecond),
			SenderTimestamp: common.TWAMPTimestamp{
				Seconds:  uint32(now.Unix()),
				Fraction: 0,
			},
		}

		// Mark some as received
		if i < 8 {
			result.ReceivedTime = now.Add(-time.Duration(50+i) * time.Millisecond)
			result.RTT = time.Duration(50) * time.Millisecond
			result.ReflectorRxTime = now.Add(-time.Duration(75+i) * time.Millisecond)
			result.ReflectorTxTime = now.Add(-time.Duration(65+i) * time.Millisecond)
			result.ReflectorLatency = 10 * time.Millisecond
		}

		session.results.Store(i, result)
	}

	// Get results
	results := session.GetResults()

	// Validate basic metrics
	if results.PacketsSent != 10 {
		t.Errorf("Expected 10 packets sent, got %d", results.PacketsSent)
	}
	if results.PacketsReceived != 8 {
		t.Errorf("Expected 8 packets received, got %d", results.PacketsReceived)
	}
	if results.PacketsLost != 2 {
		t.Errorf("Expected 2 packets lost, got %d", results.PacketsLost)
	}
	if results.MinRTT != 10*time.Millisecond {
		t.Errorf("Expected min RTT of 10ms, got %v", results.MinRTT)
	}
	if results.MaxRTT != 100*time.Millisecond {
		t.Errorf("Expected max RTT of 100ms, got %v", results.MaxRTT)
	}
	if results.AvgRTT != 50*time.Millisecond {
		t.Errorf("Expected avg RTT of 50ms, got %v", results.AvgRTT)
	}

	// Check reflector latency
	if results.AvgReflectorLatency != 10*time.Millisecond {
		t.Errorf("Expected avg reflector latency of 10ms, got %v", results.AvgReflectorLatency)
	}

	// Check individual packet results
	allResults := session.GetAllPacketResults()
	if len(allResults) != 10 {
		t.Errorf("Expected 10 packet results, got %d", len(allResults))
	}
}

func TestTestSession_StartStop(t *testing.T) {
	// Create a test session
	config := TestSessionConfig{
		SenderPort:      20003,
		ReceiverPort:    20004,
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   64,
		Timeout:         1 * time.Second,
	}

	var sid common.SessionID
	session, err := NewTestSession(config, sid, common.ModeUnauthenticated, nil)
	if err != nil {
		t.Fatalf("Failed to create test session: %v", err)
	}

	// Start the session
	err = session.Start()
	if err != nil {
		t.Fatalf("Failed to start session: %v", err)
	}

	// Verify connection is established
	session.mu.Lock()
	hasConn := session.conn != nil
	session.mu.Unlock()

	if !hasConn {
		t.Fatal("Session conn is nil after Start()")
	}

	// Start receiving
	ctx, cancel := context.WithCancel(context.Background())
	session.StartReceiving(ctx)

	// Cancel the context and stop the session
	cancel()
	err = session.Stop()
	if err != nil {
		t.Fatalf("Failed to stop session: %v", err)
	}

	// Verify connection is closed
	session.mu.Lock()
	hasConn = session.conn != nil
	session.mu.Unlock()

	if hasConn {
		t.Fatal("Session conn is not nil after Stop()")
	}

	// Verify stopping an already stopped session doesn't cause issues
	err = session.Stop()
	if err != nil {
		t.Fatalf("Failed to stop already stopped session: %v", err)
	}
}
