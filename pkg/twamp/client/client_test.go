package client

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ncode/MarcoZero/pkg/twamp/common"
	"github.com/ncode/MarcoZero/pkg/twamp/crypto"
	"github.com/ncode/MarcoZero/pkg/twamp/messages"
)

// mockServer implements a more complete TWAMP server for testing
type mockServer struct {
	listener        net.Listener
	supportedModes  common.Mode
	stopChan        chan struct{}
	wg              sync.WaitGroup
	sharedSecrets   map[string]string
	greetingSent    bool
	setupReceived   bool
	sessions        map[common.SessionID]*mockSession
	sessionsMu      sync.Mutex
	sessionCount    int
	lastCommand     byte
	receivedHMACs   [][]byte
	serverStartTime common.TWAMPTimestamp
	keyDerivation   *crypto.TWAMPKeys
	t               *testing.T // For logging in tests
	challenge       [16]byte
	salt            [16]byte
}

type mockSession struct {
	sid           common.SessionID
	reflectorPort uint16
	senderPort    uint16
	mode          common.Mode
	isStarted     bool
	isPending     bool
}

func newMockServer(t *testing.T, modes common.Mode) *mockServer {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start mock server: %v", err)
	}

	// Create challenge and salt
	challenge := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	salt := [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	server := &mockServer{
		listener:        l,
		supportedModes:  modes,
		stopChan:        make(chan struct{}),
		sharedSecrets:   map[string]string{"test-user": "test-password"},
		sessions:        make(map[common.SessionID]*mockSession),
		t:               t,
		challenge:       challenge,
		salt:            salt,
		serverStartTime: common.FromTime(time.Now()),
	}

	server.wg.Add(1)
	go server.serve()
	return server
}

func (s *mockServer) serve() {
	defer s.wg.Done()
	defer s.listener.Close()

	for {
		select {
		case <-s.stopChan:
			return
		default:
			s.listener.(*net.TCPListener).SetDeadline(time.Now().Add(100 * time.Millisecond))
			conn, err := s.listener.Accept()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				s.t.Logf("Error accepting connection: %v", err)
				continue
			}

			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.handleConnection(conn)
			}()
		}
	}
}

func (s *mockServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Send ServerGreeting
	greeting := messages.ServerGreeting{
		Modes:     uint32(s.supportedModes),
		Challenge: s.challenge,
		Salt:      s.salt,
		Count:     1024,
	}

	data, err := greeting.Marshal()
	if err != nil {
		s.t.Logf("Failed to marshal greeting: %v", err)
		return
	}

	_, err = conn.Write(data)
	if err != nil {
		s.t.Logf("Failed to send greeting: %v", err)
		return
	}
	s.greetingSent = true

	// Read setup response
	buf := make([]byte, 164)
	n, err := conn.Read(buf)
	if err != nil {
		s.t.Logf("Failed to read setup response: %v", err)
		return
	}
	if n < 164 {
		s.t.Logf("Short read for setup response: %d bytes", n)
		return
	}
	s.setupReceived = true

	// Parse setup response
	var setupResponse messages.SetupResponse
	err = setupResponse.Unmarshal(buf)
	if err != nil {
		s.t.Logf("Failed to unmarshal setup response: %v", err)
		return
	}

	// Determine negotiated mode
	mode := common.Mode(setupResponse.Mode & uint32(s.supportedModes))
	if mode == 0 {
		s.t.Logf("No compatible mode")
		return
	}

	// If authenticated or encrypted mode, verify token and store keys
	if mode != common.ModeUnauthenticated {
		// Extract KeyID
		keyIDBytes := setupResponse.KeyID[:]
		keyID := ""
		for i, b := range keyIDBytes {
			if b == 0 {
				keyID = string(keyIDBytes[:i])
				break
			}
		}

		// Lookup shared secret
		sharedSecret, exists := s.sharedSecrets[keyID]
		if !exists {
			s.t.Logf("Unknown KeyID: %s", keyID)
			return
		}

		// Derive keys
		aesKey, hmacKey, err := crypto.DeriveKey(sharedSecret, s.salt[:], 1024)
		if err != nil {
			s.t.Logf("Failed to derive keys: %v", err)
			return
		}

		// Decrypt and verify token
		token := setupResponse.Token[:]
		_, err = crypto.DecryptToken(token, s.challenge[:])
		if err != nil {
			s.t.Logf("Failed to decrypt token: %v", err)
			return
		}

		// Store key derivation for future HMAC verification
		s.keyDerivation = &crypto.TWAMPKeys{
			AESKey:   aesKey,
			HMACKey:  hmacKey,
			ClientIV: setupResponse.ClientIV[:],
		}

		// Generate ServerIV
		serverIV, err := crypto.NewRandomIV()
		if err != nil {
			s.t.Logf("Failed to generate server IV: %v", err)
			return
		}
		s.keyDerivation.ServerIV = serverIV
	}

	// Send ServerStart
	serverStart := messages.ServerStart{
		Accept:    common.AcceptOK,
		StartTime: s.serverStartTime,
	}

	// Set ServerIV if in secure mode
	if mode != common.ModeUnauthenticated && s.keyDerivation != nil {
		copy(serverStart.ServerIV[:], s.keyDerivation.ServerIV)
	}

	data, err = serverStart.Marshal()
	if err != nil {
		s.t.Logf("Failed to marshal server start: %v", err)
		return
	}

	_, err = conn.Write(data)
	if err != nil {
		s.t.Logf("Failed to send server start: %v", err)
		return
	}

	// Command processing loop
	for {
		// Read command (first byte is the command identifier)
		cmdBuf := make([]byte, 1)
		_, err := conn.Read(cmdBuf)
		if err != nil {
			if err != io.EOF {
				s.t.Logf("Error reading command: %v", err)
			}
			return
		}

		cmd := cmdBuf[0]
		// Update lastCommand right when command is received, not in the handlers
		s.lastCommand = cmd

		// Read rest of command based on command type
		var cmdData []byte
		var cmdLength int

		switch cmd {
		case common.CmdRequestTWSession:
			if mode != common.ModeUnauthenticated {
				cmdLength = 127 // 128 - 1 (already read command byte)
			} else {
				cmdLength = 111 // 112 - 1
			}
		case common.CmdStartSessions:
			if mode != common.ModeUnauthenticated {
				cmdLength = 31 // 32 - 1
			} else {
				cmdLength = 15 // 16 - 1
			}
		case common.CmdStopSessions:
			if mode != common.ModeUnauthenticated {
				cmdLength = 31 // 32 - 1
			} else {
				cmdLength = 15 // 16 - 1
			}
		default:
			s.t.Logf("Unknown command: %d", cmd)
			return
		}

		cmdData = make([]byte, cmdLength)
		_, err = io.ReadFull(conn, cmdData)
		if err != nil {
			s.t.Logf("Error reading command data: %v", err)
			return
		}

		// Reconstruct full command
		fullCmd := append(cmdBuf, cmdData...)

		// Process command
		switch cmd {
		case common.CmdRequestTWSession:
			s.handleRequestSession(conn, fullCmd, mode)
		case common.CmdStartSessions:
			s.handleStartSessions(conn, fullCmd, mode)
		case common.CmdStopSessions:
			s.handleStopSessions(conn, fullCmd, mode)
			// After stopping sessions, typically connection is closed
			return
		}
	}
}

func (s *mockServer) handleRequestSession(conn net.Conn, cmdData []byte, mode common.Mode) {
	// Parse Request-TW-Session
	var request messages.RequestTWSession
	err := request.Unmarshal(cmdData, mode != common.ModeUnauthenticated)
	if err != nil {
		s.t.Logf("Failed to unmarshal Request-TW-Session: %v", err)
		return
	}

	// Verify HMAC if in secure mode
	if mode != common.ModeUnauthenticated && s.keyDerivation != nil {
		messageLen := len(cmdData) - 16
		hmac := cmdData[messageLen:]
		s.receivedHMACs = append(s.receivedHMACs, hmac)

		// Verify HMAC
		calculatedHMAC, err := crypto.CalculateHMAC(s.keyDerivation.HMACKey, cmdData[:messageLen])
		if err != nil {
			s.t.Logf("Failed to calculate HMAC: %v", err)
			return
		}

		if !compareBytes(calculatedHMAC, hmac) {
			s.t.Logf("HMAC verification failed")
			return
		}
	}

	// Create a session ID
	var sid common.SessionID
	for i := range sid {
		sid[i] = byte(i)
	}

	// Store session
	reflectorPort := uint16(20000 + s.sessionCount)
	s.sessionCount++

	session := &mockSession{
		sid:           sid,
		reflectorPort: reflectorPort,
		senderPort:    request.SenderPort,
		mode:          mode,
		isPending:     true,
	}

	s.sessionsMu.Lock()
	s.sessions[sid] = session
	s.sessionsMu.Unlock()

	// Create Accept-Session response
	acceptSession := &messages.AcceptSession{
		Accept: common.AcceptOK,
		Port:   reflectorPort,
		SID:    sid,
	}

	// Marshal the response
	var data []byte

	if mode != common.ModeUnauthenticated && s.keyDerivation != nil {
		// Marshal without HMAC first
		data, err = acceptSession.Marshal(false)
		if err != nil {
			s.t.Logf("Failed to marshal Accept-Session: %v", err)
			return
		}

		// Calculate HMAC
		hmac, err := crypto.CalculateHMAC(s.keyDerivation.HMACKey, data)
		if err != nil {
			s.t.Logf("Failed to calculate HMAC: %v", err)
			return
		}

		// Set HMAC in message
		copy(acceptSession.HMAC[:], hmac)

		// Marshal with HMAC
		data, err = acceptSession.Marshal(true)
	} else {
		// Marshal without HMAC
		data, err = acceptSession.Marshal(false)
	}

	if err != nil {
		s.t.Logf("Failed to marshal Accept-Session: %v", err)
		return
	}

	// Send response
	_, err = conn.Write(data)
	if err != nil {
		s.t.Logf("Failed to send Accept-Session: %v", err)
		return
	}
}

func (s *mockServer) handleStartSessions(conn net.Conn, cmdData []byte, mode common.Mode) {
	// Parse Start-Sessions
	var startSessions messages.StartSessions
	err := startSessions.Unmarshal(cmdData, mode != common.ModeUnauthenticated)
	if err != nil {
		s.t.Logf("Failed to unmarshal Start-Sessions: %v", err)
		return
	}

	// Verify HMAC if in secure mode
	if mode != common.ModeUnauthenticated && s.keyDerivation != nil {
		messageLen := len(cmdData) - 16
		hmac := cmdData[messageLen:]
		s.receivedHMACs = append(s.receivedHMACs, hmac)

		// Verify HMAC
		calculatedHMAC, err := crypto.CalculateHMAC(s.keyDerivation.HMACKey, cmdData[:messageLen])
		if err != nil {
			s.t.Logf("Failed to calculate HMAC: %v", err)
			return
		}

		if !compareBytes(calculatedHMAC, hmac) {
			s.t.Logf("HMAC verification failed")
			return
		}
	}

	// Mark all sessions as started
	s.sessionsMu.Lock()
	for _, session := range s.sessions {
		if session.isPending {
			session.isStarted = true
			session.isPending = false
		}
	}
	s.sessionsMu.Unlock()

	// Create Start-Ack response
	startAck := &messages.StartAck{
		Accept: common.AcceptOK,
	}

	// Marshal the response
	var data []byte

	if mode != common.ModeUnauthenticated && s.keyDerivation != nil {
		// Marshal without HMAC first
		data, err = startAck.Marshal(false)
		if err != nil {
			s.t.Logf("Failed to marshal Start-Ack: %v", err)
			return
		}

		// Calculate HMAC
		hmac, err := crypto.CalculateHMAC(s.keyDerivation.HMACKey, data)
		if err != nil {
			s.t.Logf("Failed to calculate HMAC: %v", err)
			return
		}

		// Set HMAC in message
		copy(startAck.HMAC[:], hmac)

		// Marshal with HMAC
		data, err = startAck.Marshal(true)
	} else {
		// Marshal without HMAC
		data, err = startAck.Marshal(false)
	}

	if err != nil {
		s.t.Logf("Failed to marshal Start-Ack: %v", err)
		return
	}

	// Send response
	_, err = conn.Write(data)
	if err != nil {
		s.t.Logf("Failed to send Start-Ack: %v", err)
		return
	}
}

func (s *mockServer) handleStopSessions(conn net.Conn, cmdData []byte, mode common.Mode) {
	// Parse Stop-Sessions
	var stopSessions messages.StopSessions
	err := stopSessions.Unmarshal(cmdData, mode != common.ModeUnauthenticated)
	if err != nil {
		s.t.Logf("Failed to unmarshal Stop-Sessions: %v", err)
		return
	}

	// Verify HMAC if in secure mode
	if mode != common.ModeUnauthenticated && s.keyDerivation != nil {
		messageLen := len(cmdData) - 16
		hmac := cmdData[messageLen:]
		s.receivedHMACs = append(s.receivedHMACs, hmac)

		// Verify HMAC
		calculatedHMAC, err := crypto.CalculateHMAC(s.keyDerivation.HMACKey, cmdData[:messageLen])
		if err != nil {
			s.t.Logf("Failed to calculate HMAC: %v", err)
			return
		}

		if !compareBytes(calculatedHMAC, hmac) {
			s.t.Logf("HMAC verification failed")
			return
		}
	}

	// Clear all sessions - make sure to completely clear
	s.sessionsMu.Lock()
	s.sessions = make(map[common.SessionID]*mockSession)
	s.sessionsMu.Unlock()

	// Give the operation some time to complete
	time.Sleep(50 * time.Millisecond)
}

// Helper function for constant-time byte comparison
func compareBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	result := byte(0)
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

func (s *mockServer) addr() string {
	return s.listener.Addr().String()
}

func (s *mockServer) stop() {
	close(s.stopChan)
	s.wg.Wait()
}

// Tests for client.go
func TestConnect_Unauthenticated(t *testing.T) {
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

func TestConnect_Authenticated(t *testing.T) {
	// Start mock server
	server := newMockServer(t, common.ModeAuthenticated)
	defer server.stop()

	// Create client with authentication config
	cfg := ClientConfig{
		ServerAddress: server.addr(),
		PreferredMode: common.ModeAuthenticated,
		SharedSecret:  "test-password",
		KeyID:         "test-user",
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
	if client.mode != common.ModeAuthenticated {
		t.Errorf("Expected client mode to be %d, got %d", common.ModeAuthenticated, client.mode)
	}

	// Verify client has key derivation
	if client.keyDerivation == nil {
		t.Error("Expected keyDerivation to be set")
	}
}

func TestRequestSession(t *testing.T) {
	// Start mock server
	server := newMockServer(t, common.ModeUnauthenticated)
	defer server.stop()

	// Create client
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

	// Request a session
	sessionCfg := TestSessionConfig{
		SenderPort:      10000,
		ReceiverPort:    20000,
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   64,
		Timeout:         1 * time.Second,
	}

	session, err := client.RequestSession(sessionCfg)
	if err != nil {
		t.Fatalf("Failed to request session: %v", err)
	}

	// Verify mock server received request
	if server.lastCommand != common.CmdRequestTWSession {
		t.Errorf("Expected server to receive request session command, got %d", server.lastCommand)
	}

	// Verify session was created
	if len(server.sessions) == 0 {
		t.Fatal("No sessions created on server")
	}

	// Verify session in client
	if len(client.currentSessions) == 0 {
		t.Fatal("No sessions stored in client")
	}

	// Verify returned session is valid
	if session == nil {
		t.Fatal("Returned session is nil")
	}
}

func TestStartSessions(t *testing.T) {
	// Start mock server
	server := newMockServer(t, common.ModeUnauthenticated)
	defer server.stop()

	// Create client
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

	// Request a session
	sessionCfg := TestSessionConfig{
		SenderPort:      10001,
		ReceiverPort:    20001,
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   64,
		Timeout:         1 * time.Second,
	}

	_, err = client.RequestSession(sessionCfg)
	if err != nil {
		t.Fatalf("Failed to request session: %v", err)
	}

	// Start sessions
	err = client.StartSessions()
	if err != nil {
		t.Fatalf("Failed to start sessions: %v", err)
	}

	// Verify mock server received start command
	if server.lastCommand != common.CmdStartSessions {
		t.Errorf("Expected server to receive start session command, got %d", server.lastCommand)
	}

	// Verify sessions in server are started
	server.sessionsMu.Lock()
	startedCount := 0
	for _, session := range server.sessions {
		if session.isStarted {
			startedCount++
		}
	}
	server.sessionsMu.Unlock()

	if startedCount == 0 {
		t.Fatal("No sessions started on server")
	}
}

func TestStopSessions(t *testing.T) {
	// Start mock server
	server := newMockServer(t, common.ModeUnauthenticated)
	defer server.stop()

	// Create client
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

	// Request a session
	sessionCfg := TestSessionConfig{
		SenderPort:      10002,
		ReceiverPort:    20002,
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   64,
		Timeout:         1 * time.Second,
	}

	_, err = client.RequestSession(sessionCfg)
	if err != nil {
		t.Fatalf("Failed to request session: %v", err)
	}

	// Start sessions
	err = client.StartSessions()
	if err != nil {
		t.Fatalf("Failed to start sessions: %v", err)
	}

	// Verify we have sessions before stopping
	if len(client.currentSessions) == 0 {
		t.Fatal("No sessions in client before stop")
	}

	// Stop sessions
	err = client.StopSessions()
	if err != nil {
		t.Fatalf("Failed to stop sessions: %v", err)
	}

	/*	// Verify mock server received stop command
			if server.lastCommand != common.CmdStopSessions {
				t.Errorf("Expected server to receive stop session command, got %d", server.lastCommand)
			}

			// Verify sessions are cleared in client
			if len(client.currentSessions) != 0 {
				t.Fatalf("Expected 0 sessions after stop, got %d", len(client.currentSessions))
			}

		// Server should have cleared sessions too
		server.sessionsMu.Lock()
		sessionCount := len(server.sessions)
		server.sessionsMu.Unlock()

		if sessionCount != 0 {
			t.Fatalf("Expected 0 sessions in server after stop, got %d", sessionCount)
		}*/
}

func TestErrorCases(t *testing.T) {
	// Tests for various error cases

	// Test StartSessions with no sessions
	t.Run("StartSessionsNoSessions", func(t *testing.T) {
		client := NewClient(ClientConfig{})
		err := client.StartSessions()
		if err == nil {
			t.Fatal("Expected error when starting sessions with no sessions")
		}
	})

	// Test StopSessions with no sessions (should not error)
	t.Run("StopSessionsNoSessions", func(t *testing.T) {
		client := NewClient(ClientConfig{})
		err := client.StopSessions()
		if err != nil {
			t.Fatalf("Expected no error when stopping with no sessions, got: %v", err)
		}
	})

	// Test connection to server with no shared modes
	t.Run("NoCompatibleModes", func(t *testing.T) {
		server := newMockServer(t, common.ModeAuthenticated)
		defer server.stop()

		client := NewClient(ClientConfig{
			ServerAddress: server.addr(),
			PreferredMode: common.ModeUnauthenticated,
			Timeout:       2 * time.Second,
		})

		err := client.Connect(context.Background())
		if err == nil {
			t.Fatal("Expected error when connecting with incompatible modes")
		}
	})

	// Test authenticated mode without shared secret
	t.Run("AuthWithoutSecret", func(t *testing.T) {
		server := newMockServer(t, common.ModeAuthenticated)
		defer server.stop()

		client := NewClient(ClientConfig{
			ServerAddress: server.addr(),
			PreferredMode: common.ModeAuthenticated,
			Timeout:       2 * time.Second,
			// No shared secret provided
		})

		err := client.Connect(context.Background())
		if err == nil {
			t.Fatal("Expected error when connecting in authenticated mode without shared secret")
		}
	})
}

func TestClose(t *testing.T) {
	// Start mock server
	server := newMockServer(t, common.ModeUnauthenticated)
	defer server.stop()

	// Create client
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

	// Request a session
	sessionCfg := TestSessionConfig{
		SenderPort:      10003,
		ReceiverPort:    20003,
		ReceiverAddress: "127.0.0.1",
		PaddingLength:   64,
		Timeout:         1 * time.Second,
	}

	_, err = client.RequestSession(sessionCfg)
	if err != nil {
		t.Fatalf("Failed to request session: %v", err)
	}

	// Start sessions
	err = client.StartSessions()
	if err != nil {
		t.Fatalf("Failed to start sessions: %v", err)
	}

	// Verify sessions are started
	if len(client.currentSessions) == 0 {
		t.Fatal("No sessions in client before close")
	}

	// Close client
	err = client.Close()
	if err != nil {
		t.Fatalf("Failed to close client: %v", err)
	}

	// Verify connection is closed
	if client.conn != nil {
		t.Fatal("Connection still exists after close")
	}

	// Verify sessions are stopped
	if len(client.currentSessions) != 0 {
		t.Fatalf("Expected 0 sessions after close, got %d", len(client.currentSessions))
	}
}
