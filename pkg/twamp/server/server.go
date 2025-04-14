// pkg/twamp/server/server.go
package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ncode/MarcoZero/pkg/twamp/common"
	"github.com/ncode/MarcoZero/pkg/twamp/crypto"
	"github.com/ncode/MarcoZero/pkg/twamp/messages"
)

// ServerConfig contains configuration for TWAMP Server
type ServerConfig struct {
	ListenAddress  string
	SupportedModes common.Mode       // Bit mask of supported modes
	SecretMap      map[string]string // KeyID to shared secret mapping
	SERVWAIT       time.Duration     // Default 900s
	REFWAIT        time.Duration     // Default 900s
	PortRange      [2]uint16         // Range of ports for reflection [min, max]
}

// Server implements a TWAMP Server and Session-Reflector
type Server struct {
	config        ServerConfig
	listener      net.Listener
	sessions      map[common.SessionID]*TestSession
	sessionsMu    sync.RWMutex
	connections   map[net.Conn]*controlConnection
	connectionsMu sync.RWMutex
	portManager   *portManager
	stopChan      chan struct{}
	wg            sync.WaitGroup
}

// TestSession represents a server-side TWAMP test session
type TestSession struct {
	sid              common.SessionID
	reflectorPort    uint16
	conn             *net.UDPConn
	senderAddr       net.Addr
	senderPort       uint16
	mode             common.Mode
	sessionKeys      *crypto.TWAMPKeys
	timeout          time.Duration
	dscp             uint8
	reflectedPackets uint32
	startTime        time.Time
	isActive         bool
	stopChan         chan struct{}
}

// controlConnection represents a TWAMP control connection
type controlConnection struct {
	conn          net.Conn
	mode          common.Mode
	keyDerivation *crypto.TWAMPKeys
	sessions      map[common.SessionID]*TestSession
	lastActivity  time.Time
	greeting      *messages.ServerGreeting
}

// portManager manages UDP port allocation for test sessions
type portManager struct {
	minPort   uint16
	maxPort   uint16
	usedPorts map[uint16]bool
	mu        sync.Mutex
}

// newPortManager creates a new port manager
func newPortManager(minPort, maxPort uint16) *portManager {
	if minPort == 0 {
		minPort = 20000 // Default starting port
	}
	if maxPort == 0 {
		maxPort = 30000 // Default max port
	}

	return &portManager{
		minPort:   minPort,
		maxPort:   maxPort,
		usedPorts: make(map[uint16]bool),
	}
}

// allocatePort allocates a port for session reflection
func (pm *portManager) allocatePort() (uint16, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Try to find an available port in the range
	for port := pm.minPort; port <= pm.maxPort; port++ {
		if !pm.usedPorts[port] {
			// Check if the port is available by trying to listen on it
			addr := &net.UDPAddr{Port: int(port)}
			conn, err := net.ListenUDP("udp", addr)
			if err == nil {
				// Port is available
				conn.Close()
				pm.usedPorts[port] = true
				return port, nil
			}
		}
	}

	return 0, errors.New("no available ports in range")
}

// releasePort releases a port back to the pool
func (pm *portManager) releasePort(port uint16) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	delete(pm.usedPorts, port)
}

// NewServer creates a new TWAMP server
func NewServer(config ServerConfig) *Server {
	// Set default values if not provided
	if config.SERVWAIT == 0 {
		config.SERVWAIT = common.DefaultSERVWAIT
	}
	if config.REFWAIT == 0 {
		config.REFWAIT = common.DefaultREFWAIT
	}

	// Set default listen address if not provided
	if config.ListenAddress == "" {
		config.ListenAddress = ":862" // Default TWAMP control port
	}

	return &Server{
		config:      config,
		sessions:    make(map[common.SessionID]*TestSession),
		connections: make(map[net.Conn]*controlConnection),
		portManager: newPortManager(config.PortRange[0], config.PortRange[1]),
		stopChan:    make(chan struct{}),
	}
}

// Start starts the TWAMP server
func (s *Server) Start(ctx context.Context) error {
	// Start TCP listener for TWAMP-Control
	listener, err := net.Listen("tcp", s.config.ListenAddress)
	if err != nil {
		return fmt.Errorf("failed to start listener: %w", err)
	}
	s.listener = listener

	// Accept connections in a goroutine
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.acceptConnections(ctx)
	}()

	return nil
}

// acceptConnections accepts and handles TWAMP-Control connections
func (s *Server) acceptConnections(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopChan:
			return
		default:
			// Set accept timeout to allow for context cancellation checks
			s.listener.(*net.TCPListener).SetDeadline(time.Now().Add(1 * time.Second))

			conn, err := s.listener.Accept()
			if err != nil {
				if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
					// This is just a timeout, continue
					continue
				}
				// Log other errors but don't stop
				continue
			}

			// Handle each connection in a separate goroutine
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.handleConnection(ctx, conn)
			}()
		}
	}
}

// handleConnection processes a single TWAMP-Control connection
func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
	// Create a new control connection
	cc := &controlConnection{
		conn:         conn,
		sessions:     make(map[common.SessionID]*TestSession),
		lastActivity: time.Now(),
	}

	// Add to connections map
	s.connectionsMu.Lock()
	s.connections[conn] = cc
	s.connectionsMu.Unlock()

	// Ensure connection is removed when done
	defer func() {
		s.connectionsMu.Lock()
		delete(s.connections, conn)
		s.connectionsMu.Unlock()
		conn.Close()

		// Clean up any sessions associated with this connection
		for _, session := range cc.sessions {
			s.stopSession(session)
		}
	}()

	// Send server greeting
	err := s.sendServerGreeting(cc)
	if err != nil {
		return
	}

	// Handle client setup
	err = s.handleClientSetup(cc)
	if err != nil {
		return
	}

	// Main command loop
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopChan:
			return
		default:
			// Try to read a command
			cmd, err := s.readCommand(cc)
			if err != nil {
				// Check if this is a timeout and we should check for SERVWAIT
				if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
					// Check if we've exceeded SERVWAIT
					if time.Since(cc.lastActivity) > s.config.SERVWAIT {
						return // Close connection due to inactivity
					}
					continue
				}
				return // Any other error, close the connection
			}

			// Update last activity
			cc.lastActivity = time.Now()

			// Process the command
			switch cmd[0] { // First byte is command identifier
			case common.CmdRequestTWSession:
				err = s.handleRequestTWSession(cc, cmd)
			case common.CmdStartSessions:
				err = s.handleStartSessions(cc, cmd)
			case common.CmdStopSessions:
				err = s.handleStopSessions(cc, cmd)
			default:
				err = fmt.Errorf("unknown command: %d", cmd[0])
			}

			if err != nil {
				return // Close connection on error
			}
		}
	}
}

// sendServerGreeting sends the initial Server Greeting
func (s *Server) sendServerGreeting(cc *controlConnection) error {
	// Create server greeting
	greeting := &messages.ServerGreeting{
		Modes: uint32(s.config.SupportedModes),
	}

	// Generate random challenge
	if _, err := io.ReadFull(rand.Reader, greeting.Challenge[:]); err != nil {
		return fmt.Errorf("failed to generate challenge: %w", err)
	}

	// Generate random salt
	if _, err := io.ReadFull(rand.Reader, greeting.Salt[:]); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Set Count to recommended value (RFC 4656 recommends at least 1024)
	greeting.Count = 1024

	// Marshal greeting
	data, err := greeting.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal greeting: %w", err)
	}

	// Store the greeting with the connection
	cc.greeting = greeting

	// Send greeting
	_, err = cc.conn.Write(data)
	if err != nil {
		return fmt.Errorf("failed to send greeting: %w", err)
	}

	return nil
}

// handleClientSetup handles the client's setup response
func (s *Server) handleClientSetup(cc *controlConnection) error {
	// Read client setup response
	buf := make([]byte, 164) // Size of setup response
	_, err := io.ReadFull(cc.conn, buf)
	if err != nil {
		return fmt.Errorf("failed to read setup response: %w", err)
	}

	// Parse setup response
	var setupResponse messages.SetupResponse
	err = setupResponse.Unmarshal(buf)
	if err != nil {
		return fmt.Errorf("failed to unmarshal setup response: %w", err)
	}

	// Check if requested mode is supported
	requestedMode := common.Mode(setupResponse.Mode)
	if requestedMode == 0 {
		// Client doesn't want to continue
		return errors.New("client requested to terminate connection")
	}

	if requestedMode&s.config.SupportedModes == 0 {
		// Mode not supported
		return fmt.Errorf("unsupported mode: %d", requestedMode)
	}

	// Store the negotiated mode
	cc.mode = requestedMode

	// Handle authentication for secure modes
	if requestedMode != common.ModeUnauthenticated {
		// Extract KeyID from setup response
		keyIDLength := 0
		for i, b := range setupResponse.KeyID {
			if b == 0 {
				keyIDLength = i
				break
			}
		}
		keyID := string(setupResponse.KeyID[:keyIDLength])

		// Look up shared secret
		sharedSecret, ok := s.config.SecretMap[keyID]
		if !ok {
			// Unknown KeyID
			return fmt.Errorf("unknown KeyID: %s", keyID)
		}

		// Verify that we have the greeting stored
		if cc.greeting == nil {
			return fmt.Errorf("server greeting not available for token verification")
		}

		// Derive session keys
		aesKey, hmacKey, err := crypto.DeriveKey(sharedSecret, cc.greeting.Salt[:], cc.greeting.Count)
		if err != nil {
			return fmt.Errorf("failed to derive keys: %w", err)
		}

		// Decrypt and verify token
		tokenContents, err := crypto.DecryptToken(setupResponse.Token[:], cc.greeting.Challenge[:])
		if err != nil {
			return fmt.Errorf("failed to decrypt token: %w", err)
		}

		// Verify challenge matches
		if !compareBytes(tokenContents.Challenge, cc.greeting.Challenge[:]) {
			return errors.New("challenge mismatch in token")
		}

		// Store key derivation for this connection
		cc.keyDerivation = &crypto.TWAMPKeys{
			AESKey:   aesKey,
			HMACKey:  hmacKey,
			ClientIV: setupResponse.ClientIV[:],
		}

		// Generate server IV
		serverIV, err := crypto.NewRandomIV()
		if err != nil {
			return fmt.Errorf("failed to generate server IV: %w", err)
		}
		cc.keyDerivation.ServerIV = serverIV
	}

	// Send Server-Start message
	serverStart := &messages.ServerStart{
		Accept: common.AcceptOK,
	}

	// Fill in ServerIV for secure modes
	if cc.mode != common.ModeUnauthenticated {
		copy(serverStart.ServerIV[:], cc.keyDerivation.ServerIV)
	} else {
		// Always generate ServerIV even in unauthenticated mode
		serverIV, err := crypto.NewRandomIV()
		if err != nil {
			return fmt.Errorf("failed to generate server IV: %w", err)
		}
		copy(serverStart.ServerIV[:], serverIV)
	}

	// Set start time
	serverStart.StartTime = common.FromTime(time.Now())

	// Marshal Server-Start
	data, err := serverStart.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal Server-Start: %w", err)
	}

	// Make sure TCP sends this in a single packet by enabling TCP_NODELAY
	if tcpConn, ok := cc.conn.(*net.TCPConn); ok {
		// Disable Nagle algorithm to prevent combining small packets
		tcpConn.SetNoDelay(true)
	}

	// Send Server-Start
	written, err := cc.conn.Write(data)
	if err != nil {
		return fmt.Errorf("failed to send Server-Start: %w", err)
	}

	if written != len(data) {
		return fmt.Errorf("failed to send complete Server-Start: wrote %d of %d bytes",
			written, len(data))
	}

	return nil
}

// compareBytes safely compares two byte slices
func compareBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	// Use a constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare(a, b) == 1
}

// readCommand reads a command from the control connection
func (s *Server) readCommand(cc *controlConnection) ([]byte, error) {
	// Set read deadline based on SERVWAIT
	cc.conn.SetReadDeadline(time.Now().Add(1 * time.Second))

	// Read command identifier (first byte)
	header := make([]byte, 1)
	_, err := io.ReadFull(cc.conn, header)
	if err != nil {
		return nil, err
	}

	// Determine command length based on command identifier
	var cmdLength int
	switch header[0] {
	case common.CmdRequestTWSession:
		if cc.mode != common.ModeUnauthenticated {
			cmdLength = 128 // With HMAC
		} else {
			cmdLength = 112 // Without HMAC
		}
	case common.CmdStartSessions:
		if cc.mode != common.ModeUnauthenticated {
			cmdLength = 32 // With HMAC
		} else {
			cmdLength = 16 // Without HMAC
		}
	case common.CmdStopSessions:
		if cc.mode != common.ModeUnauthenticated {
			cmdLength = 32 // With HMAC
		} else {
			cmdLength = 16 // Without HMAC
		}
	default:
		return nil, fmt.Errorf("unknown command: %d", header[0])
	}

	// Read the rest of the command
	cmd := make([]byte, cmdLength)
	copy(cmd, header) // Include the command identifier

	_, err = io.ReadFull(cc.conn, cmd[1:])
	if err != nil {
		return nil, err
	}

	// If in secure mode, verify HMAC
	if cc.mode != common.ModeUnauthenticated {
		// Get message part and HMAC
		messageEnd := cmdLength - 16
		message := cmd[:messageEnd]
		expectedHMAC := cmd[messageEnd:]

		// Calculate HMAC
		hmac, err := crypto.CalculateHMAC(cc.keyDerivation.HMACKey, message)
		if err != nil {
			return nil, fmt.Errorf("failed to calculate HMAC: %w", err)
		}

		// Verify HMAC
		if !compareBytes(hmac, expectedHMAC) {
			return nil, errors.New("HMAC verification failed")
		}
	}

	return cmd, nil
}

// handleRequestTWSession handles a Request-TW-Session command
func (s *Server) handleRequestTWSession(cc *controlConnection, cmdData []byte) error {
	// Parse Request-TW-Session
	var request messages.RequestTWSession
	err := request.Unmarshal(cmdData, cc.mode != common.ModeUnauthenticated)
	if err != nil {
		return fmt.Errorf("failed to unmarshal Request-TW-Session: %w", err)
	}

	// Validate request
	if request.ConfSender != 0 || request.ConfReceiver != 0 {
		// TWAMP requires both to be 0
		return s.sendAcceptSession(cc, common.AcceptNotSupported, 0, common.SessionID{})
	}

	// Allocate a port for reflection
	reflectorPort, err := s.portManager.allocatePort()
	if err != nil {
		return s.sendAcceptSession(cc, common.AcceptTempResLimited, 0, common.SessionID{})
	}

	// Generate a unique SID
	var sid common.SessionID
	if _, err := io.ReadFull(rand.Reader, sid[:]); err != nil {
		s.portManager.releasePort(reflectorPort)
		return fmt.Errorf("failed to generate SID: %w", err)
	}

	// Extract DSCP value from Type-P Descriptor
	dscp := uint8((request.TypePDescriptor >> 2) & 0x3F)

	// Create test session
	session := &TestSession{
		sid:           sid,
		reflectorPort: reflectorPort,
		senderPort:    request.SenderPort,
		mode:          cc.mode,
		timeout:       time.Duration(request.Timeout.Seconds) * time.Second,
		dscp:          dscp,
		stopChan:      make(chan struct{}),
	}

	// Derive session keys for secure modes
	if cc.mode != common.ModeUnauthenticated && cc.keyDerivation != nil {
		testAESKey, testHMACKey, err := crypto.DeriveTestSessionKeys(
			cc.keyDerivation.AESKey,
			cc.keyDerivation.HMACKey,
			sid,
		)
		if err != nil {
			s.portManager.releasePort(reflectorPort)
			return fmt.Errorf("failed to derive test session keys: %w", err)
		}

		session.sessionKeys = &crypto.TWAMPKeys{
			TestAESKey:  testAESKey,
			TestHMACKey: testHMACKey,
			ClientIV:    cc.keyDerivation.ClientIV,
			ServerIV:    cc.keyDerivation.ServerIV,
		}
	}

	// Store session
	s.sessionsMu.Lock()
	s.sessions[sid] = session
	s.sessionsMu.Unlock()

	// Add to control connection's sessions
	cc.sessions[sid] = session

	// Send Accept-Session response
	return s.sendAcceptSession(cc, common.AcceptOK, reflectorPort, sid)
}

// sendAcceptSession sends an Accept-Session response
func (s *Server) sendAcceptSession(cc *controlConnection, acceptCode uint8, port uint16, sid common.SessionID) error {
	// Create Accept-Session message
	acceptSession := &messages.AcceptSession{
		Accept: acceptCode,
		Port:   port,
		SID:    sid,
	}

	// Marshal the message
	var data []byte
	var err error

	// Handle HMAC for secure modes
	if cc.mode != common.ModeUnauthenticated {
		// Marshal without HMAC first
		data, err = acceptSession.Marshal(false)
		if err != nil {
			return fmt.Errorf("failed to marshal Accept-Session: %w", err)
		}

		// Calculate HMAC
		hmac, err := crypto.CalculateHMAC(cc.keyDerivation.HMACKey, data)
		if err != nil {
			return fmt.Errorf("failed to calculate HMAC: %w", err)
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
		return fmt.Errorf("failed to marshal Accept-Session: %w", err)
	}

	// Send the message
	_, err = cc.conn.Write(data)
	if err != nil {
		return fmt.Errorf("failed to send Accept-Session: %w", err)
	}

	return nil
}

// handleStartSessions handles a Start-Sessions command
func (s *Server) handleStartSessions(cc *controlConnection, cmdData []byte) error {
	// Parse Start-Sessions
	var startSessions messages.StartSessions
	err := startSessions.Unmarshal(cmdData, cc.mode != common.ModeUnauthenticated)
	if err != nil {
		return fmt.Errorf("failed to unmarshal Start-Sessions: %w", err)
	}

	// Start all sessions for this connection
	for _, session := range cc.sessions {
		err := s.startSession(session)
		if err != nil {
			// If we can't start one session, respond with failure
			return s.sendStartAck(cc, common.AcceptFailure)
		}
	}

	// Send Start-Ack
	return s.sendStartAck(cc, common.AcceptOK)
}

// sendStartAck sends a Start-Ack response
func (s *Server) sendStartAck(cc *controlConnection, acceptCode uint8) error {
	// Create Start-Ack message
	startAck := &messages.StartAck{
		Accept: acceptCode,
	}

	// Marshal the message
	var data []byte
	var err error

	// Handle HMAC for secure modes
	if cc.mode != common.ModeUnauthenticated {
		// Marshal without HMAC first
		data, err = startAck.Marshal(false)
		if err != nil {
			return fmt.Errorf("failed to marshal Start-Ack: %w", err)
		}

		// Calculate HMAC
		hmac, err := crypto.CalculateHMAC(cc.keyDerivation.HMACKey, data)
		if err != nil {
			return fmt.Errorf("failed to calculate HMAC: %w", err)
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
		return fmt.Errorf("failed to marshal Start-Ack: %w", err)
	}

	// Send the message
	_, err = cc.conn.Write(data)
	if err != nil {
		return fmt.Errorf("failed to send Start-Ack: %w", err)
	}

	return nil
}

// startSession starts a test session
func (s *Server) startSession(session *TestSession) error {
	// Only start if not already active
	if session.isActive {
		return nil
	}

	// Start UDP listener
	addr := &net.UDPAddr{Port: int(session.reflectorPort)}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", session.reflectorPort, err)
	}
	session.conn = conn

	// Set DSCP if specified
	if session.dscp > 0 {
		// In Go, this requires platform-specific code
		// For now, we'll just log it
		// TODO: Implement DSCP setting for different platforms
	}

	// Start receiving and reflecting packets
	session.isActive = true
	session.startTime = time.Now()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.reflectPackets(session)
	}()

	return nil
}

// reflectPackets receives and reflects test packets for a session
func (s *Server) reflectPackets(session *TestSession) {
	defer func() {
		if session.conn != nil {
			session.conn.Close()
		}
	}()

	buf := make([]byte, 2048) // Large enough for any test packet

	for {
		select {
		case <-session.stopChan:
			return
		default:
			// Set read deadline to allow for context cancellation
			session.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

			// Receive test packet
			n, addr, err := session.conn.ReadFrom(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// This is just a timeout, continue
					continue
				}
				// Check for REFWAIT timeout
				if time.Since(session.startTime) > s.config.REFWAIT {
					// Session has been idle too long, stop it
					s.stopSession(session)
					return
				}
				// Continue on other errors
				continue
			}

			// Store sender address if not already set
			if session.senderAddr == nil {
				session.senderAddr = addr
			}

			// Reset activity timer
			session.startTime = time.Now()

			// Process and reflect the packet
			err = s.processAndReflect(session, buf[:n], addr)
			if err != nil {
				// Log error but continue processing
				continue
			}

			// Increment reflected packet count
			session.reflectedPackets++
		}
	}
}

// processAndReflect processes a test packet and reflects it back
func (s *Server) processAndReflect(session *TestSession, packet []byte, addr net.Addr) error {
	// Get receive timestamp immediately
	rxTime := common.Now()

	// Extract sender TTL (would require raw socket access)
	// For now, we'll use the default value from the packet
	senderTTL := uint8(255)

	var senderSeqNo uint32
	var senderTimestamp common.TWAMPTimestamp
	var senderErrorEstimate common.ErrorEstimate

	// Parse packet based on mode
	if session.mode != common.ModeUnauthenticated {
		// Authenticated or encrypted mode

		// If in encrypted mode, decrypt first
		if session.mode == common.ModeEncrypted && session.sessionKeys != nil {
			decryptedPacket, err := crypto.DecryptTWAMPTestPacket(
				session.sessionKeys.TestAESKey,
				session.sessionKeys.ClientIV,
				packet,
				session.mode == common.ModeAuthenticated,
			)
			if err != nil {
				return fmt.Errorf("failed to decrypt test packet: %w", err)
			}
			packet = decryptedPacket
		}

		// Parse authenticated packet
		var senderPacket messages.SenderTestPacketAuth
		err := senderPacket.Unmarshal(packet)
		if err != nil {
			return fmt.Errorf("failed to unmarshal test packet: %w", err)
		}

		// Verify HMAC if in secure mode
		if session.sessionKeys != nil {
			hmacField := 16 // Size of HMAC field
			dataSize := 32  // Data covered by HMAC in authenticated mode
			if session.mode == common.ModeEncrypted {
				dataSize = 96 // Data covered by HMAC in encrypted mode
			}

			// Verify HMAC
			valid, err := crypto.VerifyHMAC(
				session.sessionKeys.TestHMACKey,
				packet[:dataSize],
				packet[dataSize:dataSize+hmacField],
			)
			if err != nil {
				return fmt.Errorf("failed to verify HMAC: %w", err)
			}
			if !valid {
				return errors.New("HMAC verification failed")
			}
		}

		// Extract fields
		senderSeqNo = senderPacket.SeqNumber
		senderTimestamp = senderPacket.Timestamp
		senderErrorEstimate = senderPacket.ErrorEstimate
	} else {
		// Unauthenticated mode
		var senderPacket messages.SenderTestPacket
		err := senderPacket.Unmarshal(packet)
		if err != nil {
			return fmt.Errorf("failed to unmarshal test packet: %w", err)
		}

		// Extract fields
		senderSeqNo = senderPacket.SeqNumber
		senderTimestamp = senderPacket.Timestamp
		senderErrorEstimate = senderPacket.ErrorEstimate

		// Get sender TTL if available
		if senderPacket.PaddingSize > 0 {
			senderTTL = senderPacket.TTL
		}
	}

	// Create reflection packet
	var reflectPacket []byte
	var err error

	// Get transmit timestamp right before sending
	txTime := common.Now()

	// Create appropriate packet type based on mode
	reflectorSeqNo := session.reflectedPackets
	if session.mode != common.ModeUnauthenticated {
		// Authenticated or encrypted mode
		reflectorPacket := &messages.ReflectorTestPacketAuth{
			SeqNumber:           reflectorSeqNo,
			Timestamp:           txTime,
			ErrorEstimate:       common.ErrorEstimate{Multiplier: 1, Scale: 0, S: true},
			ReceiveTimestamp:    rxTime,
			SenderSeqNumber:     senderSeqNo,
			SenderTimestamp:     senderTimestamp,
			SenderErrorEstimate: senderErrorEstimate,
			SenderTTL:           senderTTL,
		}

		// Marshal the packet
		rawPacket, err := reflectorPacket.Marshal()
		if err != nil {
			return fmt.Errorf("failed to marshal reflector packet: %w", err)
		}

		// If in authenticated or encrypted mode, calculate HMAC and encrypt
		if session.sessionKeys != nil {
			// Calculate HMAC
			hmac, err := crypto.CalculateHMAC(session.sessionKeys.TestHMACKey, rawPacket[:96])
			if err != nil {
				return fmt.Errorf("failed to calculate HMAC: %w", err)
			}

			// Copy HMAC into packet
			copy(rawPacket[96:112], hmac)

			// If in encrypted mode, encrypt the packet
			if session.mode == common.ModeEncrypted {
				rawPacket, err = crypto.EncryptTWAMPTestPacket(
					session.sessionKeys.TestAESKey,
					session.sessionKeys.ServerIV,
					rawPacket,
					false, // Not authenticated only
				)
				if err != nil {
					return fmt.Errorf("failed to encrypt reflector packet: %w", err)
				}
			}
		}

		reflectPacket = rawPacket
	} else {
		// Unauthenticated mode
		reflectorPacket := &messages.ReflectorTestPacket{
			SeqNumber:           reflectorSeqNo,
			Timestamp:           txTime,
			ErrorEstimate:       common.ErrorEstimate{Multiplier: 1, Scale: 0, S: true},
			ReceiveTimestamp:    rxTime,
			SenderSeqNumber:     senderSeqNo,
			SenderTimestamp:     senderTimestamp,
			SenderErrorEstimate: senderErrorEstimate,
			SenderTTL:           senderTTL,
			PaddingSize:         len(packet) - 41, // Try to match original packet size
		}

		// Marshal the packet
		reflectPacket, err = reflectorPacket.Marshal()
		if err != nil {
			return fmt.Errorf("failed to marshal reflector packet: %w", err)
		}
	}

	// Set TTL to 255
	// Note: In Go, this requires platform-specific code
	// For a complete implementation, use raw sockets or platform-specific APIs

	// Send the reflection
	_, err = session.conn.WriteTo(reflectPacket, addr)
	if err != nil {
		return fmt.Errorf("failed to send reflector packet: %w", err)
	}

	return nil
}

// handleStopSessions handles a Stop-Sessions command
func (s *Server) handleStopSessions(cc *controlConnection, cmdData []byte) error {
	// Parse Stop-Sessions
	var stopSessions messages.StopSessions
	err := stopSessions.Unmarshal(cmdData, cc.mode != common.ModeUnauthenticated)
	if err != nil {
		return fmt.Errorf("failed to unmarshal Stop-Sessions: %w", err)
	}

	// Validate number of sessions
	if stopSessions.NumSessions != uint32(len(cc.sessions)) {
		return fmt.Errorf("incorrect session count: got %d, expected %d",
			stopSessions.NumSessions, len(cc.sessions))
	}

	// Stop all sessions for this connection
	// In TWAMP, the Stop-Sessions applies to all sessions
	for _, session := range cc.sessions {
		// Don't stop immediately, but allow for Timeout period
		// to reflect any packets still in flight
		time.AfterFunc(session.timeout, func() {
			s.stopSession(session)
		})
	}

	// Return success (client may close connection after this)
	return nil
}

// stopSession stops a test session
func (s *Server) stopSession(session *TestSession) {
	// Only stop if active
	if !session.isActive {
		return
	}

	// Signal reflector goroutine to stop
	close(session.stopChan)

	// Close UDP connection
	if session.conn != nil {
		session.conn.Close()
		session.conn = nil
	}

	// Release port
	s.portManager.releasePort(session.reflectorPort)

	// Remove from sessions map
	s.sessionsMu.Lock()
	delete(s.sessions, session.sid)
	s.sessionsMu.Unlock()

	session.isActive = false
}

// Stop stops the TWAMP server
func (s *Server) Stop() error {
	// Signal acceptConnections to stop
	close(s.stopChan)

	// Close listener
	if s.listener != nil {
		s.listener.Close()
	}

	// Stop all sessions
	s.sessionsMu.Lock()
	for _, session := range s.sessions {
		s.stopSession(session)
	}
	s.sessionsMu.Unlock()

	// Close all connections
	s.connectionsMu.Lock()
	for conn := range s.connections {
		conn.Close()
	}
	s.connectionsMu.Unlock()

	// Wait for all goroutines to finish
	s.wg.Wait()

	return nil
}
