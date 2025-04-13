package client

import (
	"context"
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

// ClientConfig contains configuration for TWAMP Control-Client
type ClientConfig struct {
	ServerAddress string
	PreferredMode common.Mode
	SharedSecret  string // Optional, for authenticated/encrypted modes
	KeyID         string // Optional, identifier for shared secret
	Timeout       time.Duration
}

// Client implements a TWAMP Control-Client and Session-Sender
type Client struct {
	config          ClientConfig
	conn            net.Conn
	mode            common.Mode
	keyDerivation   *crypto.TWAMPKeys
	currentSessions map[common.SessionID]*TestSession
	mu              sync.Mutex
}

// NewClient creates a new TWAMP client
func NewClient(config ClientConfig) *Client {
	// Set default timeout if not provided
	if config.Timeout == 0 {
		config.Timeout = 5 * time.Second
	}

	return &Client{
		config:          config,
		currentSessions: make(map[common.SessionID]*TestSession),
	}
}

// Connect establishes a TWAMP-Control connection to the server
func (c *Client) Connect(ctx context.Context) error {
	// Create a dialer with timeout
	dialer := net.Dialer{Timeout: c.config.Timeout}

	// Default to port 862 if not specified
	serverAddr := c.config.ServerAddress
	if _, _, err := net.SplitHostPort(serverAddr); err != nil {
		serverAddr = net.JoinHostPort(serverAddr, "862")
	}

	// Connect to the server
	conn, err := dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	c.conn = conn

	// Handle ServerGreeting
	greeting, err := c.receiveServerGreeting()
	if err != nil {
		c.conn.Close()
		return fmt.Errorf("failed to receive server greeting: %w", err)
	}

	// Negotiate mode
	err = c.negotiateMode(greeting)
	if err != nil {
		c.conn.Close()
		return fmt.Errorf("failed to negotiate mode: %w", err)
	}

	return nil
}

// receiveServerGreeting reads and parses the Server Greeting message
func (c *Client) receiveServerGreeting() (*messages.ServerGreeting, error) {
	// Server Greeting is 84 bytes in RFC 4656
	buf := make([]byte, 84)

	// Read the greeting
	_, err := io.ReadFull(c.conn, buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read server greeting: %w", err)
	}

	// Parse the greeting
	var greeting messages.ServerGreeting
	err = greeting.Unmarshal(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal server greeting: %w", err)
	}

	// Check that server supports at least one mode
	if greeting.Modes == 0 {
		return nil, errors.New("server doesn't support any mode")
	}

	return &greeting, nil
}

// receiveServerStart reads and parses the Server-Start message
func (c *Client) receiveServerStart() (*messages.ServerStart, error) {
	// Server-Start message is 48 bytes in RFC 5357
	buf := make([]byte, 48)

	// Read the response
	_, err := io.ReadFull(c.conn, buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read Server-Start: %w", err)
	}

	// Parse the message
	var serverStart messages.ServerStart
	err = serverStart.Unmarshal(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal Server-Start: %w", err)
	}

	return &serverStart, nil
}

// negotiateMode selects a compatible mode and completes the handshake
func (c *Client) negotiateMode(greeting *messages.ServerGreeting) error {
	// Determine preferred mode
	var selectedMode common.Mode
	if c.config.PreferredMode&common.ModeEncrypted != 0 && greeting.Modes&common.ModeEncrypted != 0 {
		selectedMode = common.ModeEncrypted
	} else if c.config.PreferredMode&common.ModeAuthenticated != 0 && greeting.Modes&common.ModeAuthenticated != 0 {
		selectedMode = common.ModeAuthenticated
	} else if c.config.PreferredMode&common.ModeUnauthenticated != 0 && greeting.Modes&common.ModeUnauthenticated != 0 {
		selectedMode = common.ModeUnauthenticated
	} else {
		return errors.New("no compatible mode available")
	}

	// Create Setup-Response
	setupResponse := &messages.SetupResponse{
		Mode: uint32(selectedMode),
	}

	// For authenticated or encrypted modes, add security info
	if selectedMode != common.ModeUnauthenticated {
		if c.config.SharedSecret == "" {
			return errors.New("shared secret required for secure modes")
		}

		// Derive session keys
		aesKey, hmacKey, err := crypto.DeriveKey(c.config.SharedSecret, greeting.Salt[:], greeting.Count)
		if err != nil {
			return fmt.Errorf("failed to derive keys: %w", err)
		}

		// Store key derivation for use in subsequent communication
		c.keyDerivation = &crypto.TWAMPKeys{
			AESKey:  aesKey,
			HMACKey: hmacKey,
		}

		// Generate random IV for client
		clientIV, err := crypto.NewRandomIV()
		if err != nil {
			return fmt.Errorf("failed to generate client IV: %w", err)
		}
		c.keyDerivation.ClientIV = clientIV

		// Create token
		token, err := crypto.CreateToken(greeting.Challenge[:], aesKey, hmacKey)
		if err != nil {
			return fmt.Errorf("failed to create token: %w", err)
		}

		// Set token and KeyID in setup response
		copy(setupResponse.KeyID[:], []byte(c.config.KeyID))
		copy(setupResponse.Token[:], token)
		copy(setupResponse.ClientIV[:], clientIV)
	}

	// Marshal and send Setup-Response
	data, err := setupResponse.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal setup response: %w", err)
	}

	_, err = c.conn.Write(data)
	if err != nil {
		return fmt.Errorf("failed to send setup response: %w", err)
	}

	// Receive Server-Start
	serverStart, err := c.receiveServerStart()
	if err != nil {
		return fmt.Errorf("failed to receive server start: %w", err)
	}

	// Check if server accepted our setup
	if serverStart.Accept != common.AcceptOK {
		return common.NewTWAMPError(
			serverStart.Accept,
			fmt.Sprintf("Server rejected setup: %s",
				common.AcceptCodeToString(serverStart.Accept)))
	}

	// For authenticated or encrypted modes, store Server IV
	if selectedMode != common.ModeUnauthenticated {
		c.keyDerivation.ServerIV = serverStart.ServerIV[:]
	}

	// Store negotiated mode
	c.mode = selectedMode

	return nil
}

// calculateHMAC calculates HMAC for a message
func (c *Client) calculateHMAC(message []byte) ([]byte, error) {
	return crypto.CalculateHMAC(c.keyDerivation.HMACKey, message)
}

// verifyHMAC verifies HMAC for a message
func (c *Client) verifyHMAC(message, hmac []byte) (bool, error) {
	return crypto.VerifyHMAC(c.keyDerivation.HMACKey, message, hmac)
}

// receiveAndVerify receives a message and verifies its HMAC if in secure mode
func (c *Client) receiveAndVerify(expectedLen int, includeHMAC bool) ([]byte, error) {
	buf := make([]byte, expectedLen)
	_, err := io.ReadFull(c.conn, buf)
	if err != nil {
		return nil, err
	}

	// If in secure mode and message includes HMAC, verify it
	if c.mode != common.ModeUnauthenticated && includeHMAC {
		messageLen := expectedLen - 16 // Last 16 bytes are HMAC
		valid, err := c.verifyHMAC(buf[:messageLen], buf[messageLen:])
		if err != nil {
			return nil, err
		}
		if !valid {
			return nil, errors.New("HMAC verification failed")
		}
	}

	return buf, nil
}

// sendWithHMAC sends a message with HMAC if in secure mode
func (c *Client) sendWithHMAC(message []byte, addHMAC bool) error {
	if c.mode == common.ModeUnauthenticated || !addHMAC {
		_, err := c.conn.Write(message)
		return err
	}

	// Calculate HMAC
	hmac, err := c.calculateHMAC(message)
	if err != nil {
		return err
	}

	// Append HMAC to message
	messageWithHMAC := append(message, hmac...)

	// If encrypted mode, encrypt the message
	if c.mode == common.ModeEncrypted {
		encryptedMsg, err := crypto.EncryptTWAMPControlMessage(
			c.keyDerivation.AESKey,
			c.keyDerivation.ClientIV,
			messageWithHMAC,
		)
		if err != nil {
			return err
		}
		messageWithHMAC = encryptedMsg
	}

	_, err = c.conn.Write(messageWithHMAC)
	return err
}

// RequestSession requests a new TWAMP test session
func (c *Client) RequestSession(config TestSessionConfig) (*TestSession, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Set default timeout if not provided
	if config.Timeout == 0 {
		config.Timeout = 3 * time.Second
	}

	// Set default receiver address if not provided
	if config.ReceiverAddress == "" {
		// Use server address from control connection
		host, _, err := net.SplitHostPort(c.config.ServerAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to parse server address: %w", err)
		}
		config.ReceiverAddress = host
	}

	// Create request
	request := &messages.RequestTWSession{
		Command:         common.CmdRequestTWSession,
		IPVN:            4, // IPv4
		ConfSender:      0, // Must be 0 in TWAMP
		ConfReceiver:    0, // Must be 0 in TWAMP
		NumSlots:        0, // Must be 0 in TWAMP
		NumPackets:      0, // Must be 0 in TWAMP
		SenderPort:      config.SenderPort,
		ReceiverPort:    config.ReceiverPort,
		PaddingLength:   config.PaddingLength,
		TypePDescriptor: uint32(config.DSCP << 2), // DSCP goes in top 6 bits
	}

	// Set addresses based on IP version
	ip := net.ParseIP(config.ReceiverAddress)
	if ip == nil {
		return nil, fmt.Errorf("invalid receiver address: %s", config.ReceiverAddress)
	}

	if ip4 := ip.To4(); ip4 != nil {
		// IPv4
		request.IPVN = 4
		copy(request.ReceiverAddress[:4], ip4)
	} else {
		// IPv6
		request.IPVN = 6
		copy(request.ReceiverAddress[:], ip)
	}

	// Set timeout as TWAMP timestamp
	timeoutDuration := time.Duration(config.Timeout)
	timeoutSeconds := uint32(timeoutDuration / time.Second)
	timeoutFraction := uint32(float64(timeoutDuration%time.Second) * common.NanoToFrac)
	request.Timeout = common.TWAMPTimestamp{
		Seconds:  timeoutSeconds,
		Fraction: timeoutFraction,
	}

	// Set start time to 0 (immediate start)
	request.StartTime = common.TWAMPTimestamp{
		Seconds:  0,
		Fraction: 0,
	}

	// Marshal the request
	var data []byte
	var err error

	// Handle HMAC for secure modes
	if c.mode != common.ModeUnauthenticated {
		// Marshal without HMAC first
		data, err = request.Marshal(false)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request: %w", err)
		}

		// Calculate HMAC
		hmac, err := c.calculateHMAC(data)
		if err != nil {
			return nil, fmt.Errorf("failed to calculate HMAC: %w", err)
		}

		// Set HMAC in request
		copy(request.HMAC[:], hmac)

		// Marshal with HMAC
		data, err = request.Marshal(true)
	} else {
		// Marshal without HMAC
		data, err = request.Marshal(false)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Send the request
	_, err = c.conn.Write(data)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	// Read the response - minimum 32 bytes, possibly 48 with HMAC
	respSize := 32
	if c.mode != common.ModeUnauthenticated {
		respSize = 48
	}

	respData, err := c.receiveAndVerify(respSize, c.mode != common.ModeUnauthenticated)
	if err != nil {
		return nil, fmt.Errorf("failed to receive accept session response: %w", err)
	}

	// Parse the response
	var acceptSession messages.AcceptSession
	err = acceptSession.Unmarshal(respData, c.mode != common.ModeUnauthenticated)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal accept session: %w", err)
	}

	// Check the accept code
	if acceptSession.Accept != common.AcceptOK {
		return nil, common.NewTWAMPError(
			acceptSession.Accept,
			fmt.Sprintf("Server rejected session: %s",
				common.AcceptCodeToString(acceptSession.Accept)))
	}

	// Check if port was changed by server
	if acceptSession.Port != 0 && acceptSession.Port != config.ReceiverPort {
		// Server suggested an alternate port
		config.ReceiverPort = acceptSession.Port
	}

	// Create a new test session
	session, err := NewTestSession(config, acceptSession.SID, c.mode, c.keyDerivation)
	if err != nil {
		return nil, fmt.Errorf("failed to create test session: %w", err)
	}

	// Store the session
	c.currentSessions[acceptSession.SID] = session

	return session, nil
}

// StartSessions starts all requested test sessions
func (c *Client) StartSessions() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Ensure we have sessions to start
	if len(c.currentSessions) == 0 {
		return errors.New("no sessions to start")
	}

	// Create start command
	startCmd := &messages.StartSessions{
		Command: common.CmdStartSessions,
	}

	// Marshal the command
	var data []byte
	var err error

	// Handle HMAC for secure modes
	if c.mode != common.ModeUnauthenticated {
		// Marshal without HMAC first
		data, err = startCmd.Marshal(false)
		if err != nil {
			return fmt.Errorf("failed to marshal start command: %w", err)
		}

		// Calculate HMAC
		hmac, err := c.calculateHMAC(data)
		if err != nil {
			return fmt.Errorf("failed to calculate HMAC: %w", err)
		}

		// Set HMAC in command
		copy(startCmd.HMAC[:], hmac)

		// Marshal with HMAC
		data, err = startCmd.Marshal(true)
	} else {
		// Marshal without HMAC
		data, err = startCmd.Marshal(false)
	}

	if err != nil {
		return fmt.Errorf("failed to marshal start command: %w", err)
	}

	// Send the command
	_, err = c.conn.Write(data)
	if err != nil {
		return fmt.Errorf("failed to send start command: %w", err)
	}

	// Read the response - 16 bytes, possibly 32 with HMAC
	respSize := 16
	if c.mode != common.ModeUnauthenticated {
		respSize = 32
	}

	respData, err := c.receiveAndVerify(respSize, c.mode != common.ModeUnauthenticated)
	if err != nil {
		return fmt.Errorf("failed to receive start ack: %w", err)
	}

	// Parse the response
	var startAck messages.StartAck
	err = startAck.Unmarshal(respData, c.mode != common.ModeUnauthenticated)
	if err != nil {
		return fmt.Errorf("failed to unmarshal start ack: %w", err)
	}

	// Check the accept code
	if startAck.Accept != common.AcceptOK {
		return common.NewTWAMPError(
			startAck.Accept,
			fmt.Sprintf("Server rejected start command: %s",
				common.AcceptCodeToString(startAck.Accept)))
	}

	// Start all the test sessions
	for _, session := range c.currentSessions {
		err := session.Start()
		if err != nil {
			return fmt.Errorf("failed to start test session: %w", err)
		}
	}

	return nil
}

// StopSessions stops all active test sessions
func (c *Client) StopSessions() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Ensure we have sessions to stop
	if len(c.currentSessions) == 0 {
		return nil // No sessions to stop, return success
	}

	// Create stop command
	stopCmd := &messages.StopSessions{
		Command:     common.CmdStopSessions,
		Accept:      common.AcceptOK,
		NumSessions: uint32(len(c.currentSessions)),
	}

	// Marshal the command
	var data []byte
	var err error

	// Handle HMAC for secure modes
	if c.mode != common.ModeUnauthenticated {
		// Marshal without HMAC first
		data, err = stopCmd.Marshal(false)
		if err != nil {
			return fmt.Errorf("failed to marshal stop command: %w", err)
		}

		// Calculate HMAC
		hmac, err := c.calculateHMAC(data)
		if err != nil {
			return fmt.Errorf("failed to calculate HMAC: %w", err)
		}

		// Set HMAC in command
		copy(stopCmd.HMAC[:], hmac)

		// Marshal with HMAC
		data, err = stopCmd.Marshal(true)
	} else {
		// Marshal without HMAC
		data, err = stopCmd.Marshal(false)
	}

	if err != nil {
		return fmt.Errorf("failed to marshal stop command: %w", err)
	}

	// Send the command
	_, err = c.conn.Write(data)
	if err != nil {
		return fmt.Errorf("failed to send stop command: %w", err)
	}
	// Stop all the test sessions and track which ones we've processed
	stoppedSessions := make(map[common.SessionID]struct{})
	for sid, session := range c.currentSessions {
		err := session.Stop()
		if err != nil {
			// Log the error but continue stopping other sessions
			fmt.Printf("Error stopping session %x: %v\n", sid, err)
		}
		stoppedSessions[sid] = struct{}{}
	}

	// Update current sessions to remove stopped ones
	for sid := range stoppedSessions {
		delete(c.currentSessions, sid)
	}

	return nil
}

// Close closes the control connection and all test sessions
func (c *Client) Close() error {
	// Stop all sessions first
	c.StopSessions()

	// Close the control connection
	if c.conn != nil {
		return c.conn.Close()
	}

	return nil
}
