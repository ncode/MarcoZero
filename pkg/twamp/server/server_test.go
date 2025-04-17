package server

import (
	"github.com/ncode/MarcoZero/pkg/twamp/crypto"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ncode/MarcoZero/pkg/twamp/common"
	"github.com/ncode/MarcoZero/pkg/twamp/messages"
)

func TestAllocatePortWithinRange(t *testing.T) {
	pm := newPortManager(30000, 30010)

	port, err := pm.allocatePort()
	if err != nil {
		t.Fatalf("unexpected error allocating port: %v", err)
	}
	if port < 30000 || port > 30010 {
		t.Errorf("allocated port %d outside expected range", port)
	}
}

func TestAllocateAllPorts(t *testing.T) {
	pm := newPortManager(40000, 40002) // 3 ports total
	allocated := make(map[uint16]bool)

	for i := 0; i < 3; i++ {
		p, err := pm.allocatePort()
		if err != nil {
			t.Fatalf("failed on allocation %d: %v", i, err)
		}
		allocated[p] = true
	}

	if len(allocated) != 3 {
		t.Fatalf("expected 3 unique ports, got %d", len(allocated))
	}

	// Fourth allocation should fail
	if _, err := pm.allocatePort(); err == nil {
		t.Errorf("expected error when no ports left, got nil")
	}
}

func TestReleasePort(t *testing.T) {
	pm := newPortManager(50000, 50005)

	p, err := pm.allocatePort()
	if err != nil {
		t.Fatalf("unexpected error allocating: %v", err)
	}

	pm.releasePort(p)

	p2, err := pm.allocatePort()
	if err != nil {
		t.Fatalf("unexpected error after release: %v", err)
	}
	if p != p2 {
		t.Errorf("expected port %d to be reused after release, got %d", p, p2)
	}
}

func TestAllocatePortWhenNoneAvailable(t *testing.T) {
	pm := newPortManager(60000, 60000) // only a single port

	if _, err := pm.allocatePort(); err != nil {
		t.Fatalf("unexpected error on first allocation: %v", err)
	}
	if _, err := pm.allocatePort(); err == nil {
		t.Errorf("expected error when no ports free, got nil")
	}
}

func TestUnauthHandshakeSuccess(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	srv := &Server{
		config: ServerConfig{
			SupportedModes: common.ModeUnauthenticated,
			SERVWAIT:       time.Second,
		},
	}

	cc := &controlConnection{
		conn:         serverConn,
		sessions:     make(map[common.SessionID]*TestSession),
		lastActivity: time.Now(),
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.sendServerGreeting(cc); err != nil {
			errCh <- err
			return
		}
		if err := srv.handleClientSetup(cc); err != nil {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	// --- client side ---
	greetingBuf := make([]byte, 84)
	if _, err := io.ReadFull(clientConn, greetingBuf); err != nil {
		t.Fatalf("failed to read greeting: %v", err)
	}

	var greet messages.ServerGreeting
	if err := greet.Unmarshal(greetingBuf); err != nil {
		t.Fatalf("greeting unmarshal failed: %v", err)
	}
	if greet.Modes != uint32(common.ModeUnauthenticated) {
		t.Errorf("unexpected Modes field – want %d, got %d", common.ModeUnauthenticated, greet.Modes)
	}

	setup := &messages.SetupResponse{Mode: uint32(common.ModeUnauthenticated)}
	setupData, _ := setup.Marshal()
	if _, err := clientConn.Write(setupData); err != nil {
		t.Fatalf("write Setup‑Response: %v", err)
	}

	startBuf := make([]byte, 48)
	if _, err := io.ReadFull(clientConn, startBuf); err != nil {
		t.Fatalf("read Server‑Start: %v", err)
	}

	var ss messages.ServerStart
	if err := ss.Unmarshal(startBuf); err != nil {
		t.Fatalf("Server‑Start unmarshal: %v", err)
	}
	if ss.Accept != common.AcceptOK {
		t.Errorf("expected AcceptOK, got %d", ss.Accept)
	}

	if err := <-errCh; err != nil {
		t.Errorf("server goroutine error: %v", err)
	}
}

func TestHandshakeUnsupportedMode(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	srv := &Server{
		config: ServerConfig{
			SupportedModes: common.ModeUnauthenticated,
			SERVWAIT:       time.Second,
		},
	}

	cc := &controlConnection{
		conn:     serverConn,
		sessions: make(map[common.SessionID]*TestSession),
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.sendServerGreeting(cc); err != nil {
			errCh <- err
			return
		}
		errCh <- srv.handleClientSetup(cc)
	}()

	// Discard greeting
	greetingBuf := make([]byte, 84)
	if _, err := io.ReadFull(clientConn, greetingBuf); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	// Send a Setup‑Response with an unsupported mode (encrypted)
	setup := &messages.SetupResponse{Mode: uint32(common.ModeEncrypted)}
	setupData, _ := setup.Marshal()
	clientConn.Write(setupData)

	if err := <-errCh; err == nil {
		t.Fatalf("expected error for unsupported mode, got nil")
	}
}

func TestGenerateZeroPadding(t *testing.T) {
	got := messages.GenerateZeroPadding(16)
	if len(got) != 16 {
		t.Fatalf("expected length 16, got %d", len(got))
	}
	for i, b := range got {
		if b != 0 {
			t.Fatalf("byte %d expected 0, got %d", i, b)
		}
	}

	// length 0 must return empty slice (not nil)
	empty := messages.GenerateZeroPadding(0)
	if len(empty) != 0 {
		t.Fatalf("expected empty slice for len 0, got len %d", len(empty))
	}
}

func TestGenerateRandomPadding(t *testing.T) {
	pad, err := messages.GenerateRandomPadding(32)
	if err != nil {
		t.Fatalf("GenerateRandomPadding error: %v", err)
	}
	if len(pad) != 32 {
		t.Fatalf("expected len 32, got %d", len(pad))
	}

	// size 0: no error, empty slice
	zero, err := messages.GenerateRandomPadding(0)
	if err != nil {
		t.Fatalf("len 0 should not error, got %v", err)
	}
	if len(zero) != 0 {
		t.Fatalf("expected empty slice for len 0, got %d", len(zero))
	}
}

func TestReflectorLoopEchoesPacket(t *testing.T) {
	// Prepare UDP listener that the server session will use.
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve udp: %v", err)
	}
	srvConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer srvConn.Close()

	reflectorPort := uint16(srvConn.LocalAddr().(*net.UDPAddr).Port)

	// Build minimal TestSession.
	session := &TestSession{
		reflectorPort: reflectorPort,
		mode:          common.ModeUnauthenticated,
		conn:          srvConn,
		stopChan:      make(chan struct{}),
	}
	session.isActive.Store(true)
	session.startTime = time.Now()

	// Minimal server with short REFWAIT so reflectPackets exits quickly after test.
	srv := &Server{
		config: ServerConfig{REFWAIT: 500 * time.Millisecond},
	}

	// Launch reflector goroutine.
	go srv.reflectPackets(session)

	// Build a SenderTestPacket.
	senderPacket := &messages.SenderTestPacket{
		SeqNumber:     42,
		Timestamp:     common.Now(),
		ErrorEstimate: common.ErrorEstimate{Multiplier: 1, Scale: 0, S: true},
		PaddingSize:   4,
	}
	raw, err := senderPacket.Marshal(false)
	if err != nil {
		t.Fatalf("marshal sender packet: %v", err)
	}

	// Dial UDP client to send to reflector.
	clientConn, err := net.DialUDP("udp", nil, srvConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer clientConn.Close()

	if _, err := clientConn.Write(raw); err != nil {
		t.Fatalf("write sender packet: %v", err)
	}

	// Await reflected packet.
	clientConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 2048)
	n, _, err := clientConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("no reflected packet received: %v", err)
	}

	var reflectPkt messages.ReflectorTestPacket
	if err := reflectPkt.Unmarshal(buf[:n]); err != nil {
		t.Fatalf("unmarshal reflector packet: %v", err)
	}

	if reflectPkt.SenderSeqNumber != senderPacket.SeqNumber {
		t.Errorf("expected SenderSeqNumber %d, got %d", senderPacket.SeqNumber, reflectPkt.SenderSeqNumber)
	}
	if reflectPkt.SenderTTL != 255 {
		t.Errorf("expected SenderTTL 255, got %d", reflectPkt.SenderTTL)
	}

	// Clean up
	close(session.stopChan)
	session.isActive.Store(false)
}

func TestVerifyHMACTruncatedTag(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	msg := []byte("lorem ipsum dolor sit amet")
	fullTag, err := crypto.CalculateHMAC(key, msg)
	if err != nil {
		t.Fatalf("unexpected error calculating HMAC: %v", err)
	}

	truncated := fullTag[:8] // half‑length tag should be invalid
	if _, err := crypto.VerifyHMAC(key, msg, truncated); err == nil {
		t.Fatalf("expected error for truncated HMAC tag, got nil")
	}
}

func TestDeriveKeyNilSalt(t *testing.T) {
	// Supplying a nil salt should be rejected to avoid using a zero‑entropy salt.
	if _, _, err := crypto.DeriveKey("pw", nil, 1000); err == nil {
		t.Fatalf("expected error when salt is nil, got nil")
	}
}

func TestSessionStartStop(t *testing.T) {
	srv := &Server{portManager: newPortManager(62000, 62010), config: ServerConfig{REFWAIT: 200 * time.Millisecond}}
	sess := &TestSession{mode: common.ModeUnauthenticated, stopChan: make(chan struct{})}

	if err := srv.startSession(sess); err != nil {
		t.Fatalf("startSession: %v", err)
	}
	if !sess.isActive.Load() {
		t.Fatalf("session should be active")
	}

	time.Sleep(20 * time.Millisecond)
	srv.stopSession(sess)

	if sess.isActive.Load() {
		t.Fatalf("session should be inactive")
	}
}
