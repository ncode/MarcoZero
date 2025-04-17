package messages

import (
	"bytes"
	"github.com/ncode/MarcoZero/pkg/twamp/common"
	"reflect"
	"testing"
)

func TestServerGreetingMarshaling(t *testing.T) {
	// Create a sample greeting
	greeting := ServerGreeting{
		Modes:     0x00000007, // All three modes supported
		Challenge: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Salt:      [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
		Count:     1024,
	}

	// Marshal
	data, err := greeting.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Unmarshal into a new struct
	var parsedGreeting ServerGreeting
	err = parsedGreeting.Unmarshal(data)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Verify fields match
	if greeting.Modes != parsedGreeting.Modes {
		t.Errorf("Modes mismatch: got %d, want %d", parsedGreeting.Modes, greeting.Modes)
	}

	if !bytes.Equal(greeting.Challenge[:], parsedGreeting.Challenge[:]) {
		t.Errorf("Challenge mismatch")
	}

	if !bytes.Equal(greeting.Salt[:], parsedGreeting.Salt[:]) {
		t.Errorf("Salt mismatch")
	}

	if greeting.Count != parsedGreeting.Count {
		t.Errorf("Count mismatch: got %d, want %d", parsedGreeting.Count, greeting.Count)
	}
}

func TestSetupResponseMarshaling(t *testing.T) {
	// Create a sample response
	response := SetupResponse{
		Mode:     0x00000001, // Unauthenticated mode
		KeyID:    [80]byte{}, // Empty in unauthenticated mode
		Token:    [64]byte{}, // Empty in unauthenticated mode
		ClientIV: [16]byte{}, // Empty in unauthenticated mode
	}

	// Marshal
	data, err := response.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Unmarshal into a new struct
	var parsedResponse SetupResponse
	err = parsedResponse.Unmarshal(data)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Verify fields match
	if response.Mode != parsedResponse.Mode {
		t.Errorf("Mode mismatch: got %d, want %d", parsedResponse.Mode, response.Mode)
	}
}

func TestServerStartRoundTrip(t *testing.T) {
	want := ServerStart{
		Accept:    common.AcceptOK,
		ServerIV:  [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		StartTime: common.TWAMPTimestamp{Seconds: 12, Fraction: 34},
	}
	data, err := want.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got ServerStart
	if err := got.Unmarshal(data); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("round‑trip mismatch:\nwant %+v\n got %+v", want, got)
	}
}

func TestServerStartMBZError(t *testing.T) {
	ss := ServerStart{}
	good, _ := ss.Marshal()
	bad := append([]byte(nil), good...)
	bad[0] = 1 // first MBZ byte
	if err := ss.Unmarshal(bad); err != ErrInvalidMBZ {
		t.Fatalf("expected ErrInvalidMBZ, got %v", err)
	}
}

func TestAcceptSessionRoundTrip(t *testing.T) {
	sid := common.SessionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	base := AcceptSession{Accept: common.AcceptOK, Port: 862, SID: sid}

	for _, includeHMAC := range []bool{false, true} {
		as := base
		if includeHMAC {
			as.HMAC = [16]byte{0xAA, 0xBB}
		}
		data, err := as.Marshal(includeHMAC)
		if err != nil {
			t.Fatalf("marshal(%v): %v", includeHMAC, err)
		}
		var parsed AcceptSession
		if err := parsed.Unmarshal(data, includeHMAC); err != nil {
			t.Fatalf("unmarshal(%v): %v", includeHMAC, err)
		}
		if as.Accept != parsed.Accept || as.Port != parsed.Port || !bytes.Equal(as.SID[:], parsed.SID[:]) {
			t.Fatalf("mismatch includeHMAC=%v", includeHMAC)
		}
		if includeHMAC && !bytes.Equal(as.HMAC[:], parsed.HMAC[:]) {
			t.Fatalf("HMAC mismatch includeHMAC=%v", includeHMAC)
		}
	}
}

func TestAcceptSessionMBZError(t *testing.T) {
	as := AcceptSession{}
	data, _ := as.Marshal(false)
	data[1] = 0xFF // MBZ byte must be zero
	if err := as.Unmarshal(data, false); err != ErrInvalidMBZ {
		t.Fatalf("expected ErrInvalidMBZ, got %v", err)
	}
}

func TestStartSessionsAndAckRoundTrip(t *testing.T) {
	ss := StartSessions{Command: common.CmdStartSessions}
	data, err := ss.Marshal(false)
	if err != nil {
		t.Fatalf("marshal StartSessions: %v", err)
	}
	var parsedSS StartSessions
	if err := parsedSS.Unmarshal(data, false); err != nil {
		t.Fatalf("unmarshal StartSessions: %v", err)
	}
	if ss.Command != parsedSS.Command {
		t.Fatalf("command mismatch")
	}

	ack := StartAck{Accept: common.AcceptOK}
	dataAck, err := ack.Marshal(true)
	if err != nil {
		t.Fatalf("marshal StartAck: %v", err)
	}
	var parsedAck StartAck
	if err := parsedAck.Unmarshal(dataAck, true); err != nil {
		t.Fatalf("unmarshal StartAck: %v", err)
	}
	if ack.Accept != parsedAck.Accept || !bytes.Equal(ack.HMAC[:], parsedAck.HMAC[:]) {
		t.Fatalf("StartAck mismatch")
	}
}

func TestStopSessionsRoundTrip(t *testing.T) {
	ss := StopSessions{Command: common.CmdStopSessions, Accept: common.AcceptOK, NumSessions: 3}
	data, err := ss.Marshal(false)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var parsed StopSessions
	if err := parsed.Unmarshal(data, false); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ss.Command != parsed.Command || ss.Accept != parsed.Accept || ss.NumSessions != parsed.NumSessions {
		t.Fatalf("StopSessions mismatch")
	}
}

func TestStopSessionsMBZError(t *testing.T) {
	ss := StopSessions{}
	data, _ := ss.Marshal(false)
	data[2] = 1 // first MBZ byte (part of uint16)
	if err := ss.Unmarshal(data, false); err != ErrInvalidMBZ {
		t.Fatalf("expected ErrInvalidMBZ, got %v", err)
	}
}

func TestRequestTWSessionRoundTrip(t *testing.T) {
	sid := common.SessionID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	rts := RequestTWSession{
		Command:         common.CmdRequestTWSession,
		IPVN:            4,
		ConfSender:      1,
		ConfReceiver:    1,
		NumSlots:        1,
		NumPackets:      10,
		SenderPort:      2000,
		ReceiverPort:    3000,
		SenderAddress:   [16]byte{192, 0, 2, 1},
		ReceiverAddress: [16]byte{192, 0, 2, 2},
		SID:             sid,
		PaddingLength:   0,
		StartTime:       common.TWAMPTimestamp{Seconds: 111, Fraction: 222},
		Timeout:         common.TWAMPTimestamp{Seconds: 222, Fraction: 333},
		TypePDescriptor: 0,
	}
	for _, includeHMAC := range []bool{false, true} {
		if includeHMAC {
			rts.HMAC = [16]byte{0xAA}
		}
		data, err := rts.Marshal(includeHMAC)
		if err != nil {
			t.Fatalf("marshal(%v): %v", includeHMAC, err)
		}
		var parsed RequestTWSession
		if err := parsed.Unmarshal(data, includeHMAC); err != nil {
			t.Fatalf("unmarshal(%v): %v", includeHMAC, err)
		}
		if rts.Command != parsed.Command || rts.NumSlots != parsed.NumSlots || rts.NumPackets != parsed.NumPackets {
			t.Fatalf("RequestTWSession basic fields mismatch includeHMAC=%v", includeHMAC)
		}
		if includeHMAC && !bytes.Equal(rts.HMAC[:], parsed.HMAC[:]) {
			t.Fatalf("HMAC mismatch includeHMAC=%v", includeHMAC)
		}
	}
}

func TestRequestTWSessionMBZError(t *testing.T) {
	rts := RequestTWSession{}
	data, _ := rts.Marshal(false)
	data[4] = 1 // first MBZ byte after 4 bytes of header
	if err := rts.Unmarshal(data, false); err != ErrInvalidMBZ {
		t.Fatalf("expected ErrInvalidMBZ, got %v", err)
	}
}
