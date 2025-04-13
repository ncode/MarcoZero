package messages

import (
	"encoding/binary"
	"errors"

	"github.com/ncode/MarcoZero/pkg/twamp/common"
)

// Error definitions
var (
	ErrInvalidMessageLength = common.ErrInvalidMessageLength
	ErrInvalidMBZ           = errors.New("non-zero value in MBZ field")
)

// ServerGreeting represents the first message in TWAMP-Control
type ServerGreeting struct {
	Unused    [12]byte // Must be zeros
	Modes     uint32
	Challenge [16]byte
	Salt      [16]byte
	Count     uint32
	MBZ       [12]byte // Must be zeros
}

// Marshal converts ServerGreeting to network bytes
func (sg *ServerGreeting) Marshal() ([]byte, error) {
	buf := make([]byte, 84) // Total size is 84 bytes

	// First 12 bytes must be zeros (already zeros from make)

	// Modes (4 bytes)
	binary.BigEndian.PutUint32(buf[12:16], sg.Modes)

	// Challenge (16 bytes)
	copy(buf[16:32], sg.Challenge[:])

	// Salt (16 bytes)
	copy(buf[32:48], sg.Salt[:])

	// Count (4 bytes)
	binary.BigEndian.PutUint32(buf[48:52], sg.Count)

	// Last 12 bytes are MBZ (already zeros from make)

	return buf, nil
}

// Unmarshal parses network bytes into ServerGreeting
func (sg *ServerGreeting) Unmarshal(data []byte) error {
	if len(data) < 84 {
		return ErrInvalidMessageLength
	}

	// Check that MBZ fields are zeros
	for i := 0; i < 12; i++ {
		if data[i] != 0 {
			return ErrInvalidMBZ
		}
	}

	for i := 52; i < 64; i++ {
		if data[i] != 0 {
			return ErrInvalidMBZ
		}
	}

	// Extract Modes
	sg.Modes = binary.BigEndian.Uint32(data[12:16])

	// Extract Challenge
	copy(sg.Challenge[:], data[16:32])

	// Extract Salt
	copy(sg.Salt[:], data[32:48])

	// Extract Count
	sg.Count = binary.BigEndian.Uint32(data[48:52])

	return nil
}

// SetupResponse is the client's response to a ServerGreeting
type SetupResponse struct {
	Mode     uint32
	KeyID    [80]byte
	Token    [64]byte
	ClientIV [16]byte
}

// Marshal converts SetupResponse to network bytes
func (sr *SetupResponse) Marshal() ([]byte, error) {
	buf := make([]byte, 164) // Total size is 164 bytes

	// Mode (4 bytes)
	binary.BigEndian.PutUint32(buf[0:4], sr.Mode)

	// KeyID (80 bytes)
	copy(buf[4:84], sr.KeyID[:])

	// Token (64 bytes)
	copy(buf[84:148], sr.Token[:])

	// ClientIV (16 bytes)
	copy(buf[148:164], sr.ClientIV[:])

	return buf, nil
}

// Unmarshal parses network bytes into SetupResponse
func (sr *SetupResponse) Unmarshal(data []byte) error {
	if len(data) < 164 {
		return ErrInvalidMessageLength
	}

	// Extract Mode
	sr.Mode = binary.BigEndian.Uint32(data[0:4])

	// Extract KeyID
	copy(sr.KeyID[:], data[4:84])

	// Extract Token
	copy(sr.Token[:], data[84:148])

	// Extract ClientIV
	copy(sr.ClientIV[:], data[148:164])

	return nil
}

// ServerStart is the server's response to a SetupResponse
type ServerStart struct {
	MBZ       [15]byte // Must be zeros
	Accept    uint8
	ServerIV  [16]byte
	StartTime common.TWAMPTimestamp
	MBZ2      [8]byte // Must be zeros
}

// Marshal converts ServerStart to network bytes
func (ss *ServerStart) Marshal() ([]byte, error) {
	buf := make([]byte, 48) // Total size is 48 bytes

	// First 15 bytes are MBZ (already zeros from make)

	// Accept (1 byte)
	buf[15] = ss.Accept

	// ServerIV (16 bytes)
	copy(buf[16:32], ss.ServerIV[:])

	// StartTime (8 bytes)
	ss.StartTime.Marshal(buf[32:40])

	// Last 8 bytes are MBZ (already zeros from make)

	return buf, nil
}

// Unmarshal parses network bytes into ServerStart
func (ss *ServerStart) Unmarshal(data []byte) error {
	if len(data) < 48 {
		return ErrInvalidMessageLength
	}

	// Check that MBZ fields are zeros
	for i := 0; i < 15; i++ {
		if data[i] != 0 {
			return ErrInvalidMBZ
		}
	}

	for i := 40; i < 48; i++ {
		if data[i] != 0 {
			return ErrInvalidMBZ
		}
	}

	// Extract Accept
	ss.Accept = data[15]

	// Extract ServerIV
	copy(ss.ServerIV[:], data[16:32])

	// Extract StartTime
	ss.StartTime.Unmarshal(data[32:40])

	return nil
}

// RequestTWSession represents a request for a new TWAMP test session
type RequestTWSession struct {
	Command         uint8
	MBZ1            uint8
	IPVN            uint8
	ConfSender      uint8
	ConfReceiver    uint8
	MBZ2            [3]byte // Must be zeros
	NumSlots        uint32
	NumPackets      uint32
	SenderPort      uint16
	ReceiverPort    uint16
	SenderAddress   [16]byte
	ReceiverAddress [16]byte
	SID             common.SessionID
	PaddingLength   uint32
	StartTime       common.TWAMPTimestamp
	Timeout         common.TWAMPTimestamp
	TypePDescriptor uint32
	MBZ3            [8]byte  // Must be zeros
	HMAC            [16]byte // Optional, based on mode
}

// Marshal converts RequestTWSession to network bytes
func (rts *RequestTWSession) Marshal(includeHMAC bool) ([]byte, error) {
	size := 112
	if includeHMAC {
		size = 128
	}

	buf := make([]byte, size)

	// Command (1 byte)
	buf[0] = rts.Command

	// MBZ, IPVN (1 byte total)
	buf[1] = (rts.MBZ1 & 0xF0) | (rts.IPVN & 0x0F)

	// ConfSender (1 byte)
	buf[2] = rts.ConfSender

	// ConfReceiver (1 byte)
	buf[3] = rts.ConfReceiver

	// MBZ (3 bytes, already zeros from make)

	// NumSlots (4 bytes)
	binary.BigEndian.PutUint32(buf[7:11], rts.NumSlots)

	// NumPackets (4 bytes)
	binary.BigEndian.PutUint32(buf[11:15], rts.NumPackets)

	// SenderPort (2 bytes)
	binary.BigEndian.PutUint16(buf[15:17], rts.SenderPort)

	// ReceiverPort (2 bytes)
	binary.BigEndian.PutUint16(buf[17:19], rts.ReceiverPort)

	// SenderAddress (16 bytes)
	copy(buf[19:35], rts.SenderAddress[:])

	// ReceiverAddress (16 bytes)
	copy(buf[35:51], rts.ReceiverAddress[:])

	// SID (16 bytes)
	copy(buf[51:67], rts.SID[:])

	// PaddingLength (4 bytes)
	binary.BigEndian.PutUint32(buf[67:71], rts.PaddingLength)

	// StartTime (8 bytes)
	rts.StartTime.Marshal(buf[71:79])

	// Timeout (8 bytes)
	rts.Timeout.Marshal(buf[79:87])

	// TypePDescriptor (4 bytes)
	binary.BigEndian.PutUint32(buf[87:91], rts.TypePDescriptor)

	// MBZ (8 bytes, already zeros from make)

	// HMAC (16 bytes), if included
	if includeHMAC {
		copy(buf[112:128], rts.HMAC[:])
	}

	return buf, nil
}

// Unmarshal parses network bytes into RequestTWSession
func (rts *RequestTWSession) Unmarshal(data []byte, includeHMAC bool) error {
	minSize := 112
	if includeHMAC {
		minSize = 128
	}

	if len(data) < minSize {
		return ErrInvalidMessageLength
	}

	// Extract Command
	rts.Command = data[0]

	// Extract MBZ, IPVN
	rts.MBZ1 = data[1] & 0xF0
	rts.IPVN = data[1] & 0x0F

	// Extract ConfSender
	rts.ConfSender = data[2]

	// Extract ConfReceiver
	rts.ConfReceiver = data[3]

	// Skip MBZ bytes (4-6), but validate they're zero
	for i := 4; i < 7; i++ {
		if data[i] != 0 {
			return ErrInvalidMBZ
		}
	}

	// Extract NumSlots
	rts.NumSlots = binary.BigEndian.Uint32(data[7:11])

	// Extract NumPackets
	rts.NumPackets = binary.BigEndian.Uint32(data[11:15])

	// Extract SenderPort
	rts.SenderPort = binary.BigEndian.Uint16(data[15:17])

	// Extract ReceiverPort
	rts.ReceiverPort = binary.BigEndian.Uint16(data[17:19])

	// Extract SenderAddress
	copy(rts.SenderAddress[:], data[19:35])

	// Extract ReceiverAddress
	copy(rts.ReceiverAddress[:], data[35:51])

	// Extract SID
	copy(rts.SID[:], data[51:67])

	// Extract PaddingLength
	rts.PaddingLength = binary.BigEndian.Uint32(data[67:71])

	// Extract StartTime
	rts.StartTime.Unmarshal(data[71:79])

	// Extract Timeout
	rts.Timeout.Unmarshal(data[79:87])

	// Extract TypePDescriptor
	rts.TypePDescriptor = binary.BigEndian.Uint32(data[87:91])

	// Skip MBZ bytes (91-98), but validate they're zero
	for i := 91; i < 99; i++ {
		if data[i] != 0 {
			return ErrInvalidMBZ
		}
	}

	// Extract HMAC if included
	if includeHMAC {
		copy(rts.HMAC[:], data[112:128])
	}

	return nil
}

// AcceptSession is the server's response to a RequestTWSession
type AcceptSession struct {
	Accept uint8
	MBZ    uint8
	Port   uint16
	SID    common.SessionID
	MBZ2   [12]byte // Must be zeros
	HMAC   [16]byte // Optional, based on mode
}

// Marshal converts AcceptSession to network bytes
func (as *AcceptSession) Marshal(includeHMAC bool) ([]byte, error) {
	size := 32
	if includeHMAC {
		size = 48
	}

	buf := make([]byte, size)

	// Accept (1 byte)
	buf[0] = as.Accept

	// MBZ (1 byte, already zeros from make)

	// Port (2 bytes)
	binary.BigEndian.PutUint16(buf[2:4], as.Port)

	// SID (16 bytes)
	copy(buf[4:20], as.SID[:])

	// MBZ (12 bytes, already zeros from make)

	// HMAC (16 bytes), if included
	if includeHMAC {
		copy(buf[32:48], as.HMAC[:])
	}

	return buf, nil
}

// Unmarshal parses network bytes into AcceptSession
func (as *AcceptSession) Unmarshal(data []byte, includeHMAC bool) error {
	minSize := 32
	if includeHMAC {
		minSize = 48
	}

	if len(data) < minSize {
		return ErrInvalidMessageLength
	}

	// Extract Accept
	as.Accept = data[0]

	// Extract MBZ (and validate)
	as.MBZ = data[1]
	if as.MBZ != 0 {
		return ErrInvalidMBZ
	}

	// Extract Port
	as.Port = binary.BigEndian.Uint16(data[2:4])

	// Extract SID
	copy(as.SID[:], data[4:20])

	// Skip MBZ bytes (20-31), but validate they're zero
	for i := 20; i < 32; i++ {
		if data[i] != 0 {
			return ErrInvalidMBZ
		}
	}

	// Extract HMAC if included
	if includeHMAC {
		copy(as.HMAC[:], data[32:48])
	}

	return nil
}

// StartSessions command to start all previously requested sessions
type StartSessions struct {
	Command uint8
	MBZ     [15]byte // Must be zeros
	HMAC    [16]byte // Optional, based on mode
}

// Marshal converts StartSessions to network bytes
func (ss *StartSessions) Marshal(includeHMAC bool) ([]byte, error) {
	size := 16
	if includeHMAC {
		size = 32
	}

	buf := make([]byte, size)

	// Command (1 byte)
	buf[0] = ss.Command

	// MBZ (15 bytes, already zeros from make)

	// HMAC (16 bytes), if included
	if includeHMAC {
		copy(buf[16:32], ss.HMAC[:])
	}

	return buf, nil
}

// Unmarshal parses network bytes into StartSessions
func (ss *StartSessions) Unmarshal(data []byte, includeHMAC bool) error {
	minSize := 16
	if includeHMAC {
		minSize = 32
	}

	if len(data) < minSize {
		return ErrInvalidMessageLength
	}

	// Extract Command
	ss.Command = data[0]

	// Skip MBZ bytes (1-15), but validate they're zero
	for i := 1; i < 16; i++ {
		if data[i] != 0 {
			return ErrInvalidMBZ
		}
	}

	// Extract HMAC if included
	if includeHMAC {
		copy(ss.HMAC[:], data[16:32])
	}

	return nil
}

// StartAck is the server's response to a StartSessions command
type StartAck struct {
	Accept uint8
	MBZ    [15]byte // Must be zeros
	HMAC   [16]byte // Optional, based on mode
}

// Marshal converts StartAck to network bytes
func (sa *StartAck) Marshal(includeHMAC bool) ([]byte, error) {
	size := 16
	if includeHMAC {
		size = 32
	}

	buf := make([]byte, size)

	// Accept (1 byte)
	buf[0] = sa.Accept

	// MBZ (15 bytes, already zeros from make)

	// HMAC (16 bytes), if included
	if includeHMAC {
		copy(buf[16:32], sa.HMAC[:])
	}

	return buf, nil
}

// Unmarshal parses network bytes into StartAck
func (sa *StartAck) Unmarshal(data []byte, includeHMAC bool) error {
	minSize := 16
	if includeHMAC {
		minSize = 32
	}

	if len(data) < minSize {
		return ErrInvalidMessageLength
	}

	// Extract Accept
	sa.Accept = data[0]

	// Skip MBZ bytes (1-15), but validate they're zero
	for i := 1; i < 16; i++ {
		if data[i] != 0 {
			return ErrInvalidMBZ
		}
	}

	// Extract HMAC if included
	if includeHMAC {
		copy(sa.HMAC[:], data[16:32])
	}

	return nil
}

// StopSessions command to stop all running test sessions
type StopSessions struct {
	Command     uint8
	Accept      uint8
	MBZ         uint16
	NumSessions uint32
	MBZ2        [8]byte  // Must be zeros
	HMAC        [16]byte // Optional, based on mode
}

// Marshal converts StopSessions to network bytes
func (ss *StopSessions) Marshal(includeHMAC bool) ([]byte, error) {
	size := 16
	if includeHMAC {
		size = 32
	}

	buf := make([]byte, size)

	// Command (1 byte)
	buf[0] = ss.Command

	// Accept (1 byte)
	buf[1] = ss.Accept

	// MBZ (2 bytes)
	binary.BigEndian.PutUint16(buf[2:4], ss.MBZ)

	// NumSessions (4 bytes)
	binary.BigEndian.PutUint32(buf[4:8], ss.NumSessions)

	// MBZ (8 bytes, already zeros from make)

	// HMAC (16 bytes), if included
	if includeHMAC {
		copy(buf[16:32], ss.HMAC[:])
	}

	return buf, nil
}

// Unmarshal parses network bytes into StopSessions
func (ss *StopSessions) Unmarshal(data []byte, includeHMAC bool) error {
	minSize := 16
	if includeHMAC {
		minSize = 32
	}

	if len(data) < minSize {
		return ErrInvalidMessageLength
	}

	// Extract Command
	ss.Command = data[0]

	// Extract Accept
	ss.Accept = data[1]

	// Extract MBZ
	ss.MBZ = binary.BigEndian.Uint16(data[2:4])
	if ss.MBZ != 0 {
		return ErrInvalidMBZ
	}

	// Extract NumSessions
	ss.NumSessions = binary.BigEndian.Uint32(data[4:8])

	// Skip MBZ bytes (8-15), but validate they're zero
	for i := 8; i < 16; i++ {
		if data[i] != 0 {
			return ErrInvalidMBZ
		}
	}

	// Extract HMAC if included
	if includeHMAC {
		copy(ss.HMAC[:], data[16:32])
	}

	return nil
}
