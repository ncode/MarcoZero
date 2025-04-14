package messages

import (
	"encoding/binary"

	"github.com/ncode/MarcoZero/pkg/twamp/common"
)

// SenderTestPacket represents the TWAMP-Test packet sent by Session-Sender
// in Unauthenticated mode
type SenderTestPacket struct {
	SeqNumber     uint32
	Timestamp     common.TWAMPTimestamp
	ErrorEstimate common.ErrorEstimate
	TTL           uint8 // Initialized to 255
	PaddingSize   int   // Not part of the packet, but size info for padding
}

// Marshal converts SenderTestPacket to network bytes with appropriate padding
// Update the Marshal method in SenderTestPacket
func (stp *SenderTestPacket) Marshal(useRandomPadding bool) ([]byte, error) {
	// Base size + padding
	size := 14 + stp.PaddingSize
	buf := make([]byte, size)

	// Sequence Number (4 bytes)
	binary.BigEndian.PutUint32(buf[0:4], stp.SeqNumber)

	// Timestamp (8 bytes)
	stp.Timestamp.Marshal(buf[4:12])

	// Error Estimate (2 bytes)
	binary.BigEndian.PutUint16(buf[12:14], stp.ErrorEstimate.ToUint16())

	// Set TTL to 255
	if stp.PaddingSize > 0 {
		buf[14] = 255 // TTL set to 255
	}

	// Fill remaining padding with random or zero bytes
	if stp.PaddingSize > 1 {
		var padding []byte
		var err error

		if useRandomPadding {
			padding, err = GenerateRandomPadding(stp.PaddingSize - 1)
			if err != nil {
				return nil, err
			}
		} else {
			padding = GenerateZeroPadding(stp.PaddingSize - 1)
		}

		copy(buf[15:], padding)
	}

	return buf, nil
}

// Unmarshal parses network bytes into SenderTestPacket
func (stp *SenderTestPacket) Unmarshal(data []byte) error {
	if len(data) < 14 {
		return ErrInvalidMessageLength
	}

	// Extract Sequence Number
	stp.SeqNumber = binary.BigEndian.Uint32(data[0:4])

	// Extract Timestamp
	stp.Timestamp.Unmarshal(data[4:12])

	// Extract Error Estimate
	var ee uint16
	ee = binary.BigEndian.Uint16(data[12:14])
	stp.ErrorEstimate.FromUint16(ee)

	// Record actual padding size
	stp.PaddingSize = len(data) - 14

	// Extract TTL if padding exists
	if stp.PaddingSize > 0 {
		stp.TTL = data[14]
	}

	return nil
}

// SenderTestPacketAuth represents the authenticated/encrypted version
// of the SenderTestPacket
type SenderTestPacketAuth struct {
	SeqNumber     uint32
	MBZ           [12]byte // Must be zeros
	Timestamp     common.TWAMPTimestamp
	ErrorEstimate common.ErrorEstimate
	MBZ2          [6]byte // Must be zeros
	HMAC          [16]byte
	PaddingSize   int // Not part of the packet, but size info for padding
}

// Marshal converts SenderTestPacketAuth to network bytes
func (stpa *SenderTestPacketAuth) Marshal() ([]byte, error) {
	// Base size (48) + padding
	size := 48 + stpa.PaddingSize
	buf := make([]byte, size)

	// Sequence Number (4 bytes)
	binary.BigEndian.PutUint32(buf[0:4], stpa.SeqNumber)

	// MBZ (12 bytes, already zeros from make)

	// Timestamp (8 bytes)
	stpa.Timestamp.Marshal(buf[16:24])

	// Error Estimate (2 bytes)
	binary.BigEndian.PutUint16(buf[24:26], stpa.ErrorEstimate.ToUint16())

	// MBZ (6 bytes, already zeros from make)

	// HMAC (16 bytes)
	copy(buf[32:48], stpa.HMAC[:])

	// Fill padding with random bytes
	// In real implementation, should use crypto/rand for this
	for i := 48; i < size; i++ {
		buf[i] = byte(i % 256) // Deterministic pattern for now
	}

	return buf, nil
}

// Unmarshal parses network bytes into SenderTestPacketAuth
func (stpa *SenderTestPacketAuth) Unmarshal(data []byte) error {
	if len(data) < 48 {
		return ErrInvalidMessageLength
	}

	// Extract Sequence Number
	stpa.SeqNumber = binary.BigEndian.Uint32(data[0:4])

	// Validate MBZ
	for i := 4; i < 16; i++ {
		if data[i] != 0 {
			return ErrInvalidMBZ
		}
	}

	// Extract Timestamp
	stpa.Timestamp.Unmarshal(data[16:24])

	// Extract Error Estimate
	var ee uint16
	ee = binary.BigEndian.Uint16(data[24:26])
	stpa.ErrorEstimate.FromUint16(ee)

	// Validate MBZ
	for i := 26; i < 32; i++ {
		if data[i] != 0 {
			return ErrInvalidMBZ
		}
	}

	// Extract HMAC
	copy(stpa.HMAC[:], data[32:48])

	// Record actual padding size
	stpa.PaddingSize = len(data) - 48

	return nil
}

// ReflectorTestPacket represents the TWAMP-Test packet sent by Session-Reflector
// in Unauthenticated mode
type ReflectorTestPacket struct {
	SeqNumber           uint32
	Timestamp           common.TWAMPTimestamp
	ErrorEstimate       common.ErrorEstimate
	MBZ                 [2]byte // Must be zeros
	ReceiveTimestamp    common.TWAMPTimestamp
	SenderSeqNumber     uint32
	SenderTimestamp     common.TWAMPTimestamp
	SenderErrorEstimate common.ErrorEstimate
	MBZ2                [2]byte // Must be zeros
	SenderTTL           uint8
	PaddingSize         int // Not part of the packet, but size info for padding
}

// Marshal converts ReflectorTestPacket to network bytes
func (rtp *ReflectorTestPacket) Marshal() ([]byte, error) {
	// Base size (41) + padding
	size := 41 + rtp.PaddingSize
	buf := make([]byte, size)

	// Sequence Number (4 bytes)
	binary.BigEndian.PutUint32(buf[0:4], rtp.SeqNumber)

	// Timestamp (8 bytes)
	rtp.Timestamp.Marshal(buf[4:12])

	// Error Estimate (2 bytes)
	binary.BigEndian.PutUint16(buf[12:14], rtp.ErrorEstimate.ToUint16())

	// MBZ (2 bytes, already zeros from make)

	// Receive Timestamp (8 bytes)
	rtp.ReceiveTimestamp.Marshal(buf[16:24])

	// Sender Sequence Number (4 bytes)
	binary.BigEndian.PutUint32(buf[24:28], rtp.SenderSeqNumber)

	// Sender Timestamp (8 bytes)
	rtp.SenderTimestamp.Marshal(buf[28:36])

	// Sender Error Estimate (2 bytes)
	binary.BigEndian.PutUint16(buf[36:38], rtp.SenderErrorEstimate.ToUint16())

	// MBZ (2 bytes, already zeros from make)

	// Sender TTL (1 byte)
	buf[40] = rtp.SenderTTL

	// Fill padding with random bytes
	// In real implementation, should use crypto/rand for this
	for i := 41; i < size; i++ {
		buf[i] = byte(i % 256) // Deterministic pattern for now
	}

	return buf, nil
}

// Unmarshal parses network bytes into ReflectorTestPacket
func (rtp *ReflectorTestPacket) Unmarshal(data []byte) error {
	if len(data) < 41 {
		return ErrInvalidMessageLength
	}

	// Extract Sequence Number
	rtp.SeqNumber = binary.BigEndian.Uint32(data[0:4])

	// Extract Timestamp
	rtp.Timestamp.Unmarshal(data[4:12])

	// Extract Error Estimate
	var ee uint16
	ee = binary.BigEndian.Uint16(data[12:14])
	rtp.ErrorEstimate.FromUint16(ee)

	// Validate MBZ
	if data[14] != 0 || data[15] != 0 {
		return ErrInvalidMBZ
	}

	// Extract Receive Timestamp
	rtp.ReceiveTimestamp.Unmarshal(data[16:24])

	// Extract Sender Sequence Number
	rtp.SenderSeqNumber = binary.BigEndian.Uint32(data[24:28])

	// Extract Sender Timestamp
	rtp.SenderTimestamp.Unmarshal(data[28:36])

	// Extract Sender Error Estimate
	ee = binary.BigEndian.Uint16(data[36:38])
	rtp.SenderErrorEstimate.FromUint16(ee)

	// Validate MBZ
	if data[38] != 0 || data[39] != 0 {
		return ErrInvalidMBZ
	}

	// Extract Sender TTL
	rtp.SenderTTL = data[40]

	// Record actual padding size
	rtp.PaddingSize = len(data) - 41

	return nil
}

// ReflectorTestPacketAuth represents the authenticated/encrypted version
// of the ReflectorTestPacket
type ReflectorTestPacketAuth struct {
	SeqNumber           uint32
	MBZ                 [12]byte // Must be zeros
	Timestamp           common.TWAMPTimestamp
	ErrorEstimate       common.ErrorEstimate
	MBZ2                [6]byte // Must be zeros
	ReceiveTimestamp    common.TWAMPTimestamp
	MBZ3                [8]byte // Must be zeros
	SenderSeqNumber     uint32
	MBZ4                [12]byte // Must be zeros
	SenderTimestamp     common.TWAMPTimestamp
	SenderErrorEstimate common.ErrorEstimate
	MBZ5                [6]byte // Must be zeros
	SenderTTL           uint8
	MBZ6                [15]byte // Must be zeros
	HMAC                [16]byte
	PaddingSize         int // Not part of the packet, but size info for padding
}

// Marshal converts ReflectorTestPacketAuth to network bytes
func (rtpa *ReflectorTestPacketAuth) Marshal() ([]byte, error) {
	// Base size (112) + padding (to fit auth)
	minSize := 112
	size := minSize
	if rtpa.PaddingSize > 0 {
		size = minSize + rtpa.PaddingSize
	}
	buf := make([]byte, size)

	// Sequence Number (4 bytes)
	binary.BigEndian.PutUint32(buf[0:4], rtpa.SeqNumber)

	// MBZ (12 bytes, already zeros from make)

	// Timestamp (8 bytes)
	rtpa.Timestamp.Marshal(buf[16:24])

	// Error Estimate (2 bytes)
	binary.BigEndian.PutUint16(buf[24:26], rtpa.ErrorEstimate.ToUint16())

	// MBZ (6 bytes, already zeros from make)

	// Receive Timestamp (8 bytes)
	rtpa.ReceiveTimestamp.Marshal(buf[32:40])

	// MBZ (8 bytes, already zeros from make)

	// Sender Sequence Number (4 bytes)
	binary.BigEndian.PutUint32(buf[48:52], rtpa.SenderSeqNumber)

	// MBZ (12 bytes, already zeros from make)

	// Sender Timestamp (8 bytes)
	rtpa.SenderTimestamp.Marshal(buf[64:72])

	// Sender Error Estimate (2 bytes)
	binary.BigEndian.PutUint16(buf[72:74], rtpa.SenderErrorEstimate.ToUint16())

	// MBZ (6 bytes, already zeros from make)

	// Sender TTL (1 byte)
	buf[80] = rtpa.SenderTTL

	// MBZ (15 bytes, already zeros from make)

	// HMAC (16 bytes)
	copy(buf[96:112], rtpa.HMAC[:])

	// Fill padding with random bytes
	// In real implementation, should use crypto/rand for this
	for i := 112; i < size; i++ {
		buf[i] = byte(i % 256) // Deterministic pattern for now
	}

	return buf, nil
}

// Unmarshal parses network bytes into ReflectorTestPacketAuth
func (rtpa *ReflectorTestPacketAuth) Unmarshal(data []byte) error {
	if len(data) < 104 {
		return ErrInvalidMessageLength
	}

	// Extract Sequence Number
	rtpa.SeqNumber = binary.BigEndian.Uint32(data[0:4])

	// Validate MBZ
	for i := 4; i < 16; i++ {
		if data[i] != 0 {
			return ErrInvalidMBZ
		}
	}

	// Extract Timestamp
	rtpa.Timestamp.Unmarshal(data[16:24])

	// Extract Error Estimate
	var ee uint16
	ee = binary.BigEndian.Uint16(data[24:26])
	rtpa.ErrorEstimate.FromUint16(ee)

	// Validate MBZ
	for i := 26; i < 32; i++ {
		if data[i] != 0 {
			return ErrInvalidMBZ
		}
	}

	// Extract Receive Timestamp
	rtpa.ReceiveTimestamp.Unmarshal(data[32:40])

	// Validate MBZ
	for i := 40; i < 48; i++ {
		if data[i] != 0 {
			return ErrInvalidMBZ
		}
	}

	// Extract Sender Sequence Number
	rtpa.SenderSeqNumber = binary.BigEndian.Uint32(data[48:52])

	// Validate MBZ
	for i := 52; i < 64; i++ {
		if data[i] != 0 {
			return ErrInvalidMBZ
		}
	}

	// Extract Sender Timestamp
	rtpa.SenderTimestamp.Unmarshal(data[64:72])

	// Extract Sender Error Estimate
	ee = binary.BigEndian.Uint16(data[72:74])
	rtpa.SenderErrorEstimate.FromUint16(ee)

	// Validate MBZ
	for i := 74; i < 80; i++ {
		if data[i] != 0 {
			return ErrInvalidMBZ
		}
	}

	// Extract Sender TTL
	rtpa.SenderTTL = data[80]

	// Validate MBZ
	for i := 81; i < 96; i++ {
		if data[i] != 0 {
			return ErrInvalidMBZ
		}
	}

	// Extract HMAC
	copy(rtpa.HMAC[:], data[96:112])

	// Record actual padding size
	rtpa.PaddingSize = len(data) - 104

	return nil
}
