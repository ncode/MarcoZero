// pkg/twamp/client/test_session.go
package client

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/ncode/MarcoZero/pkg/twamp/common"
	"github.com/ncode/MarcoZero/pkg/twamp/crypto"
	"github.com/ncode/MarcoZero/pkg/twamp/messages"
)

type PacketResult struct {
	SenderSeqNo            uint32
	ReflectorSeqNo         uint32
	SentTime               time.Time
	ReceivedTime           time.Time
	ReflectorRxTime        time.Time
	ReflectorTxTime        time.Time
	SenderTimestamp        common.TWAMPTimestamp // Original sender timestamp
	SenderErrorEstimate    common.ErrorEstimate  // Sender's error estimate
	ReflectorErrorEstimate common.ErrorEstimate  // Reflector's error estimate
	SenderTTL              uint8
	RTT                    time.Duration
	ReflectorLatency       time.Duration
}

// TestSessionConfig contains configuration for a TWAMP test session
type TestSessionConfig struct {
	SenderPort      uint16
	ReceiverPort    uint16
	ReceiverAddress string // Optional, defaults to control connection address
	PaddingLength   uint32
	Timeout         time.Duration
	DSCP            uint8
}

// TestSessionResult contains results from a TWAMP test session
type TestSessionResult struct {
	PacketsSent     uint32
	PacketsReceived uint32
	PacketsLost     uint32
	MinRTT          time.Duration
	MaxRTT          time.Duration
	AvgRTT          time.Duration
	RTTVariation    time.Duration // Jitter (standard deviation)

	// Enhanced metrics
	MinReflectorLatency time.Duration // Min processing time on reflector
	MaxReflectorLatency time.Duration // Max processing time on reflector
	AvgReflectorLatency time.Duration // Avg processing time on reflector

	// One-way delay estimates (if clocks are synced)
	AvgForwardDelay time.Duration // Average sender->reflector
	AvgReverseDelay time.Duration // Average reflector->sender
	DelayAsymmetry  float64       // Ratio of forward to reverse delay
}

// TestSession represents an individual TWAMP test session
type TestSession struct {
	config          TestSessionConfig
	sid             common.SessionID
	conn            *net.UDPConn
	seqNo           uint32
	sessionKeys     *crypto.TWAMPKeys
	mode            common.Mode
	results         sync.Map // map[uint32]*PacketResult
	totalSent       uint32
	totalReceived   uint32
	minRTT          time.Duration
	maxRTT          time.Duration
	sumRTT          time.Duration
	mu              sync.Mutex
	stopChan        chan struct{}
	isAuthenticated bool
	isEncrypted     bool
	isStopping      bool           // New flag to track stopping state
	receiverWg      sync.WaitGroup // New WaitGroup to track receiver goroutine
}

// NewTestSession creates a new test session
func NewTestSession(config TestSessionConfig, sid common.SessionID, mode common.Mode, controlKeys *crypto.TWAMPKeys) (*TestSession, error) {
	ts := &TestSession{
		config:   config,
		sid:      sid,
		mode:     mode,
		stopChan: make(chan struct{}),
		minRTT:   time.Duration(1<<63 - 1), // Max value for comparison
	}

	// Determine if session is authenticated or encrypted
	ts.isAuthenticated = mode == common.ModeAuthenticated || mode == common.ModeEncrypted
	ts.isEncrypted = mode == common.ModeEncrypted

	// Derive session keys if using authenticated or encrypted mode
	if ts.isAuthenticated && controlKeys != nil {
		testAESKey, testHMACKey, err := crypto.DeriveTestSessionKeys(
			controlKeys.AESKey,
			controlKeys.HMACKey,
			sid,
		)
		if err != nil {
			return nil, err
		}

		ts.sessionKeys = &crypto.TWAMPKeys{
			TestAESKey:  testAESKey,
			TestHMACKey: testHMACKey,
			ClientIV:    controlKeys.ClientIV,
			ServerIV:    controlKeys.ServerIV,
		}
	}

	return ts, nil
}

// Start starts the test session
func (ts *TestSession) Start() error {
	ts.mu.Lock()
	// Reset stopping flag when starting
	ts.isStopping = false
	// Create a new stop channel if needed
	if ts.stopChan == nil {
		ts.stopChan = make(chan struct{})
	}
	ts.mu.Unlock()

	// Set up UDP connection for the test session
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%s", strconv.Itoa(int(ts.config.SenderPort))))
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}

	ts.mu.Lock()
	ts.conn = conn
	ts.mu.Unlock()

	return nil
}

// SendTestPacket sends a single test packet
func (ts *TestSession) SendTestPacket() error {
	// Lock to ensure atomic sequence number usage
	ts.mu.Lock()
	seqNo := ts.seqNo
	ts.seqNo++
	ts.totalSent++
	ts.mu.Unlock()

	// Get current timestamp using monotonic clock for accuracy
	timestamp, localTime := common.MonotonicNow()

	// Create error estimate (using a more realistic value now)
	// The S bit indicates if the clock is synchronized with an external source
	// Scale and Multiplier encode the error estimate as per RFC 4656
	syncBit := isClockSynchronized()
	errorEstimate := common.ErrorEstimate{
		Multiplier: 1,
		Scale:      8, // Realistic error scale for most NTP-synchronized clocks
		S:          syncBit,
	}

	var packet []byte
	var err error

	// Create appropriate packet type based on mode
	if ts.isAuthenticated {
		// Authenticated or encrypted mode
		testPacket := &messages.SenderTestPacketAuth{
			SeqNumber:     seqNo,
			Timestamp:     timestamp,
			ErrorEstimate: errorEstimate,
			PaddingSize:   int(ts.config.PaddingLength) - 48, // Adjust for header size
		}

		// Marshal the packet
		packet, err = testPacket.Marshal()
		if err != nil {
			return err
		}

		// If in authenticated or encrypted mode, calculate HMAC and encrypt
		if ts.sessionKeys != nil {
			// Calculate HMAC
			hmacSize := 32
			if ts.isEncrypted {
				hmacSize = 96
			}
			hmac, err := crypto.CalculateHMAC(ts.sessionKeys.TestHMACKey, packet[:hmacSize])

			// Copy HMAC into packet
			copy(packet[hmacSize:hmacSize+16], hmac)

			// If in encrypted mode, encrypt the packet
			if ts.isEncrypted {
				packet, err = crypto.EncryptTWAMPTestPacket(
					ts.sessionKeys.TestAESKey,
					ts.sessionKeys.ClientIV,
					packet,
					false, // Not authenticated only
				)
				if err != nil {
					return err
				}
			}
		}
	} else {
		// Unauthenticated mode
		testPacket := &messages.SenderTestPacket{
			SeqNumber:     seqNo,
			Timestamp:     timestamp,
			ErrorEstimate: errorEstimate,
			PaddingSize:   int(ts.config.PaddingLength) - 14, // Adjust for header size
		}

		// Marshal the packet
		packet, err = testPacket.Marshal(true) // Use random padding
		if err != nil {
			return err
		}
	}

	// Store sent time for RTT calculation - using the same monotonic time reference
	ts.results.Store(seqNo, &PacketResult{
		SenderSeqNo:     seqNo,
		SentTime:        localTime,
		SenderTimestamp: timestamp,
	})

	// Send the packet
	destAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%s", ts.config.ReceiverAddress, strconv.Itoa(int(ts.config.ReceiverPort))))
	if err != nil {
		return err
	}

	_, err = ts.conn.WriteTo(packet, destAddr)
	return err
}

// StartReceiving starts a goroutine to receive and process test responses
func (ts *TestSession) StartReceiving(ctx context.Context) {
	ts.mu.Lock()
	if ts.isStopping || ts.conn == nil {
		ts.mu.Unlock()
		return // Don't start if already stopping or no connection
	}
	ts.receiverWg.Add(1) // Track the goroutine with WaitGroup
	ts.mu.Unlock()

	go func() {
		defer ts.receiverWg.Done()

		buf := make([]byte, 2048)

		for {
			// Get a safe copy of the connection and stopChan
			ts.mu.Lock()
			conn := ts.conn
			stopChan := ts.stopChan
			ts.mu.Unlock()

			if conn == nil || stopChan == nil {
				return // Exit if either is nil
			}

			// Set a short deadline and check for ctx/stopChan frequently
			conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))

			select {
			case <-ctx.Done():
				return
			case <-stopChan:
				return
			default:
				// Try to read a packet
				n, _, err := conn.ReadFrom(buf)
				if err != nil {
					// Handle timeout and continue
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						continue
					}

					// Check if we need to stop
					select {
					case <-stopChan:
						return
					default:
						continue // Some other error
					}
				}

				recvTime := time.Now()
				err = ts.processReceivedPacket(buf[:n], recvTime)
				if err != nil {
					log.Printf("Error processing received packet: %v", err)
				}
			}
		}
	}()
}

// processReceivedPacket processes a received test packet
func (ts *TestSession) processReceivedPacket(packet []byte, recvTime time.Time) error {
	var senderSeqNo uint32
	var reflectorSeqNo uint32
	var senderTimestamp common.TWAMPTimestamp
	var reflectorRxTimestamp common.TWAMPTimestamp
	var reflectorTxTimestamp common.TWAMPTimestamp
	var senderErrEst common.ErrorEstimate
	var reflectorErrEst common.ErrorEstimate
	var senderTTL uint8

	// Parse packet based on mode
	if ts.isAuthenticated {
		// Authenticated or encrypted mode
		var testPacket messages.ReflectorTestPacketAuth

		// If in encrypted mode, decrypt first
		if ts.isEncrypted && ts.sessionKeys != nil {
			decryptedPacket, err := crypto.DecryptTWAMPTestPacket(
				ts.sessionKeys.TestAESKey,
				ts.sessionKeys.ServerIV,
				packet,
				false, // Not authenticated only
			)
			if err != nil {
				return err
			}
			packet = decryptedPacket
		}

		err := testPacket.Unmarshal(packet)
		if err != nil {
			return err
		}

		// Verify HMAC if in secure mode
		if ts.sessionKeys != nil {
			valid, err := crypto.VerifyHMAC(ts.sessionKeys.TestHMACKey, packet[:96], packet[96:112])
			if err != nil {
				return err
			}
			if !valid {
				return errors.New("HMAC verification failed")
			}
		}

		// Extract all fields
		reflectorSeqNo = testPacket.SeqNumber
		reflectorTxTimestamp = testPacket.Timestamp
		reflectorErrEst = testPacket.ErrorEstimate
		reflectorRxTimestamp = testPacket.ReceiveTimestamp
		senderSeqNo = testPacket.SenderSeqNumber
		senderTimestamp = testPacket.SenderTimestamp
		senderErrEst = testPacket.SenderErrorEstimate
		senderTTL = testPacket.SenderTTL
	} else {
		// Unauthenticated mode
		var testPacket messages.ReflectorTestPacket
		err := testPacket.Unmarshal(packet)
		if err != nil {
			return err
		}

		// Extract all fields
		reflectorSeqNo = testPacket.SeqNumber
		reflectorTxTimestamp = testPacket.Timestamp
		reflectorErrEst = testPacket.ErrorEstimate
		reflectorRxTimestamp = testPacket.ReceiveTimestamp
		senderSeqNo = testPacket.SenderSeqNumber
		senderTimestamp = testPacket.SenderTimestamp
		senderErrEst = testPacket.SenderErrorEstimate
		senderTTL = testPacket.SenderTTL
	}

	// Look up the original sent packet info
	resultVal, ok := ts.results.Load(senderSeqNo)
	if !ok {
		return errors.New("received response for unknown sequence number")
	}
	result := resultVal.(*PacketResult)

	// Update result with ALL received information
	result.ReceivedTime = recvTime
	result.ReflectorSeqNo = reflectorSeqNo
	result.ReflectorRxTime = reflectorRxTimestamp.ToTime()
	result.ReflectorTxTime = reflectorTxTimestamp.ToTime()
	result.SenderTimestamp = senderTimestamp
	result.SenderErrorEstimate = senderErrEst
	result.ReflectorErrorEstimate = reflectorErrEst
	result.SenderTTL = senderTTL

	// Calculate RTT - since we used monotonic clocks, this will be accurate
	// even if system time jumps during the measurement
	rtt := recvTime.Sub(result.SentTime)
	result.RTT = rtt

	// Calculate reflector latency in two ways:
	// 1. Using the timestamps from the packet (reflector's view)
	reflectorLatency := common.DurationBetween(reflectorRxTimestamp, reflectorTxTimestamp)
	result.ReflectorLatency = reflectorLatency

	// Update statistics
	ts.mu.Lock()
	ts.totalReceived++
	ts.sumRTT += rtt
	if rtt < ts.minRTT {
		ts.minRTT = rtt
	}
	if rtt > ts.maxRTT {
		ts.maxRTT = rtt
	}
	ts.mu.Unlock()

	return nil
}

// Stop stops the test session
func (ts *TestSession) Stop() error {
	ts.mu.Lock()

	// Check if already stopping
	if ts.isStopping {
		ts.mu.Unlock()
		return nil
	}

	// Mark as stopping
	ts.isStopping = true

	// Get a reference to the stopChan and channel
	stopChan := ts.stopChan
	conn := ts.conn

	// Clear the fields to prevent reuse
	ts.stopChan = nil
	ts.conn = nil

	ts.mu.Unlock()

	// Close channel outside lock
	if stopChan != nil {
		close(stopChan)
	}

	// Wait for receiver goroutine to exit
	ts.receiverWg.Wait()

	// Now it's safe to close the connection
	if conn != nil {
		return conn.Close()
	}

	return nil
}

// GetResults returns the current test session results with enhanced metrics
func (ts *TestSession) GetResults() TestSessionResult {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	// Basic metrics
	var avgRTT time.Duration
	if ts.totalReceived > 0 {
		avgRTT = ts.sumRTT / time.Duration(ts.totalReceived)
	}

	result := TestSessionResult{
		PacketsSent:     ts.totalSent,
		PacketsReceived: ts.totalReceived,
		PacketsLost:     ts.totalSent - ts.totalReceived,
		MinRTT:          ts.minRTT,
		MaxRTT:          ts.maxRTT,
		AvgRTT:          avgRTT,
	}

	// Calculate enhanced metrics if we have received packets
	if ts.totalReceived > 0 {
		var sumReflectorLatency time.Duration
		var minReflectorLatency = time.Duration(1<<63 - 1) // Max value
		var maxReflectorLatency time.Duration

		// Sum of squared differences for RTT jitter calculation
		var sumSquaredRTTDiff time.Duration

		// One-way delay estimates (if clocks are synced)
		var sumForwardDelay time.Duration
		var sumReverseDelay time.Duration

		count := 0

		// Process all packets to calculate enhanced metrics
		ts.results.Range(func(_, value interface{}) bool {
			pr := value.(*PacketResult)

			// Only count packets that were actually received
			if !pr.ReceivedTime.IsZero() {
				count++

				// Reflector latency
				reflectorLatency := pr.ReflectorLatency
				sumReflectorLatency += reflectorLatency

				if reflectorLatency < minReflectorLatency {
					minReflectorLatency = reflectorLatency
				}
				if reflectorLatency > maxReflectorLatency {
					maxReflectorLatency = reflectorLatency
				}

				// RTT variance for jitter calculation
				diffFromAvg := pr.RTT - avgRTT
				sumSquaredRTTDiff += diffFromAvg * diffFromAvg

				// One-way delay estimates
				// (only meaningful if clocks are synced between sender and reflector)
				if pr.SenderErrorEstimate.S && pr.ReflectorErrorEstimate.S {
					// Both clocks claim to be synchronized

					// Forward delay: reflector receive time - sender send time
					forwardDelay := pr.ReflectorRxTime.Sub(pr.SentTime)
					sumForwardDelay += forwardDelay

					// Reverse delay: sender receive time - reflector send time
					reverseDelay := pr.ReceivedTime.Sub(pr.ReflectorTxTime)
					sumReverseDelay += reverseDelay
				}
			}
			return true
		})

		// Calculate final enhanced metrics
		if count > 0 {
			// Reflector latency stats
			result.MinReflectorLatency = minReflectorLatency
			result.MaxReflectorLatency = maxReflectorLatency
			result.AvgReflectorLatency = sumReflectorLatency / time.Duration(count)

			// RTT standard deviation (jitter)
			if count > 1 {
				variance := sumSquaredRTTDiff / time.Duration(count-1)
				result.RTTVariation = time.Duration(math.Sqrt(float64(variance)))
			}

			// One-way delay estimates
			result.AvgForwardDelay = sumForwardDelay / time.Duration(count)
			result.AvgReverseDelay = sumReverseDelay / time.Duration(count)

			// Calculate delay asymmetry if we have valid delay values
			if result.AvgReverseDelay > 0 {
				result.DelayAsymmetry = float64(result.AvgForwardDelay) / float64(result.AvgReverseDelay)
			}
		}
	}

	return result
}

// GetAllPacketResults returns detailed results for all packets
func (ts *TestSession) GetAllPacketResults() []*PacketResult {
	results := make([]*PacketResult, 0)

	ts.results.Range(func(key, value interface{}) bool {
		results = append(results, value.(*PacketResult))
		return true
	})

	return results
}
