// examples/client/main.go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/ncode/MarcoZero/pkg/twamp/client"
	"github.com/ncode/MarcoZero/pkg/twamp/common"
)

func main() {
	// Create a client
	cfg := client.ClientConfig{
		ServerAddress: "127.0.0.1:8620",
		PreferredMode: common.ModeAuthenticated,
		SharedSecret:  "test-password", // Shared secret for authentication
		KeyID:         "test-user",     // KeyID that identifies which shared secret to use
		Timeout:       5 * time.Second,
	}

	twampClient := client.NewClient(cfg)

	// Connect to TWAMP server
	ctx := context.Background()
	err := twampClient.Connect(ctx)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer twampClient.Close()

	// Request a test session
	sessionCfg := client.TestSessionConfig{
		SenderPort:    10000,
		ReceiverPort:  20000,
		PaddingLength: 64,
		Timeout:       2 * time.Second,
	}

	session, err := twampClient.RequestSession(sessionCfg)
	if err != nil {
		log.Fatalf("Failed to request session: %v", err)
	}

	// Start sessions
	err = twampClient.StartSessions()
	if err != nil {
		log.Fatalf("Failed to start sessions: %v", err)
	}

	// Start receiving responses
	session.StartReceiving(ctx)

	// Send 10 test packets at 1-second intervals
	for i := 0; i < 10; i++ {
		err = session.SendTestPacket()
		if err != nil {
			log.Printf("Failed to send test packet: %v", err)
		}
		time.Sleep(1 * time.Second)
	}

	// Get results
	results := session.GetResults()
	fmt.Printf("Test Results:\n")
	fmt.Printf("  Packets Sent: %d\n", results.PacketsSent)
	fmt.Printf("  Packets Received: %d\n", results.PacketsReceived)
	fmt.Printf("  Packets Lost: %d\n", results.PacketsLost)
	fmt.Printf("  Min RTT: %v\n", results.MinRTT)
	fmt.Printf("  Max RTT: %v\n", results.MaxRTT)
	fmt.Printf("  Avg RTT: %v\n", results.AvgRTT)
	fmt.Printf("  Min Latency: %v\n", results.MinReflectorLatency)
	fmt.Printf("  Max Latency: %v\n", results.MaxReflectorLatency)
	fmt.Printf("  Avg Latency: %v\n", results.AvgReflectorLatency)

	// Stop sessions and cleanup
	err = twampClient.StopSessions()
	if err != nil {
		log.Printf("Failed to stop sessions: %v", err)
	}
}
