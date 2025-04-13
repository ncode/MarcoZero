// examples/server/main.go
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/ncode/MarcoZero/pkg/twamp/common"
	"github.com/ncode/MarcoZero/pkg/twamp/server"
)

func main() {
	// Create a server
	cfg := server.ServerConfig{
		ListenAddress:  "127.0.0.1:8620",
		SupportedModes: common.ModeUnauthenticated | common.ModeAuthenticated | common.ModeEncrypted,
		SecretMap:      map[string]string{"test-user": "test-password"},
	}

	twampServer := server.NewServer(cfg)

	// Start the server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := twampServer.Start(ctx)
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	log.Println("TWAMP server running on port 862")

	// Wait for signal to shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down server...")
	twampServer.Stop()
}
