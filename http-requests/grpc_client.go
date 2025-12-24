package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"os"
	"strings"
	"time"

	"github.com/elementsproject/peerswap/peerswaprpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Default credentials (used if no environment variables are provided)
const (
	defaultUser = "ebis"
	defaultPass = "password"
)

// basicAuthCred injects "authorization: Basic <base64(user:pass)>" into gRPC metadata.
type basicAuthCred struct {
	headerVal string // e.g., "Basic ZWJpczpwYXNzd29yZA=="
}

func (c basicAuthCred) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	// Use lowercase key to match server-side parsing.
	return map[string]string{"authorization": c.headerVal}, nil
}

func (c basicAuthCred) RequireTransportSecurity() bool {
	// Set to true in production when using TLS.
	return false
}

// buildBasicHeader returns "Basic <base64(user:pass)>" from rpcauth input:
// - "user:password" -> encodes and prefixes "Basic "
// - "Basic <base64>" -> returns as-is
// - "<base64>" -> prefixes "Basic " (if it's valid base64)
func buildBasicHeader(rpcauth string) (string, error) {
	s := strings.TrimSpace(rpcauth)
	if s == "" {
		return "", nil
	}
	if strings.Contains(s, ":") {
		enc := base64.StdEncoding.EncodeToString([]byte(s))
		return "Basic " + enc, nil
	}
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "basic ") {
		return s, nil
	}
	// Validate it's base64(user:pass)
	if _, err := base64.StdEncoding.DecodeString(s); err != nil {
		return "", err
	}
	return "Basic " + s, nil
}

func main() {
	// Read rpcauth from environment:
	// - PEERSWAP_RPCAUTH: "user:password" or "Basic <base64>" or "<base64>"
	// Fallback:
	// - PEERSWAP_RPC_USER / PEERSWAP_RPC_PASSWORD -> "user:password"
	// Default:
	// - "ebis:password"
	rpcauth := strings.TrimSpace(os.Getenv("PEERSWAP_RPCAUTH"))
	if rpcauth == "" {
		user := os.Getenv("PEERSWAP_RPC_USER")
		pass := os.Getenv("PEERSWAP_RPC_PASSWORD")
		switch {
		case user != "":
			rpcauth = user + ":" + pass
		default:
			rpcauth = defaultUser + ":" + defaultPass
		}
	}

	var dialOpts []grpc.DialOption
	dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))

	if rpcauth != "" {
		header, err := buildBasicHeader(rpcauth)
		if err != nil {
			log.Fatalf("invalid rpcauth: %v", err)
		}
		dialOpts = append(dialOpts, grpc.WithPerRPCCredentials(basicAuthCred{headerVal: header}))
	}

	conn, err := grpc.Dial("localhost:42069", dialOpts...)
	if err != nil {
		log.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()

	client := peerswaprpc.NewPeerSwapClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := client.ListPeers(ctx, &peerswaprpc.ListPeersRequest{})
	if err != nil {
		log.Fatalf("ListPeers failed: %v", err)
	}

	jsonData, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		log.Fatalf("JSON marshal failed: %v", err)
	}

	log.Println(string(jsonData))
}
