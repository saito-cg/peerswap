package main

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/elementsproject/peerswap/peerswaprpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	conn, err := grpc.Dial(
		"localhost:42069",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
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
