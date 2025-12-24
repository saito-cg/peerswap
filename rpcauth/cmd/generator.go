package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
)

// GenerateSalt creates a random hex salt of specified byte size
func GenerateSalt(size int) (string, error) {
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// GeneratePassword creates a random password
func GeneratePassword(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	for i := 0; i < length; i++ {
		bytes[i] = charset[int(bytes[i])%len(charset)]
	}
	return string(bytes), nil
}

// PasswordToHMAC computes HMAC-SHA256 hash
func PasswordToHMAC(salt, password string) string {
	h := hmac.New(sha256.New, []byte(salt))
	h.Write([]byte(password))
	return hex.EncodeToString(h.Sum(nil))
}

// RPCAuth represents the authentication credentials
type RPCAuth struct {
	Username string
	Salt     string
	Hash     string
	Password string
}

// GenerateRPCAuth generates complete rpcauth credentials
func GenerateRPCAuth(username, password string) (*RPCAuth, error) {
	// Generate password if not provided
	if password == "" {
		var err error
		password, err = GeneratePassword(32)
		if err != nil {
			return nil, fmt.Errorf("failed to generate password:  %w", err)
		}
	}

	// Generate 16-byte salt
	salt, err := GenerateSalt(16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Compute HMAC
	hash := PasswordToHMAC(salt, password)

	return &RPCAuth{
		Username: username,
		Salt:     salt,
		Hash:     hash,
		Password: password,
	}, nil
}

// String returns the rpcauth configuration line
func (r *RPCAuth) String() string {
	return fmt.Sprintf("rpcauth=%s:%s$%s", r.Username, r.Salt, r.Hash)
}

func main() {
	username := flag.String("username", "", "Username for authentication (required)")
	password := flag.String("password", "", "Password (leave empty to auto-generate)")
	configFormat := flag.Bool("config", false, "Output in config file format")
	envFormat := flag.Bool("env", false, "Output environment variables only")
	jsonFormat := flag.Bool("json", false, "Output in JSON format")

	flag.Usage = func() {
		fmt.Println("Usage: go run generator.go [OPTIONS]")
		fmt.Println("\nGenerate rpcauth credentials for PeerSwap gRPC authentication")
		fmt.Println("\nOptions:")
		flag.PrintDefaults()
		fmt.Println("\nExamples:")
		fmt.Println("  # Generate with auto-generated password")
		fmt.Println("  go run generator. go -username alice")
		fmt.Println()
		fmt.Println("  # Generate with specific password")
		fmt.Println("  go run generator.go -username alice -password mypassword")
		fmt.Println()
		fmt.Println("  # Output only config format")
		fmt.Println("  go run generator.go -username alice -config")
		fmt.Println()
		fmt.Println("  # Output only environment variables")
		fmt.Println("  go run generator.go -username alice -env")
		fmt.Println()
		fmt.Println("  # Output in JSON format")
		fmt.Println("  go run generator.go -username alice -json")
	}

	flag.Parse()

	if *username == "" {
		log.Fatal("Error: Username is required.  Use -username flag.")
	}

	auth, err := GenerateRPCAuth(*username, *password)
	if err != nil {
		log.Fatalf("Failed to generate credentials: %v", err)
	}

	// JSON format output
	if *jsonFormat {
		fmt.Printf(`{
  "username": "%s",
  "password": "%s",
  "rpcauth": "%s:%s$%s"
}
`, auth.Username, auth.Password, auth.Username, auth.Salt, auth.Hash)
		return
	}

	// Environment variables only
	if *envFormat {
		fmt.Printf("export PEERSWAP_RPC_USER=%s\n", auth.Username)
		fmt.Printf("export PEERSWAP_RPC_PASSWORD=%s\n", auth.Password)
		return
	}

	// Config format only
	if *configFormat {
		fmt.Println(auth.String())
		return
	}

	// Full output (default)
	fmt.Println("╔════════════════════════════════════════════════════════════════╗")
	fmt.Println("║          PeerSwap RPC Authentication Credentials               ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	fmt.Println("📝 Configuration File Entry")
	fmt.Println("───────────────────────────────────────────────────────────────")
	fmt.Println("Add this line to your peerswap.conf:")
	fmt.Println()
	fmt.Printf("  %s\n", auth.String())
	fmt.Println()

	fmt.Println("🔐 Your Credentials")
	fmt.Println("───────────────────────────────────────────────────────────────")
	fmt.Printf("  Username: %s\n", auth.Username)
	fmt.Printf("  Password: %s\n", auth.Password)
	fmt.Println()
}
