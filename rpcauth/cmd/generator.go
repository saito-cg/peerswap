package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/urfave/cli"
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
			return nil, fmt.Errorf("failed to generate password: %w", err)
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
	app := &cli.App{
		Name:  "ps-rpcauth-generator",
		Usage: "Generate rpcauth credentials for PeerSwap gRPC authentication",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "username",
				Usage:    "Username for authentication (required)",
				Required: true,
			},
			&cli.StringFlag{
				Name:  "password",
				Usage: "Password (leave empty to auto-generate)",
			},
		},
		Action: func(c *cli.Context) error {
			username := c.String("username")
			password := c.String("password")

			auth, err := GenerateRPCAuth(username, password)
			if err != nil {
				return fmt.Errorf("failed to generate credentials: %w", err)
			}

			// Precompute Base64 of "username:password" for Basic Auth header
			b64Cred := base64.StdEncoding.EncodeToString([]byte(auth.Username + ":" + auth.Password))

			// Default output (simple, human-friendly)
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

			fmt.Println("🧾 Encoded Basic Auth (Base64 of username:password)")
			fmt.Println("───────────────────────────────────────────────────────────────")
			fmt.Printf("  %s\n", b64Cred)
			fmt.Println()
			fmt.Println("Use in HTTP header as: Authorization: Basic " + b64Cred)

			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
