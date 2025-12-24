package rpcauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/elementsproject/peerswap/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Entry holds parsed rpcauth credentials for a single user.
type Entry struct {
	Salt string
	Hash string // lowercased hex HMAC-SHA256(salt, password)
}

// ParseConfigValue parses a config string that may contain one or more rpcauth
// entries separated by commas. Each entry must be in the form "username:salt$hash".
func ParseConfigValue(authValue string) map[string]Entry {
	raw := strings.TrimSpace(authValue)
	log.Debugf("[AUTH][ParseConfigValue] raw length=%d empty=%v", len(raw), raw == "")
	if raw == "" {
		return map[string]Entry{}
	}
	entries := strings.Split(raw, ",")
	log.Debugf("[AUTH][ParseConfigValue] split into %d entries", len(entries))
	for i, e := range entries {
		log.Debugf("[AUTH][ParseConfigValue] entry[%d]=%q", i, strings.TrimSpace(e))
	}
	return ParseRpcauthEntries(entries)
}

// ParseRpcauthEntries converts `username:salt$hash` strings into a map[username]Entry.
func ParseRpcauthEntries(entries []string) map[string]Entry {
	log.Debugf("[AUTH][ParseRpcauthEntries] start parse, count=%d", len(entries))
	auths := make(map[string]Entry)
	for idx, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			log.Debugf("[AUTH][ParseRpcauthEntries] entry[%d] empty, skip", idx)
			continue
		}
		parts := strings.SplitN(e, ":", 2)
		if len(parts) != 2 {
			log.Debugf("[AUTH][ParseRpcauthEntries] entry[%d] invalid (missing ':'), raw=%q", idx, e)
			continue
		}
		user := strings.TrimSpace(parts[0])
		saltAndHash := strings.SplitN(parts[1], "$", 2)
		if len(saltAndHash) != 2 {
			log.Debugf("[AUTH][ParseRpcauthEntries] entry[%d] invalid (missing '$'), user=%q rawRemainder=%q", idx, user, parts[1])
			continue
		}
		salt := strings.TrimSpace(saltAndHash[0])
		hash := strings.TrimSpace(saltAndHash[1])
		if user == "" || salt == "" || hash == "" {
			log.Debugf("[AUTH][ParseRpcauthEntries] entry[%d] invalid (empty component) user=%q saltLen=%d hashLen=%d", idx, user, len(salt), len(hash))
			continue
		}
		if len(salt) != 32 {
			log.Debugf("[AUTH][ParseRpcauthEntries] entry[%d] salt length unexpected: got=%d user=%q", idx, len(salt), user)
		}
		if len(hash) != 64 {
			log.Debugf("[AUTH][ParseRpcauthEntries] entry[%d] hash length unexpected: got=%d user=%q", idx, len(hash), user)
		}
		lowerHash := strings.ToLower(hash)
		auths[user] = Entry{Salt: salt, Hash: lowerHash}
		log.Debugf("[AUTH][ParseRpcauthEntries] entry[%d] parsed user=%q saltLen=%d hashLen=%d", idx, user, len(salt), len(lowerHash))
	}
	log.Infof("[AUTH] loaded %d rpcauth entries", len(auths))
	return auths
}

// ExtractBasicAuth parses Authorization: Basic base64(user:pass) from gRPC metadata.
func ExtractBasicAuth(ctx context.Context) (string, string, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	log.Debugf("[AUTH][ExtractBasicAuth] metadata present=%v", ok)
	if !ok {
		return "", "", false
	}
	authVals := md.Get("authorization")
	log.Debugf("[AUTH][ExtractBasicAuth] 'authorization' header count=%d", len(authVals))
	if len(authVals) == 0 {
		authVals = md.Get("Authorization")
		log.Debugf("[AUTH][ExtractBasicAuth] 'Authorization' header count=%d", len(authVals))
	}
	if len(authVals) == 0 {
		return "", "", false
	}
	auth := authVals[0]
	log.Debugf("[AUTH][ExtractBasicAuth] first header prefix=%q", prefix(auth, 16))
	if !strings.HasPrefix(strings.ToLower(auth), "basic ") {
		log.Debugf("[AUTH][ExtractBasicAuth] header does not start with 'Basic '")
		return "", "", false
	}
	enc := strings.TrimSpace(auth[len("Basic "):])
	dec, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		log.Debugf("[AUTH][ExtractBasicAuth] base64 decode failed: %v", err)
		return "", "", false
	}
	cred := string(dec)
	log.Debugf("[AUTH][ExtractBasicAuth] decoded credential length=%d", len(cred))
	up := strings.SplitN(cred, ":", 2)
	if len(up) != 2 {
		log.Debugf("[AUTH][ExtractBasicAuth] decoded credential missing ':' separator")
		return "", "", false
	}
	log.Debugf("[AUTH][ExtractBasicAuth] parsed user=%q passwordLen=%d", up[0], len(up[1]))
	return up[0], up[1], true
}

// VerifyRpcauth: hash == HMAC_SHA256(key=salt, msg=password).
func VerifyRpcauth(user, password string, auths map[string]Entry) bool {
	log.Debugf("[AUTH][VerifyRpcauth] start verify user=%q authsCount=%d", user, len(auths))
	entry, ok := auths[user]
	if !ok {
		log.Debugf("[AUTH][VerifyRpcauth] user not found: %q", user)
		return false
	}
	log.Debugf("[AUTH][VerifyRpcauth] found entry for user=%q saltLen=%d hashLen=%d", user, len(entry.Salt), len(entry.Hash))
	mac := hmac.New(sha256.New, []byte(entry.Salt))
	mac.Write([]byte(password))
	sumHex := hex.EncodeToString(mac.Sum(nil))
	log.Debugf("[AUTH][VerifyRpcauth] computed hash hex prefix=%q fullLen=%d", prefix(sumHex, 12), len(sumHex))
	match := subtle.ConstantTimeCompare([]byte(sumHex), []byte(strings.ToLower(entry.Hash))) == 1
	log.Debugf("[AUTH][VerifyRpcauth] constant-time compare result=%v", match)
	return match
}

func NewUnaryInterceptor(authMap map[string]Entry) grpc.UnaryServerInterceptor {
	log.Debugf("[AUTH][Interceptor] build interceptor authMapCount=%d", len(authMap))
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		log.Debugf("[AUTH][Interceptor] invoked method=%s authEnabled=%v", info.FullMethod, len(authMap) > 0)
		if len(authMap) == 0 {
			return handler(ctx, req)
		}
		u, p, ok := ExtractBasicAuth(ctx)
		log.Debugf("[AUTH][Interceptor] extracted auth ok=%v user=%q passwordLen=%d", ok, u, len(p))
		if !ok {
			log.Infof("[AUTH] missing or invalid Authorization header for %s", info.FullMethod)
			return nil, status.Error(codes.Unauthenticated, "missing or invalid Authorization header")
		}
		if !VerifyRpcauth(u, p, authMap) {
			log.Infof("[AUTH] authentication failed for user '%s' on %s", u, info.FullMethod)
			return nil, status.Error(codes.Unauthenticated, "authentication failed")
		}
		log.Debugf("[AUTH][Interceptor] authentication success for user=%q method=%s", u, info.FullMethod)
		return handler(ctx, req)
	}
}

func prefix(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
