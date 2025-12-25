package rpcauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"github.com/elementsproject/peerswap/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// Entry holds parsed rpcauth credentials for a single user.
type Entry struct {
	Salt string
	Hash string // lowercased hex HMAC-SHA256(salt, password)
}

// SecurityOptions collects auth map and IP allowlist used by both gRPC and REST.
type SecurityOptions struct {
	AuthMap     map[string]Entry
	AllowedNets []*net.IPNet
}

// BuildSecurity parses rpcauth and rpcallowip from config values,
// and applies localhost-only default when rpcallowip is not set.
func BuildSecurity(rpcauthValue string, rpcAllowIPs []string) SecurityOptions {
	authMap := ParseConfigValue(rpcauthValue)
	allow := ParseAllowCIDRs(rpcAllowIPs)
	allow = EnsureDefaultLocalAllow(allow)
	return SecurityOptions{AuthMap: authMap, AllowedNets: allow}
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
	mac := hmac.New(sha256.New, []byte(entry.Salt))
	mac.Write([]byte(password))
	sumHex := hex.EncodeToString(mac.Sum(nil))
	match := subtle.ConstantTimeCompare([]byte(sumHex), []byte(strings.ToLower(entry.Hash))) == 1
	return match
}

// NewUnaryInterceptor builds a gRPC unary interceptor that enforces rpcauth.
// If authMap is empty, authentication is skipped (backwards-compatible).
func NewUnaryInterceptor(authMap map[string]Entry) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if len(authMap) == 0 {
			return handler(ctx, req)
		}
		u, p, ok := ExtractBasicAuth(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing or invalid Authorization header")
		}
		if !VerifyRpcauth(u, p, authMap) {
			return nil, status.Error(codes.Unauthenticated, "authentication failed")
		}
		return handler(ctx, req)
	}
}

// ParseAllowCIDRs parses allowlist strings (IP or CIDR) into []*net.IPNet.
func ParseAllowCIDRs(rpcAllow []string) []*net.IPNet {
	var nets []*net.IPNet
	for _, v := range rpcAllow {
		s := strings.TrimSpace(v)
		if s == "" {
			continue
		}
		if strings.Contains(s, "/") {
			_, n, err := net.ParseCIDR(s)
			if err != nil {
				continue
			}
			nets = append(nets, n)
			continue
		}
		ip := net.ParseIP(s)
		if ip == nil {
			continue
		}
		var mask net.IPMask
		if ip.To4() != nil {
			mask = net.CIDRMask(32, 32)
		} else {
			mask = net.CIDRMask(128, 128)
		}
		n := &net.IPNet{IP: ip, Mask: mask}
		nets = append(nets, n)
	}
	return nets
}

// EnsureDefaultLocalAllow applies bitcoind-like default: if rpcallowip is not set,
// restrict to localhost only (127.0.0.1 and ::1). Used for both REST and gRPC.
func EnsureDefaultLocalAllow(allowedNets []*net.IPNet) []*net.IPNet {
	if len(allowedNets) == 0 {
		return ParseAllowCIDRs([]string{"127.0.0.1", "::1"})
	}
	return allowedNets
}

// NewUnaryIPAllowInterceptor enforces IP allowlist on gRPC.
func NewUnaryIPAllowInterceptor(allowedNets []*net.IPNet) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if len(allowedNets) > 0 {
			ip := clientIPFromGRPC(ctx)
			if !ipAllowed(ip, allowedNets) {
				return nil, status.Error(codes.PermissionDenied, "forbidden: ip not allowed")
			}
		}
		return handler(ctx, req)
	}
}

// clientIPFromGRPC determines client IP for gRPC requests (XFF metadata > peer.Addr).
func clientIPFromGRPC(ctx context.Context) net.IP {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		xff := md.Get("x-forwarded-for")
		if len(xff) == 0 {
			xff = md.Get("X-Forwarded-For")
		}
		if len(xff) > 0 {
			parts := strings.Split(xff[0], ",")
			ip := net.ParseIP(strings.TrimSpace(parts[0]))
			if ip != nil {
				return ip
			}
		}
	}
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		host, _, err := net.SplitHostPort(p.Addr.String())
		if err == nil {
			return net.ParseIP(host)
		}
		if ip := net.ParseIP(p.Addr.String()); ip != nil {
			return ip
		}
	}
	return nil
}

// NewHTTPAuthMiddleware returns an HTTP middleware that enforces rpcallowip and rpcauth.
func NewHTTPAuthMiddleware(authMap map[string]Entry, allowedNets []*net.IPNet) func(next http.Handler) http.Handler {
	enabled := len(authMap) > 0
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// IP allowlist check
			if len(allowedNets) > 0 {
				remoteIP := clientIP(r)
				if !ipAllowed(remoteIP, allowedNets) {
					writeJSON(w, http.StatusForbidden, 7, "forbidden: ip not allowed")
					return
				}
			}
			// rpcauth check
			if enabled {
				u, p, ok := extractBasicFromHTTP(r)
				if !ok {
					w.Header().Set("Www-Authenticate", `Basic realm="peerswap"`)
					writeJSON(w, http.StatusUnauthorized, 16, "missing or invalid Authorization header")
					return
				}
				if !VerifyRpcauth(u, p, authMap) {
					w.Header().Set("Www-Authenticate", `Basic realm="peerswap"`)
					writeJSON(w, http.StatusUnauthorized, 16, "authentication failed")
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Convenience helpers to reduce boilerplate in peerswapd/main.go

// GRPCServerOptions returns server options with IP allowlist and optional rpcauth.
func GRPCServerOptions(sec SecurityOptions, extra ...grpc.ServerOption) []grpc.ServerOption {
	var interceptors []grpc.UnaryServerInterceptor
	interceptors = append(interceptors, NewUnaryIPAllowInterceptor(sec.AllowedNets))
	if len(sec.AuthMap) > 0 {
		interceptors = append(interceptors, NewUnaryInterceptor(sec.AuthMap))
	}
	opts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(interceptors...),
	}
	return append(opts, extra...)
}

// RESTHandler wraps a base handler with IP allowlist and optional rpcauth checks.
func RESTHandler(base http.Handler, sec SecurityOptions) http.Handler {
	return NewHTTPAuthMiddleware(sec.AuthMap, sec.AllowedNets)(base)
}

// HTTP helpers

func extractBasicFromHTTP(r *http.Request) (string, string, bool) {
	auth := r.Header.Get("Authorization")
	if auth == "" || !strings.HasPrefix(strings.ToLower(auth), "basic ") {
		return "", "", false
	}
	enc := strings.TrimSpace(auth[len("Basic "):])
	dec, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", "", false
	}
	cred := string(dec)
	up := strings.SplitN(cred, ":", 2)
	if len(up) != 2 {
		return "", "", false
	}
	return up[0], up[1], true
}

func clientIP(r *http.Request) net.IP {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		ip := net.ParseIP(strings.TrimSpace(parts[0]))
		if ip != nil {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

func ipAllowed(ip net.IP, nets []*net.IPNet) bool {
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"code":    code,
		"message": msg,
		"details": []any{},
	})
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
