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

// NewUnaryInterceptor builds a gRPC unary interceptor that enforces rpcauth.
// If authMap is empty, authentication is skipped (backwards-compatible).
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

// ParseAllowCIDRs parses allowlist strings (IP or CIDR) into []*net.IPNet.
// - "1.2.3.4" -> 1.2.3.4/32
// - "2001:db8::1" -> /128
// - "10.0.0.0/8" -> as-is
func ParseAllowCIDRs(rpcAllow []string) []*net.IPNet {
	var nets []*net.IPNet
	for idx, v := range rpcAllow {
		s := strings.TrimSpace(v)
		if s == "" {
			log.Debugf("[AUTH][ParseAllowCIDRs] entry[%d] empty, skip", idx)
			continue
		}
		if strings.Contains(s, "/") {
			_, n, err := net.ParseCIDR(s)
			if err != nil {
				log.Debugf("[AUTH][ParseAllowCIDRs] invalid CIDR %q: %v", s, err)
				continue
			}
			nets = append(nets, n)
			log.Debugf("[AUTH][ParseAllowCIDRs] add CIDR %q", s)
			continue
		}
		ip := net.ParseIP(s)
		if ip == nil {
			log.Debugf("[AUTH][ParseAllowCIDRs] invalid IP %q", s)
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
		log.Debugf("[AUTH][ParseAllowCIDRs] add IP %q", s)
	}
	log.Infof("[AUTH] rpcallowip entries=%d", len(nets))
	return nets
}

// EnsureDefaultLocalAllow applies bitcoind-like default: if rpcallowip is not set,
// restrict to localhost only (127.0.0.1 and ::1).
func EnsureDefaultLocalAllow(allowedNets []*net.IPNet) []*net.IPNet {
	if len(allowedNets) == 0 {
		log.Infof("[AUTH][HTTP] rpcallowip not set; defaulting to localhost-only (127.0.0.1, ::1)")
		return ParseAllowCIDRs([]string{"127.0.0.1", "::1"})
	}
	return allowedNets
}

// NewHTTPAuthMiddleware returns an HTTP middleware that enforces rpcallowip and rpcauth.
// - If allowedNets is non-empty, only requests from these IP ranges are allowed.
// - If authMap is non-empty, Authorization: Basic base64(user:pass) is required.
// - If either is empty, the corresponding check is skipped.
func NewHTTPAuthMiddleware(authMap map[string]Entry, allowedNets []*net.IPNet) func(next http.Handler) http.Handler {
	enabled := len(authMap) > 0
	log.Infof("[AUTH][HTTP] rpcauth enabled=%v, rpcallowip count=%d", enabled, len(allowedNets))
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// IP allowlist check
			if len(allowedNets) > 0 {
				remoteIP := clientIP(r)
				if !ipAllowed(remoteIP, allowedNets) {
					log.Infof("[AUTH][HTTP] forbidden remote ip=%s path=%s", remoteIP, r.URL.Path)
					writeJSON(w, http.StatusForbidden, 7, "forbidden: ip not allowed") // gRPC code 7: PermissionDenied
					return
				}
			}

			// rpcauth check
			if enabled {
				u, p, ok := extractBasicFromHTTP(r)
				if !ok {
					log.Infof("[AUTH][HTTP] missing or invalid Authorization header path=%s", r.URL.Path)
					w.Header().Set("Www-Authenticate", `Basic realm="peerswap"`)
					writeJSON(w, http.StatusUnauthorized, 16, "missing or invalid Authorization header") // gRPC code 16: Unauthenticated
					return
				}
				if !VerifyRpcauth(u, p, authMap) {
					log.Infof("[AUTH][HTTP] authentication failed for user=%q path=%s", u, r.URL.Path)
					w.Header().Set("Www-Authenticate", `Basic realm="peerswap"`)
					writeJSON(w, http.StatusUnauthorized, 16, "authentication failed")
					return
				}
			}

			// OK
			next.ServeHTTP(w, r)
		})
	}
}

func extractBasicFromHTTP(r *http.Request) (string, string, bool) {
	auth := r.Header.Get("Authorization")
	log.Debugf("[AUTH][HTTP] Authorization header prefix=%q", prefix(auth, 16))
	if auth == "" || !strings.HasPrefix(strings.ToLower(auth), "basic ") {
		return "", "", false
	}
	enc := strings.TrimSpace(auth[len("Basic "):])
	dec, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		log.Debugf("[AUTH][HTTP] base64 decode failed: %v", err)
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
	// Trust X-Forwarded-For first if present (left-most IP)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		ip := net.ParseIP(strings.TrimSpace(parts[0]))
		if ip != nil {
			log.Debugf("[AUTH][HTTP] XFF client ip=%s", ip)
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		log.Debugf("[AUTH][HTTP] split remote addr failed: %v", err)
		return nil
	}
	ip := net.ParseIP(host)
	log.Debugf("[AUTH][HTTP] remote ip=%s", ip)
	return ip
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
