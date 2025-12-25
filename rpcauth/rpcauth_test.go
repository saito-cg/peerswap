package rpcauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// helper to compute HMAC-SHA256(key=salt, msg=password) in hex lowercase
func hmacHex(salt, password string) string {
	m := hmac.New(sha256.New, []byte(salt))
	m.Write([]byte(password))
	return hex.EncodeToString(m.Sum(nil))
}

func TestParseConfigValue_EmptyAndMultiple(t *testing.T) {
	// empty
	m := ParseConfigValue("")
	if len(m) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(m))
	}

	// multiple entries (one valid, one invalid)
	salt := "0123456789abcdef0123456789abcdef" // 16 bytes hex => 32 chars
	pass := "secret"
	hash := hmacHex(salt, pass)
	cfg := "alice:" + salt + "$" + hash + ",invalid-entry-without-colon"

	parsed := ParseConfigValue(cfg)
	if len(parsed) != 1 {
		t.Fatalf("expected 1 valid entry, got %d", len(parsed))
	}
	if e, ok := parsed["alice"]; !ok {
		t.Fatalf("expected user 'alice' to be present")
	} else {
		if e.Salt != salt {
			t.Fatalf("unexpected salt, got %s", e.Salt)
		}
		if e.Hash != hash {
			t.Fatalf("unexpected hash, got %s", e.Hash)
		}
	}
}

func TestParseRpcauthEntries_Invalids(t *testing.T) {
	entries := []string{
		"",                    // empty
		"no-dollar:abc",       // missing $
		"no-colon",            // missing :
		"user:abc$def",        // valid-ish
		"user2:abc$def$extra", // extra $, SplitN(2) makes second include "$extra"
	}
	res := ParseRpcauthEntries(entries)
	// Only "user:abc$def" and "user2:abc$def$extra" have both ":" and "$"
	if len(res) != 2 {
		t.Fatalf("expected 2 entries parsed, got %d", len(res))
	}
}

func TestVerifyRpcauth_SuccessAndFailure(t *testing.T) {
	user := "alice"
	salt := "0123456789abcdef0123456789abcdef"
	pass := "secret"
	hash := hmacHex(salt, pass)

	auths := map[string]Entry{
		user: {Salt: salt, Hash: hash},
	}

	// success
	if !VerifyRpcauth(user, pass, auths) {
		t.Fatalf("expected verification success")
	}
	// wrong password
	if VerifyRpcauth(user, "wrong", auths) {
		t.Fatalf("expected verification failure for wrong password")
	}
	// unknown user
	if VerifyRpcauth("bob", pass, auths) {
		t.Fatalf("expected verification failure for unknown user")
	}
}

func TestExtractBasicAuth(t *testing.T) {
	user := "alice"
	pass := "secret"
	cred := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))

	// Proper Basic header
	md := metadata.New(map[string]string{
		"authorization": "Basic " + cred,
	})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	u, p, ok := ExtractBasicAuth(ctx)
	if !ok {
		t.Fatalf("expected ok=true")
	}
	if u != user || p != pass {
		t.Fatalf("unexpected creds, got %q:%q", u, p)
	}

	// Wrong scheme (Bearer)
	md2 := metadata.New(map[string]string{
		"authorization": "Bearer " + cred,
	})
	ctx2 := metadata.NewIncomingContext(context.Background(), md2)
	_, _, ok2 := ExtractBasicAuth(ctx2)
	if ok2 {
		t.Fatalf("expected ok=false for Bearer scheme")
	}

	// Missing header
	ctx3 := context.Background()
	_, _, ok3 := ExtractBasicAuth(ctx3)
	if ok3 {
		t.Fatalf("expected ok=false for missing metadata")
	}
}

func TestNewUnaryInterceptor(t *testing.T) {
	user := "alice"
	salt := "0123456789abcdef0123456789abcdef"
	pass := "secret"
	hash := hmacHex(salt, pass)
	auths := map[string]Entry{user: {Salt: salt, Hash: hash}}

	interceptor := NewUnaryInterceptor(auths)

	// Happy path: valid Basic header
	cred := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
	md := metadata.New(map[string]string{"authorization": "Basic " + cred})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	called := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		called = true
		return "ok", nil
	}
	info := &grpc.UnaryServerInfo{FullMethod: "/peerswap.PeerSwap/ListPeers"}
	resp, err := interceptor(ctx, nil, info, handler)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatalf("handler was not called")
	}
	if resp.(string) != "ok" {
		t.Fatalf("unexpected handler response: %v", resp)
	}

	// Failure: wrong password
	credWrong := base64.StdEncoding.EncodeToString([]byte(user + ":wrong"))
	mdWrong := metadata.New(map[string]string{"authorization": "Basic " + credWrong})
	ctxWrong := metadata.NewIncomingContext(context.Background(), mdWrong)
	_, err = interceptor(ctxWrong, nil, info, handler)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}
}

func TestParseAllowCIDRs_AndIPAllowed(t *testing.T) {
	allow := []string{
		"127.0.0.1",     // IPv4 single host
		"10.0.0.0/8",    // IPv4 cidr
		"::1",           // IPv6 loopback
		"2001:db8::/32", // IPv6 documentation prefix (narrow)
	}
	nets := ParseAllowCIDRs(allow)
	if len(nets) != 4 {
		t.Fatalf("expected 4 networks, got %d", len(nets))
	}

	tests := []struct {
		ip      string
		allowed bool
	}{
		{"127.0.0.1", true},
		{"127.0.0.2", false},
		{"10.23.45.67", true},
		{"11.0.0.1", false},
		{"::1", true},
		{"2001:db8::1234", true},
		{"2001:db9::1", false},
	}
	for _, tc := range tests {
		ip := net.ParseIP(tc.ip)
		got := ipAllowed(ip, nets)
		if got != tc.allowed {
			t.Fatalf("ipAllowed(%s)=%v, want %v", tc.ip, got, tc.allowed)
		}
	}
}

func TestNewHTTPAuthMiddleware(t *testing.T) {
	// Base handler that returns 200 OK with a body
	base := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	// 1) No auth, no allowlist -> should pass
	mw := NewHTTPAuthMiddleware(map[string]Entry{}, []*net.IPNet{})(base)
	srv := httptest.NewServer(mw)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/peers", nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("http request failed: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	// 2) Allowlist only (deny)
	only10 := ParseAllowCIDRs([]string{"10.0.0.0/8"})
	mw2 := NewHTTPAuthMiddleware(map[string]Entry{}, only10)(base)
	srv2 := httptest.NewServer(mw2)
	defer srv2.Close()

	req2, _ := http.NewRequest(http.MethodGet, srv2.URL+"/v1/peers", nil)
	res2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("http request failed: %v", err)
	}
	if res2.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", res2.StatusCode)
	}

	// 3) Allowlist include localhost -> pass
	allowLocal := ParseAllowCIDRs([]string{"127.0.0.1", "::1"})
	mw3 := NewHTTPAuthMiddleware(map[string]Entry{}, allowLocal)(base)
	srv3 := httptest.NewServer(mw3)
	defer srv3.Close()

	req3, _ := http.NewRequest(http.MethodGet, srv3.URL+"/v1/peers", nil)
	res3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatalf("http request failed: %v", err)
	}
	if res3.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res3.StatusCode)
	}

	// 4) Auth required: missing header -> 401
	user := "alice"
	salt := "0123456789abcdef0123456789abcdef"
	pass := "secret"
	hash := hmacHex(salt, pass)
	authMap := map[string]Entry{user: {Salt: salt, Hash: hash}}

	mw4 := NewHTTPAuthMiddleware(authMap, allowLocal)(base)
	srv4 := httptest.NewServer(mw4)
	defer srv4.Close()

	req4, _ := http.NewRequest(http.MethodGet, srv4.URL+"/v1/peers", nil)
	res4, err := http.DefaultClient.Do(req4)
	if err != nil {
		t.Fatalf("http request failed: %v", err)
	}
	if res4.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", res4.StatusCode)
	}
	if ah := res4.Header.Get("Www-Authenticate"); ah == "" {
		t.Fatalf("expected Www-Authenticate header to be set")
	}

	// 5) Auth required: correct Basic header -> 200
	cred := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
	req5, _ := http.NewRequest(http.MethodGet, srv4.URL+"/v1/peers", nil)
	req5.Header.Set("Authorization", "Basic "+cred)
	res5, err := http.DefaultClient.Do(req5)
	if err != nil {
		t.Fatalf("http request failed: %v", err)
	}
	if res5.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res5.StatusCode)
	}

	// 6) Auth required: wrong password -> 401
	credWrong := base64.StdEncoding.EncodeToString([]byte(user + ":wrong"))
	req6, _ := http.NewRequest(http.MethodGet, srv4.URL+"/v1/peers", nil)
	req6.Header.Set("Authorization", "Basic "+credWrong)
	res6, err := http.DefaultClient.Do(req6)
	if err != nil {
		t.Fatalf("http request failed: %v", err)
	}
	if res6.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", res6.StatusCode)
	}
}
