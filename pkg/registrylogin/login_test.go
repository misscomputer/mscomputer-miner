// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package registrylogin

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	hotkey  = "5Dk38RwXtHyqF8FvkyuGeE9ssUJzMtXqgrZ1bWhZsU37a9sE"
	leaseID = "sbx-11111111111111111111111111111111"
	built   = "built/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/msb-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

var leaseSignature = strings.Repeat("ab", 64)

func seedKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	return ed25519.NewKeyFromSeed(seed)
}

// The operator's suite (Python) checks the same vectors.
func TestSigningMessageMatchesTheSharedVectors(t *testing.T) {
	for _, tc := range []struct{ scope, lease, leaseSig, want string }{
		{ScopePool, "", "", "2939622968c044b5177db290a66dbd764d95da0736707e2f973a0076ea05cd184476f6bc5fbc583783597e02a036363b8f0885930d909d3656c0437d6580270b"},
		{ScopeLease, leaseID, leaseSignature, "74d08404393adc64ee57d77116a70cc65a36011eccf5f8b7f77bfc22a9c2d5e571c9bbcc83a1da84a3cdade76bf02387402c11e12109552d0d4018022dad960e"},
	} {
		got := hex.EncodeToString(ed25519.Sign(seedKey(), SigningMessage("finney", 24, hotkey, tc.scope, tc.lease, tc.leaseSig, "1800000000", "00000000000000000000000000000001")))
		if got != tc.want {
			t.Fatalf("%s vector: got %s", tc.scope, got)
		}
	}
}

type fakeMirror struct {
	server *httptest.Server
	calls  atomic.Int32
	status int
	expiry time.Duration
	seen   []http.Header
}

func newMirror(t *testing.T) *fakeMirror {
	m := &fakeMirror{status: http.StatusOK, expiry: time.Hour}
	m.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.calls.Add(1)
		m.seen = append(m.seen, r.Header.Clone())
		if r.Method != http.MethodPost || r.URL.Path != "/v1/mirror-login" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		message := SigningMessage("finney", 24, r.Header.Get(HeaderHotkey), r.Header.Get(HeaderScope), r.Header.Get(HeaderLeaseID), r.Header.Get(HeaderLeaseSignature), r.Header.Get(HeaderTimestamp), r.Header.Get(HeaderNonce))
		signature, _ := hex.DecodeString(r.Header.Get(HeaderSignature))
		if !ed25519.Verify(seedKey().Public().(ed25519.PublicKey), message, signature) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if m.status != http.StatusOK {
			w.WriteHeader(m.status)
			return
		}
		scope := "pool"
		if r.Header.Get(HeaderScope) == ScopeLease {
			scope = built
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"username": hotkey, "password": "v2.x." + scope, "expires_at": time.Now().Add(m.expiry).Unix(), "scope": scope})
	}))
	t.Cleanup(m.server.Close)
	return m
}

func (m *fakeMirror) client(t *testing.T) *Client {
	// The test server listens on 127.0.0.1:<port>; route the mirror host there.
	addr := strings.TrimPrefix(m.server.URL, "https://")
	transport := m.server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.ServerName = "example.com" // the test certificate's name
	dial := (&net.Dialer{}).DialContext
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dial(ctx, network, addr)
	}
	return &Client{
		URL: "https://mirror.example/v1/mirror-login", Network: "finney", NetUID: 24, Hotkey: hotkey,
		ServiceKey: seedKey(), HTTP: &http.Client{Transport: transport},
	}
}

func TestPoolCredentialIsCachedAndOnlyOfferedToTheMirrorHost(t *testing.T) {
	m := newMirror(t)
	c := m.client(t)
	for range 3 {
		credential, ok, err := c.CredentialFor(context.Background(), "mirror.example/docker.io/library/python", Lease{})
		if err != nil || !ok || credential.Scope != "pool" || credential.ServerAddress != "mirror.example" {
			t.Fatalf("pool credential: %+v %v %v", credential, ok, err)
		}
	}
	if m.calls.Load() != 1 {
		t.Fatalf("pool logins = %d, want 1 (cached)", m.calls.Load())
	}
	for _, repository := range []string{"ghcr.io/org/app", "docker.io/library/python", "mirror.example.evil/x/y", "evil/mirror.example/x"} {
		if _, ok, err := c.CredentialFor(context.Background(), repository, Lease{}); ok || err != nil {
			t.Fatalf("%s got a credential (%v)", repository, err)
		}
	}
	if m.calls.Load() != 1 {
		t.Fatal("a non-mirror repository caused a login")
	}
	if m.seen[0].Get(HeaderLeaseID) != "" || m.seen[0].Get(HeaderScope) != ScopePool {
		t.Fatalf("pool login headers: %v", m.seen[0])
	}
}

func TestPoolCredentialIsRenewedBeforeItExpires(t *testing.T) {
	m := newMirror(t)
	m.expiry = 4 * time.Minute // inside refreshBefore: never reused
	c := m.client(t)
	for range 2 {
		if _, _, err := c.CredentialFor(context.Background(), "mirror.example/docker.io/library/python", Lease{}); err != nil {
			t.Fatal(err)
		}
	}
	if m.calls.Load() != 2 {
		t.Fatalf("logins = %d, want 2", m.calls.Load())
	}
}

func TestPrivateImagesGetAFreshLeaseCredentialEachTime(t *testing.T) {
	m := newMirror(t)
	c := m.client(t)
	lease := Lease{SandboxID: leaseID, Signature: leaseSignature}
	for range 2 {
		credential, ok, err := c.CredentialFor(context.Background(), "mirror.example/"+built, lease)
		if err != nil || !ok || credential.Scope != built {
			t.Fatalf("lease credential: %+v %v %v", credential, ok, err)
		}
	}
	if m.calls.Load() != 2 {
		t.Fatalf("lease logins = %d, want 2 (never cached)", m.calls.Load())
	}
	h := m.seen[0]
	if h.Get(HeaderScope) != ScopeLease || h.Get(HeaderLeaseID) != leaseID || h.Get(HeaderLeaseSignature) != leaseSignature {
		t.Fatalf("lease login headers: %v", h)
	}
	if _, ok, err := c.CredentialFor(context.Background(), "mirror.example/"+built, Lease{}); ok || err == nil {
		t.Fatal("a private pull without its lease logged in")
	}
}

func TestRefusedLoginIsAnErrorAndBacksOff(t *testing.T) {
	m := newMirror(t)
	m.status = http.StatusForbidden
	c := m.client(t)
	_, ok, err := c.CredentialFor(context.Background(), "mirror.example/docker.io/library/python", Lease{})
	var status *StatusError
	if ok || !errors.As(err, &status) || status.Status != http.StatusForbidden {
		t.Fatalf("refused login: %v %v", ok, err)
	}
	if _, _, err := c.CredentialFor(context.Background(), "mirror.example/docker.io/library/python", Lease{}); err == nil {
		t.Fatal("no backoff error")
	}
	if m.calls.Load() != 1 {
		t.Fatalf("logins during backoff = %d, want 1", m.calls.Load())
	}
}

func TestRegistryAuthIsTheEngineAuthConfig(t *testing.T) {
	raw, err := base64.URLEncoding.DecodeString(Credential{Username: hotkey, Password: "p", ServerAddress: "mirror.example"}.RegistryAuth())
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]string
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Fatal(err)
	}
	if config["username"] != hotkey || config["password"] != "p" || config["serveraddress"] != "mirror.example" {
		t.Fatalf("auth config: %v", config)
	}
}

func TestValidateRefusesUnsafeURLs(t *testing.T) {
	for _, u := range []string{"http://mirror.example/v1/mirror-login", "https://u:p@mirror.example/x", "https://mirror.example:8443/x", "https://mirror.example/x?y=1", ""} {
		c := &Client{URL: u, Network: "finney", NetUID: 24, Hotkey: hotkey, ServiceKey: seedKey()}
		if c.Validate() == nil {
			t.Fatalf("%q accepted", u)
		}
	}
}
