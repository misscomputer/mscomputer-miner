// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package artifact

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const pullHotkey = "5Dk38RwXtHyqF8FvkyuGeE9ssUJzMtXqgrZ1bWhZsU37a9sE"

var pullBlobKey = "v1/blobs/sha256/" + strings.Repeat("a", 64)

type pullFixture struct {
	gateway, objects *httptest.Server
	store            PullStore
	gatewayCalls     atomic.Int32
	objectCalls      atomic.Int32
	gatewayStatus    []int
	objectStatus     []int
	body             []byte
	declaredLength   int
}

func newPullFixture(t *testing.T) *pullFixture {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	f := &pullFixture{body: []byte("verified elsewhere")}
	f.objects = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := int(f.objectCalls.Add(1)) - 1
		if r.Header.Get(PullHeaderSignature) != "" || r.Header.Get(PullHeaderHotkey) != "" {
			t.Errorf("gateway headers leaked to the object store")
		}
		if r.URL.Query().Get("X-Amz-Signature") != "sig" {
			t.Errorf("object hop lost the presigned query")
		}
		if call < len(f.objectStatus) && f.objectStatus[call] != http.StatusOK {
			w.WriteHeader(f.objectStatus[call])
			return
		}
		if f.declaredLength > 0 {
			w.Header().Set("Content-Length", strconv.Itoa(f.declaredLength))
		}
		_, _ = w.Write(f.body)
	}))
	f.gateway = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := int(f.gatewayCalls.Add(1)) - 1
		key := strings.TrimPrefix(r.URL.Path, "/v1/miner-artifacts/")
		signature, _ := hex.DecodeString(r.Header.Get(PullHeaderSignature))
		message := PullSigningMessage("finney", 24, r.Header.Get(PullHeaderHotkey), key, r.Header.Get(PullHeaderTimestamp), r.Header.Get(PullHeaderNonce))
		if r.Header.Get(PullHeaderHotkey) != pullHotkey || len(r.Header.Get(PullHeaderNonce)) != 32 || !ed25519.Verify(public, message, signature) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if call < len(f.gatewayStatus) && f.gatewayStatus[call] != http.StatusTemporaryRedirect {
			w.WriteHeader(f.gatewayStatus[call])
			return
		}
		w.Header().Set("Location", f.objects.URL+"/bucket/"+key+"?X-Amz-Signature=sig")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	t.Cleanup(f.gateway.Close)
	t.Cleanup(f.objects.Close)
	f.store = PullStore{
		BaseURL: f.gateway.URL + "/v1/miner-artifacts/", Network: "finney", NetUID: 24, Hotkey: pullHotkey,
		ServiceKey: private, Client: bothTrusted(f.gateway, f.objects), MaxAttempts: 3, LocationHostSuffix: ".0.0.1",
		RetryJitter: func(time.Duration, time.Duration) time.Duration { return time.Millisecond },
	}
	return f
}

func bothTrusted(servers ...*httptest.Server) *http.Client {
	pool := x509.NewCertPool()
	for _, server := range servers {
		pool.AddCert(server.Certificate())
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
}

func TestPullStoreSignsResolvesAndFetches(t *testing.T) {
	f := newPullFixture(t)
	got, err := f.store.GetBounded(context.Background(), pullBlobKey, 1<<20)
	if err != nil || !bytes.Equal(got, f.body) {
		t.Fatalf("GetBounded = %q, %v", got, err)
	}
	reader, err := f.store.OpenBounded(context.Background(), pullBlobKey, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	streamed, err := io.ReadAll(reader)
	reader.Close()
	if err != nil || !bytes.Equal(streamed, f.body) {
		t.Fatalf("OpenBounded = %q, %v", streamed, err)
	}
	if f.gatewayCalls.Load() != 2 || f.objectCalls.Load() != 2 {
		t.Fatalf("calls gateway=%d object=%d", f.gatewayCalls.Load(), f.objectCalls.Load())
	}
}

func TestPullStoreClassifiesNotFoundAndOversize(t *testing.T) {
	f := newPullFixture(t)
	f.gatewayStatus = []int{http.StatusNotFound}
	if _, err := f.store.Get(context.Background(), pullBlobKey); !IsNotFound(err) {
		t.Fatalf("missing object error = %v", err)
	}
	if f.gatewayCalls.Load() != 1 {
		t.Fatalf("not-found must not retry, calls=%d", f.gatewayCalls.Load())
	}
	f = newPullFixture(t)
	if _, err := f.store.GetBounded(context.Background(), pullBlobKey, 4); !IsOversize(err) {
		t.Fatalf("undeclared oversize error = %v", err)
	}
	f.declaredLength = len(f.body)
	if _, err := f.store.OpenBounded(context.Background(), pullBlobKey, 4); !IsOversize(err) {
		t.Fatalf("declared oversize error = %v", err)
	}
}

func TestPullStoreRetriesTransientAndExpiredURL(t *testing.T) {
	f := newPullFixture(t)
	f.gatewayStatus = []int{http.StatusServiceUnavailable, http.StatusTemporaryRedirect}
	f.objectStatus = []int{http.StatusForbidden}
	got, err := f.store.Get(context.Background(), pullBlobKey)
	if err != nil || !bytes.Equal(got, f.body) {
		t.Fatalf("Get = %q, %v", got, err)
	}
	if f.gatewayCalls.Load() != 3 {
		t.Fatalf("gateway calls = %d, want 3", f.gatewayCalls.Load())
	}
}

func TestPullStoreUnauthorizedIsReported(t *testing.T) {
	f := newPullFixture(t)
	_, other, _ := ed25519.GenerateKey(nil)
	f.store.ServiceKey = other
	_, err := f.store.Get(context.Background(), pullBlobKey)
	var s3Err *S3Error
	if !errors.As(err, &s3Err) || s3Err.Kind != S3ErrorAuthentication {
		t.Fatalf("error = %v", err)
	}
	if f.gatewayCalls.Load() != 3 || f.objectCalls.Load() != 0 {
		t.Fatalf("calls gateway=%d object=%d", f.gatewayCalls.Load(), f.objectCalls.Load())
	}
}

func TestPullStoreRejectsUnsafeConfigurationKeysAndRedirects(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(nil)
	for _, store := range []PullStore{
		{BaseURL: "http://gw/v1/miner-artifacts", Network: "finney", NetUID: 24, Hotkey: pullHotkey, ServiceKey: key},
		{BaseURL: "https://user:pw@gw/x", Network: "finney", NetUID: 24, Hotkey: pullHotkey, ServiceKey: key},
		{BaseURL: "https://gw/x", Network: "", NetUID: 24, Hotkey: pullHotkey, ServiceKey: key},
		{BaseURL: "https://gw/x", Network: "finney", Hotkey: pullHotkey},
		{BaseURL: "https://gw/x", Network: "finney", NetUID: 0, Hotkey: pullHotkey, ServiceKey: key},
	} {
		if store.Validate() == nil {
			t.Fatalf("Validate accepted %+v", store.BaseURL)
		}
	}
	f := newPullFixture(t)
	for _, bad := range []string{"v1/blobs/sha256/" + strings.Repeat("A", 64), "../v1/x", "v1/manifests/x.json"} {
		if _, err := f.store.Get(context.Background(), bad); err == nil {
			t.Fatalf("accepted key %q", bad)
		}
	}
	if f.gatewayCalls.Load() != 0 {
		t.Fatal("invalid keys reached the gateway")
	}
	if err := f.store.Put(context.Background(), pullBlobKey, nil, ""); err == nil {
		t.Fatal("pull store accepted a write")
	}
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://insecure.example/obj")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer plain.Close()
	f.gateway.Config.Handler = plain.Config.Handler
	var s3Err *S3Error
	if _, err := f.store.Get(context.Background(), pullBlobKey); !errors.As(err, &s3Err) || s3Err.Kind != S3ErrorUnexpected {
		t.Fatalf("http redirect error = %v", err)
	}
}

func TestPullStoreRejectsForeignRedirectHost(t *testing.T) {
	f := newPullFixture(t)
	f.store.LocationHostSuffix = ".objects.example"
	var s3Err *S3Error
	if _, err := f.store.Get(context.Background(), pullBlobKey); !errors.As(err, &s3Err) || s3Err.Kind != S3ErrorUnexpected {
		t.Fatalf("foreign host error = %v", err)
	}
	if f.objectCalls.Load() != 0 {
		t.Fatal("followed a redirect outside the object store")
	}
}

// Cross-language vector: a Python verifier checks the same bytes.
func TestPullSigningCrossLanguageVector(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	key := ed25519.NewKeyFromSeed(seed)
	if got := hex.EncodeToString(key.Public().(ed25519.PublicKey)); got != "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8" {
		t.Fatalf("public key %s", got)
	}
	message := PullSigningMessage("finney", 24, pullHotkey, pullBlobKey, "1800000000", strings.Repeat("0", 32))
	want := "e17120ade745c628fa6a42223a803e12ffd14a4bee1fb35a6f78ac8d889b4ba87de11031d29bba482c72bdb0cc183b7c82f949f23086fa61140a3695cc30dc03"
	if got := hex.EncodeToString(ed25519.Sign(key, message)); got != want {
		t.Fatalf("signature %s", got)
	}
}

func TestPullSigningMessageIsStable(t *testing.T) {
	got := string(PullSigningMessage("finney", 24, "hk", "v1/k", "1800000000", "00"))
	want := "mscomputer-miner-artifact-pull-v1\nfinney\n24\nhk\nv1/k\n1800000000\n00"
	if got != want {
		t.Fatalf("message = %q", got)
	}
}
