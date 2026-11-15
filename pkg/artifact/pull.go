// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package artifact

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// PullProtocol names the signed request format of the subnet operator's
// miner artifact pull gateway.
const PullProtocol = "mscomputer-miner-artifact-pull-v1"

// Pull gateway request headers.
const (
	PullHeaderHotkey    = "X-MS-Miner-Hotkey"
	PullHeaderTimestamp = "X-MS-Miner-Timestamp"
	PullHeaderNonce     = "X-MS-Miner-Nonce"
	PullHeaderSignature = "X-MS-Miner-Signature"
)

var pullKeyPattern = regexp.MustCompile(`^v1/(?:blobs/sha256/[0-9a-f]{64}|manifests/[0-9a-f]{64}\.json|static-sites/[0-9a-f]{64}\.json)$`)

// PullStore reads artifacts through the operator's pull gateway instead of
// holding object-store credentials. Each read is signed with the miner's
// Ed25519 service key; the gateway answers with a short-lived presigned URL
// for that one object, which PullStore then fetches. It is read-only.
//
// Integrity does not depend on the gateway or the object store: every
// consumer verifies fetched bytes against the digest in its signed ticket.
type PullStore struct {
	// BaseURL is the gateway route, e.g. https://api.ms.computer/v1/miner-artifacts.
	BaseURL    string
	Network    string
	NetUID     uint16
	Hotkey     string
	ServiceKey ed25519.PrivateKey
	Client     *http.Client
	Now        func() time.Time
	// RequestTimeout bounds obtaining response headers of each hop.
	RequestTimeout time.Duration
	MaxAttempts    int
	RetryBaseDelay time.Duration
	RetryJitter    func(minimum, maximum time.Duration) time.Duration
	MaxObjectBytes int64
	// LocationHostSuffix, when set, restricts the hosts the gateway may
	// redirect to (a host equal to it without the leading dot, or ending in
	// it). Empty accepts any https host; bytes are digest-verified either way.
	LocationHostSuffix string
}

// PullSigningMessage returns the bytes a miner signs for one gateway read.
func PullSigningMessage(network string, netuid uint16, hotkey, key, timestamp, nonce string) []byte {
	return []byte(strings.Join([]string{PullProtocol, network, strconv.FormatUint(uint64(netuid), 10), hotkey, key, timestamp, nonce}, "\n"))
}

// Validate checks local configuration without a network request.
func (s PullStore) Validate() error {
	_, err := s.settings()
	return err
}

func (s PullStore) settings() (s3RequestSettings, error) {
	base, err := url.Parse(s.BaseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return s3RequestSettings{}, errors.New("artifact pull URL must be an https URL without credentials, query or fragment")
	}
	if strings.TrimSpace(s.Network) == "" || s.Hotkey == "" || s.NetUID == 0 {
		return s3RequestSettings{}, errors.New("artifact pull requires network and hotkey")
	}
	if len(s.ServiceKey) != ed25519.PrivateKeySize {
		return s3RequestSettings{}, errors.New("artifact pull requires the Ed25519 service key")
	}
	// Shared bounds and defaults of the artifact HTTP stores.
	return newRequestSettings(s.RequestTimeout, s.MaxAttempts, s.RetryBaseDelay, s.RetryJitter, s.MaxObjectBytes)
}

func (s PullStore) Put(context.Context, string, []byte, string) error {
	return errors.New("artifact pull store is read-only")
}

func (s PullStore) Get(ctx context.Context, key string) ([]byte, error) {
	return s.getBounded(ctx, key, 0)
}

func (s PullStore) GetBounded(ctx context.Context, key string, maximum int64) ([]byte, error) {
	if maximum < 1 {
		return nil, errors.New("artifact response limit must be positive")
	}
	return s.getBounded(ctx, key, maximum)
}

func (s PullStore) getBounded(ctx context.Context, key string, maximum int64) ([]byte, error) {
	settings, err := s.settings()
	if err != nil {
		return nil, err
	}
	if maximum == 0 || maximum > settings.maxObjectBytes {
		maximum = settings.maxObjectBytes
	}
	reader, err := s.OpenBounded(ctx, key, maximum)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	body, err := readBounded(reader, maximum)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if errors.Is(err, errObjectTooLarge) {
			return nil, &S3Error{Operation: "get", Key: key, Kind: S3ErrorResponseTooBig}
		}
		return nil, &S3Error{Operation: "get", Key: key, Kind: S3ErrorTransport, Retryable: true}
	}
	return body, nil
}

// OpenBounded streams one object. Retries cover the gateway hop and the
// object hop up to the start of the body.
func (s PullStore) OpenBounded(ctx context.Context, key string, maximum int64) (io.ReadCloser, error) {
	if ctx == nil {
		return nil, errors.New("artifact pull context is required")
	}
	if maximum < 1 {
		return nil, errors.New("artifact response limit must be positive")
	}
	settings, err := s.settings()
	if err != nil {
		return nil, err
	}
	if !pullKeyPattern.MatchString(key) {
		return nil, fmt.Errorf("invalid artifact key %q", safeErrorKey(key))
	}
	if maximum > settings.maxObjectBytes {
		maximum = settings.maxObjectBytes
	}
	client := s.httpClient()
	for attempt := 1; attempt <= settings.attempts; attempt++ {
		reader, classified, retryAfter := s.attempt(ctx, client, settings, key, maximum)
		if classified == nil {
			return reader, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !classified.Retryable || attempt == settings.attempts {
			return nil, classified
		}
		if err := waitForRetry(ctx, retryDelay(settings.retryBaseDelay, attempt, retryAfter, settings.retryJitter)); err != nil {
			return nil, err
		}
	}
	panic("unreachable artifact pull retry loop")
}

func (s PullStore) attempt(ctx context.Context, client *http.Client, settings s3RequestSettings, key string, maximum int64) (io.ReadCloser, *S3Error, string) {
	location, classified, retryAfter := s.resolve(ctx, client, settings, key)
	if classified != nil {
		return nil, classified, retryAfter
	}
	attemptCtx, cancel := context.WithCancel(ctx)
	headerTimer := time.AfterFunc(settings.timeout, cancel)
	req, err := http.NewRequestWithContext(attemptCtx, http.MethodGet, location, nil)
	if err != nil {
		headerTimer.Stop()
		cancel()
		return nil, &S3Error{Operation: "get", Key: key, Kind: S3ErrorUnexpected}, ""
	}
	resp, err := client.Do(req)
	timedOut := !headerTimer.Stop()
	if err == nil && timedOut {
		_ = resp.Body.Close()
		err = context.DeadlineExceeded
	}
	if err != nil {
		cancel()
		kind := S3ErrorTransport
		if timedOut || errors.Is(err, context.DeadlineExceeded) {
			kind = S3ErrorTimeout
		}
		return nil, &S3Error{Operation: "get", Key: key, Kind: kind, Retryable: true}, ""
	}
	if resp.StatusCode/100 == 2 {
		if resp.ContentLength > maximum {
			_ = resp.Body.Close()
			cancel()
			return nil, &S3Error{Operation: "get", Key: key, Kind: S3ErrorResponseTooBig}, ""
		}
		return &boundedReadCloser{reader: resp.Body, closer: cancelCloser{body: resp.Body, cancel: cancel}, remaining: maximum}, nil, ""
	}
	serviceCode, truncated := readS3Error(resp.Body)
	retryAfter = resp.Header.Get("Retry-After")
	_ = resp.Body.Close()
	cancel()
	classified = classifyS3Status("get", key, resp.StatusCode, serviceCode, truncated)
	if resp.StatusCode == http.StatusForbidden {
		// An expired presigned URL (slow hop or clock skew) is worth one
		// more gateway round trip.
		classified.Retryable = true
	}
	return nil, classified, retryAfter
}

// resolve asks the gateway for a presigned object URL.
func (s PullStore) resolve(ctx context.Context, client *http.Client, settings s3RequestSettings, key string) (string, *S3Error, string) {
	attemptCtx, cancel := context.WithTimeout(ctx, settings.timeout)
	defer cancel()
	target := strings.TrimRight(s.BaseURL, "/") + "/" + key
	req, err := http.NewRequestWithContext(attemptCtx, http.MethodGet, target, nil)
	if err != nil {
		return "", &S3Error{Operation: "resolve", Key: key, Kind: S3ErrorUnexpected}, ""
	}
	var nonceBytes [16]byte
	if _, err := rand.Read(nonceBytes[:]); err != nil {
		return "", &S3Error{Operation: "resolve", Key: key, Kind: S3ErrorUnexpected}, ""
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	timestamp := strconv.FormatInt(now().Unix(), 10)
	nonce := hex.EncodeToString(nonceBytes[:])
	signature := ed25519.Sign(s.ServiceKey, PullSigningMessage(s.Network, s.NetUID, s.Hotkey, key, timestamp, nonce))
	req.Header.Set(PullHeaderHotkey, s.Hotkey)
	req.Header.Set(PullHeaderTimestamp, timestamp)
	req.Header.Set(PullHeaderNonce, nonce)
	req.Header.Set(PullHeaderSignature, hex.EncodeToString(signature))
	resp, err := client.Do(req)
	if err != nil {
		kind := S3ErrorTransport
		if errors.Is(err, context.DeadlineExceeded) {
			kind = S3ErrorTimeout
		}
		return "", &S3Error{Operation: "resolve", Key: key, Kind: kind, Retryable: true}, ""
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxS3ErrorBodyBytes))
	_ = resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusTemporaryRedirect, http.StatusFound, http.StatusSeeOther:
	default:
		classified := classifyS3Status("resolve", key, resp.StatusCode, "", false)
		if resp.StatusCode == http.StatusUnauthorized {
			// Stale timestamp or a binding refresh in flight: retry signs anew.
			classified.Retryable = true
		}
		return "", classified, resp.Header.Get("Retry-After")
	}
	location, err := url.Parse(resp.Header.Get("Location"))
	suffix := s.LocationHostSuffix
	if err != nil || location.Scheme != "https" || location.Host == "" || location.User != nil || location.Fragment != "" ||
		(suffix != "" && location.Hostname() != strings.TrimPrefix(suffix, ".") && !strings.HasSuffix(location.Hostname(), suffix)) {
		return "", &S3Error{Operation: "resolve", Key: key, Kind: S3ErrorUnexpected, StatusCode: resp.StatusCode}, ""
	}
	return location.String(), nil, ""
}

// httpClient never follows redirects itself, so gateway headers are never
// forwarded to the object store and each hop is checked explicitly.
func (s PullStore) httpClient() *http.Client {
	base := s.Client
	if base == nil {
		base = defaultS3HTTPClient
	}
	copy := *base
	copy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	return &copy
}
