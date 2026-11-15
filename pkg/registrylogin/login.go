// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

// Package registrylogin obtains short-lived image registry credentials from
// the subnet operator's image mirror by signing a login with the miner's
// Ed25519 service key (the key the hotkey bound at registration).
//
// Two scopes exist. A pool credential admits the mirror's public images and
// is cached until shortly before it expires. A lease credential admits one
// private image for one lease: the login names the lease and its signature,
// and the operator issues it only for a live lease assigned to this miner.
// Lease credentials are never cached.
//
// The credential is handed to the container engine per pull (X-Registry-Auth)
// and never written to disk.
package registrylogin

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Protocol names the signed login format.
const Protocol = "mscomputer-image-mirror-login-v1"

// Login request headers.
const (
	HeaderHotkey         = "X-MS-Miner-Hotkey"
	HeaderTimestamp      = "X-MS-Miner-Timestamp"
	HeaderNonce          = "X-MS-Miner-Nonce"
	HeaderSignature      = "X-MS-Miner-Signature"
	HeaderScope          = "X-MS-Mirror-Scope"
	HeaderLeaseID        = "X-MS-Lease-Id"
	HeaderLeaseSignature = "X-MS-Lease-Signature"
)

// Scopes.
const (
	ScopePool  = "pool"
	ScopeLease = "lease"
)

const (
	// refreshBefore renews a cached pool credential this long before it
	// expires, so a pull never starts with one about to lapse.
	refreshBefore = 5 * time.Minute
	// failureBackoff suppresses repeated pool logins after a failure.
	failureBackoff = 30 * time.Second
	maxAnswerBytes = 16 << 10
	defaultTimeout = 10 * time.Second
)

var (
	leaseIDPattern   = regexp.MustCompile(`^sbx-[0-9a-f]{32}$`)
	signaturePattern = regexp.MustCompile(`^[0-9a-f]{128}$`)
	builtPattern     = regexp.MustCompile(`^built/[0-9a-f]{32}/msb-[0-9a-f]{64}$`)
)

// Credential is one registry login: HTTP Basic for the registry host.
type Credential struct {
	Username, Password string
	// ServerAddress is the registry host the credential is for.
	ServerAddress string
	ExpiresAt     time.Time
	Scope         string
}

// RegistryAuth is the engine's X-Registry-Auth value for c: base64url of
// the JSON auth configuration.
func (c Credential) RegistryAuth() string {
	raw, _ := json.Marshal(struct {
		Username      string `json:"username"`
		Password      string `json:"password"`
		ServerAddress string `json:"serveraddress"`
	}{c.Username, c.Password, c.ServerAddress})
	return base64.URLEncoding.EncodeToString(raw)
}

// SigningMessage returns the bytes a miner signs for one login. leaseID and
// leaseSignature are empty for the pool scope.
func SigningMessage(network string, netuid uint16, hotkey, scope, leaseID, leaseSignature, timestamp, nonce string) []byte {
	return []byte(strings.Join([]string{Protocol, network, strconv.FormatUint(uint64(netuid), 10), hotkey, scope, leaseID, leaseSignature, timestamp, nonce}, "\n"))
}

// Client logs in to one mirror.
type Client struct {
	// URL is the login route, e.g. https://mirror.ms.computer/v1/mirror-login.
	// Credentials are only ever offered for images on its host.
	URL        string
	Network    string
	NetUID     uint16
	Hotkey     string
	ServiceKey ed25519.PrivateKey
	HTTP       *http.Client
	Now        func() time.Time

	mu         sync.Mutex
	pool       *Credential
	poolFailed time.Time
}

// Validate checks local configuration without a network request.
func (c *Client) Validate() error {
	_, err := c.host()
	if err != nil {
		return err
	}
	if strings.TrimSpace(c.Network) == "" || c.NetUID == 0 || c.Hotkey == "" {
		return errors.New("registry login requires network, netuid and hotkey")
	}
	if len(c.ServiceKey) != ed25519.PrivateKeySize {
		return errors.New("registry login requires the Ed25519 service key")
	}
	return nil
}

func (c *Client) host() (string, error) {
	u, err := url.Parse(c.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Port() != "" {
		return "", errors.New("registry login URL must be an https URL without port, credentials, query or fragment")
	}
	return strings.ToLower(u.Hostname()), nil
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Lease identifies the lease a private pull serves.
type Lease struct {
	SandboxID, Signature string
}

// CredentialFor returns the credential for pulling repository (an engine
// repository name, host first, without tag or digest) under lease, and
// false when the repository is not on the mirror (no credential is sent to
// any other registry).
func (c *Client) CredentialFor(ctx context.Context, repository string, lease Lease) (Credential, bool, error) {
	host, err := c.host()
	if err != nil {
		return Credential{}, false, err
	}
	registry, path, found := strings.Cut(repository, "/")
	if !found || strings.ToLower(registry) != host {
		return Credential{}, false, nil
	}
	if builtPattern.MatchString(path) {
		credential, err := c.login(ctx, ScopeLease, lease)
		return credential, err == nil, err
	}
	credential, err := c.poolCredential(ctx)
	return credential, err == nil, err
}

func (c *Client) poolCredential(ctx context.Context) (Credential, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.pool != nil && now.Add(refreshBefore).Before(c.pool.ExpiresAt) {
		return *c.pool, nil
	}
	if !c.poolFailed.IsZero() && now.Sub(c.poolFailed) < failureBackoff {
		return Credential{}, errors.New("registry login failed recently")
	}
	credential, err := c.login(ctx, ScopePool, Lease{})
	if err != nil {
		c.pool, c.poolFailed = nil, now
		return Credential{}, err
	}
	c.pool, c.poolFailed = &credential, time.Time{}
	return credential, nil
}

// StatusError is a refused login.
type StatusError struct{ Status int }

func (e *StatusError) Error() string {
	return fmt.Sprintf("registry login refused: HTTP %d", e.Status)
}

func (c *Client) login(ctx context.Context, scope string, lease Lease) (Credential, error) {
	if err := c.Validate(); err != nil {
		return Credential{}, err
	}
	host, _ := c.host()
	if scope == ScopeLease && (!leaseIDPattern.MatchString(lease.SandboxID) || !signaturePattern.MatchString(lease.Signature)) {
		return Credential{}, errors.New("a private image pull needs its signed lease")
	}
	var nonceBytes [16]byte
	if _, err := rand.Read(nonceBytes[:]); err != nil {
		return Credential{}, err
	}
	nonce := hex.EncodeToString(nonceBytes[:])
	timestamp := strconv.FormatInt(c.now().Unix(), 10)
	signature := ed25519.Sign(c.ServiceKey, SigningMessage(c.Network, c.NetUID, c.Hotkey, scope, lease.SandboxID, lease.Signature, timestamp, nonce))
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, nil)
	if err != nil {
		return Credential{}, err
	}
	req.Header.Set(HeaderHotkey, c.Hotkey)
	req.Header.Set(HeaderTimestamp, timestamp)
	req.Header.Set(HeaderNonce, nonce)
	req.Header.Set(HeaderSignature, hex.EncodeToString(signature))
	req.Header.Set(HeaderScope, scope)
	if scope == ScopeLease {
		req.Header.Set(HeaderLeaseID, lease.SandboxID)
		req.Header.Set(HeaderLeaseSignature, lease.Signature)
	}
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: defaultTimeout}
	}
	// Never follow a redirect: the signed request is for this route only.
	noRedirect := *client
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noRedirect.Do(req)
	if err != nil {
		return Credential{}, fmt.Errorf("registry login: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswerBytes))
	if err != nil {
		return Credential{}, fmt.Errorf("registry login: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return Credential{}, &StatusError{Status: resp.StatusCode}
	}
	var answer struct {
		Username  string `json:"username"`
		Password  string `json:"password"`
		ExpiresAt int64  `json:"expires_at"`
		Scope     string `json:"scope"`
	}
	if err := json.Unmarshal(raw, &answer); err != nil {
		return Credential{}, errors.New("registry login: undecodable answer")
	}
	expires := time.Unix(answer.ExpiresAt, 0)
	if answer.Username != c.Hotkey || answer.Password == "" || len(answer.Password) > 512 || !expires.After(c.now()) {
		return Credential{}, errors.New("registry login: unusable answer")
	}
	return Credential{Username: answer.Username, Password: answer.Password, ServerAddress: host, ExpiresAt: expires, Scope: answer.Scope}, nil
}
