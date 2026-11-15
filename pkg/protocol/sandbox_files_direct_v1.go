// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package protocol

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"time"

	"github.com/misscomputer/mscomputer-miner/pkg/organic"
	"github.com/misscomputer/mscomputer-miner/pkg/sandbox"
)

// Direct file transfer documents. The validator runtime signs a grant with
// the same Ed25519 service key that signed the lease, so a miner verifies it
// against the key pinned in that lease and nothing new is distributed. The
// tenant presents the grant straight to the miner's direct-files endpoint and
// streams the bytes; the miner answers with a receipt signed by its service
// key, which the broker checks against the grant it asked for.
const (
	SandboxFileGrantSchema          = organic.SchemaPrefix + "sandbox-file-grant"
	SandboxFileReceiptSchema        = organic.SchemaPrefix + "sandbox-file-receipt"
	SandboxFilesDirectSchemaVersion = 1

	SandboxFileGrantSigningDomain   = SandboxFileGrantSchema + "/v1/ed25519"
	SandboxFileReceiptSigningDomain = SandboxFileReceiptSchema + "/v1/ed25519"

	// DirectFileUpload and DirectFileDownload are the two grant operations.
	DirectFileUpload   = "upload"
	DirectFileDownload = "download"

	// MaxFileGrantWindow bounds expires_at - issued_at of a grant.
	MaxFileGrantWindow = 15 * time.Minute
	// MaxDirectFileBytes bounds one granted part. It equals the largest
	// file the sandbox file area accepts.
	MaxDirectFileBytes = sandbox.MaxFileWriteBytes
)

// SandboxFileGrantV1 authorizes exactly one transfer of at most max_bytes at
// offset of path in the sandbox lease it names. account is an opaque tenant
// digest the broker chose; nonce makes the grant single-use.
type SandboxFileGrantV1 struct {
	Account        string                 `json:"account"`
	ExpectedSHA256 *string                `json:"expected_sha256"`
	ExpiresAt      string                 `json:"expires_at"`
	Generation     uint64                 `json:"generation"`
	IssuedAt       string                 `json:"issued_at"`
	LeaseDigest    string                 `json:"lease_digest"`
	LeaseID        string                 `json:"lease_id"`
	MaxBytes       uint64                 `json:"max_bytes"`
	MinerID        string                 `json:"miner_id"`
	Mode           *uint32                `json:"mode"`
	Nonce          string                 `json:"nonce"`
	Offset         uint64                 `json:"offset"`
	Op             string                 `json:"op"`
	Path           string                 `json:"path"`
	SandboxID      string                 `json:"sandbox_id"`
	Schema         string                 `json:"schema"`
	SchemaVersion  int                    `json:"schema_version"`
	Signature      string                 `json:"signature"`
	Subnet         *StaticSubnetBindingV1 `json:"subnet"`
}

// SandboxFileReceiptV1 is the miner's signed account of one completed
// transfer: bytes moved, their SHA-256 and the resulting file size.
type SandboxFileReceiptV1 struct {
	Account       string                 `json:"account"`
	Bytes         uint64                 `json:"bytes"`
	CompletedAt   string                 `json:"completed_at"`
	FileSize      uint64                 `json:"file_size"`
	Generation    uint64                 `json:"generation"`
	GrantDigest   string                 `json:"grant_digest"`
	LeaseID       string                 `json:"lease_id"`
	MinerID       string                 `json:"miner_id"`
	Nonce         string                 `json:"nonce"`
	Offset        uint64                 `json:"offset"`
	Op            string                 `json:"op"`
	Path          string                 `json:"path"`
	SandboxID     string                 `json:"sandbox_id"`
	Schema        string                 `json:"schema"`
	SchemaVersion int                    `json:"schema_version"`
	SHA256        string                 `json:"sha256"`
	Signature     string                 `json:"signature"`
	Subnet        *StaticSubnetBindingV1 `json:"subnet"`
}

// Validate checks a received grant; the signature must be present.
func (g SandboxFileGrantV1) Validate() error {
	if err := g.validateUnsigned(); err != nil {
		return err
	}
	return validateSandboxSignature(g.Signature, "file grant")
}

func (g SandboxFileGrantV1) validateUnsigned() error {
	if g.Schema != SandboxFileGrantSchema || g.SchemaVersion != SandboxFilesDirectSchemaVersion {
		return errors.New("sandbox file grant schema is invalid")
	}
	if !validSandboxIdentity(g.SandboxID, g.MinerID, g.Generation) || !leaseIDNames(g.LeaseID, g.SandboxID, g.MinerID, g.Generation) ||
		!organic.ValidDigest(g.LeaseDigest) || !lowercaseHex(g.Nonce, 32) || !lowercaseHex(g.Account, 64) {
		return errors.New("sandbox file grant identity is invalid")
	}
	if err := sandbox.ValidOpPath(g.Path, false); err != nil {
		return err
	}
	if g.MaxBytes == 0 || g.MaxBytes > MaxDirectFileBytes || g.Offset > MaxDirectFileBytes {
		return errors.New("sandbox file grant max_bytes or offset is out of bounds")
	}
	switch g.Op {
	case DirectFileUpload:
		if g.Offset+g.MaxBytes > MaxDirectFileBytes {
			return errors.New("sandbox file grant would exceed the maximum file size")
		}
		if (g.Offset == 0) != (g.Mode != nil) || (g.Mode != nil && *g.Mode > sandbox.MaxFileModeBits) {
			return errors.New("sandbox file grant mode is required exactly at offset 0")
		}
		if g.ExpectedSHA256 != nil && !lowercaseHex(*g.ExpectedSHA256, 64) {
			return errors.New("sandbox file grant expected_sha256 must be 64 lowercase hex")
		}
	case DirectFileDownload:
		if g.Mode != nil || g.ExpectedSHA256 != nil {
			return errors.New("sandbox file grant download carries no mode or expected_sha256")
		}
	default:
		return errors.New("sandbox file grant op is invalid")
	}
	if err := validateSandboxWindow(g.IssuedAt, g.ExpiresAt, MaxFileGrantWindow, "file_grant"); err != nil {
		return err
	}
	return validateSandboxBinding(g.Subnet, g.MinerID)
}

// Validate checks a received receipt; the signature must be present.
func (r SandboxFileReceiptV1) Validate() error {
	if err := r.validateUnsigned(); err != nil {
		return err
	}
	return validateSandboxSignature(r.Signature, "file receipt")
}

func (r SandboxFileReceiptV1) validateUnsigned() error {
	if r.Schema != SandboxFileReceiptSchema || r.SchemaVersion != SandboxFilesDirectSchemaVersion {
		return errors.New("sandbox file receipt schema is invalid")
	}
	if !validSandboxIdentity(r.SandboxID, r.MinerID, r.Generation) || !leaseIDNames(r.LeaseID, r.SandboxID, r.MinerID, r.Generation) ||
		!organic.ValidDigest(r.GrantDigest) || !lowercaseHex(r.Nonce, 32) || !lowercaseHex(r.Account, 64) || !lowercaseHex(r.SHA256, 64) {
		return errors.New("sandbox file receipt identity is invalid")
	}
	if r.Op != DirectFileUpload && r.Op != DirectFileDownload {
		return errors.New("sandbox file receipt op is invalid")
	}
	if err := sandbox.ValidOpPath(r.Path, false); err != nil {
		return err
	}
	if r.Bytes > MaxDirectFileBytes || r.Offset > MaxDirectFileBytes || r.FileSize > sandbox.MaxSafeInteger {
		return errors.New("sandbox file receipt sizes are out of bounds")
	}
	if _, err := parseStaticTime(r.CompletedAt); err != nil {
		return errors.New("sandbox file receipt completed_at is invalid")
	}
	return validateSandboxBinding(r.Subnet, r.MinerID)
}

// SandboxFileDigestV1 is "sha256:" + hex(SHA-256(canonical JSON of the
// complete signed grant or receipt)).
func SandboxFileDigestV1(document any) (string, error) {
	switch document.(type) {
	case SandboxFileGrantV1, SandboxFileReceiptV1:
		return staticDigest(document)
	}
	return "", errors.New("not a sandbox-file document")
}

// SignSandboxFileGrantV1 signs g with the validator Go service key.
func SignSandboxFileGrantV1(g *SandboxFileGrantV1, key ed25519.PrivateKey) error {
	if g == nil {
		return errors.New("invalid sandbox file grant signing input")
	}
	return signSandbox(SandboxFileGrantSigningDomain, g.validateUnsigned, *g, key, &g.Signature)
}

// SignSandboxFileReceiptV1 signs r with the miner Go service key.
func SignSandboxFileReceiptV1(r *SandboxFileReceiptV1, key ed25519.PrivateKey) error {
	if r == nil {
		return errors.New("invalid sandbox file receipt signing input")
	}
	return signSandbox(SandboxFileReceiptSigningDomain, r.validateUnsigned, *r, key, &r.Signature)
}

// VerifySandboxFileReceiptV1 verifies the bound miner service key signature.
func VerifySandboxFileReceiptV1(r SandboxFileReceiptV1, key ed25519.PublicKey) error {
	minerKey := ""
	if r.Subnet != nil {
		minerKey = r.Subnet.MinerServicePublicKey
	}
	return verifySandbox(SandboxFileReceiptSigningDomain, r.Validate, r, r.Signature, minerKey, key)
}

// VerifySandboxFileGrantForLeaseV1 is the miner's admission check of a grant
// against the signed lease it names: same lease (ID, digest, sandbox,
// generation, miner, parties), signed by that lease's validator service key,
// and inside its window at now. Whether the lease is still running is the
// caller's durable-state decision.
func VerifySandboxFileGrantForLeaseV1(g SandboxFileGrantV1, lease SandboxLeaseV1, now time.Time) error {
	if err := g.Validate(); err != nil {
		return err
	}
	digest, err := SandboxDigestV1(lease)
	if err != nil {
		return err
	}
	if g.LeaseDigest != digest || g.LeaseID != SandboxLeaseIDV1(lease) || g.SandboxID != lease.SandboxID ||
		g.Generation != lease.Generation || g.MinerID != lease.MinerID || !sameSandboxParties(g.Subnet, lease.Subnet) {
		return errors.New("sandbox file grant does not target the lease")
	}
	key, err := hexEd25519Key(bindingValidatorKey(lease.Subnet))
	if err != nil {
		return err
	}
	if err := verifySandbox(SandboxFileGrantSigningDomain, g.Validate, g, g.Signature, bindingValidatorKey(g.Subnet), key); err != nil {
		return err
	}
	issued, _ := parseStaticTime(g.IssuedAt)
	expires, _ := parseStaticTime(g.ExpiresAt)
	if now.Before(issued.Add(-sandbox.IssueSkew)) {
		return errors.New("sandbox file grant is not yet valid")
	}
	if !now.Before(expires) {
		return errors.New("sandbox file grant has expired")
	}
	return nil
}

// SandboxFileReceiptAnswersV1 is the broker's acceptance check of a receipt
// against the grant it obtained: same grant digest and identity, and never
// more bytes than the grant allowed. It does not verify the receipt
// signature: callers use VerifySandboxFileReceiptV1 with the bound miner key.
func SandboxFileReceiptAnswersV1(r SandboxFileReceiptV1, grant SandboxFileGrantV1) error {
	if err := grant.Validate(); err != nil {
		return err
	}
	if err := r.Validate(); err != nil {
		return err
	}
	digest, err := SandboxFileDigestV1(grant)
	if err != nil {
		return err
	}
	if r.GrantDigest != digest || r.Nonce != grant.Nonce || r.Account != grant.Account || r.Op != grant.Op || r.Path != grant.Path ||
		r.LeaseID != grant.LeaseID || r.SandboxID != grant.SandboxID || r.Generation != grant.Generation ||
		r.MinerID != grant.MinerID || !sameSandboxParties(r.Subnet, grant.Subnet) {
		return errors.New("sandbox file receipt does not answer the grant")
	}
	// A download may name a sub-range of its window; an upload is exactly
	// the granted part.
	if r.Offset < grant.Offset || r.Offset-grant.Offset > grant.MaxBytes || r.Bytes > grant.MaxBytes-(r.Offset-grant.Offset) ||
		(grant.Op == DirectFileUpload && r.Offset != grant.Offset) {
		return errors.New("sandbox file receipt reports bytes outside the granted window")
	}
	if grant.Op == DirectFileUpload && (r.Bytes != grant.MaxBytes || r.FileSize != grant.Offset+grant.MaxBytes ||
		(grant.ExpectedSHA256 != nil && *grant.ExpectedSHA256 != r.SHA256)) {
		return errors.New("sandbox file upload receipt contradicts the granted part")
	}
	return nil
}

func hexEd25519Key(encoded string) (ed25519.PublicKey, error) {
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("bound service key is not a 32-byte Ed25519 key")
	}
	return ed25519.PublicKey(decoded), nil
}
