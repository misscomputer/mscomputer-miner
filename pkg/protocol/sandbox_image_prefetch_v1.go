// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package protocol

import (
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/misscomputer/mscomputer-miner/pkg/organic"
	"github.com/misscomputer/mscomputer-miner/pkg/sandbox"
)

// Image prefetch documents. The validator runtime signs a prefetch request
// with the service key that signs its leases; the miner verifies it against
// the validator key in the subnet binding (exactly as for a lease) and
// answers with a receipt signed by its own service key. A prefetch only
// warms the miner's image cache: it holds no capacity and runs nothing.
const (
	SandboxImagePrefetchSchema        = organic.SchemaPrefix + "sandbox-image-prefetch"
	SandboxImagePrefetchReceiptSchema = organic.SchemaPrefix + "sandbox-image-prefetch-receipt"
	SandboxImagePrefetchSchemaVersion = 1

	SandboxImagePrefetchSigningDomain        = SandboxImagePrefetchSchema + "/v1/ed25519"
	SandboxImagePrefetchReceiptSigningDomain = SandboxImagePrefetchReceiptSchema + "/v1/ed25519"

	// MaxImagePrefetchWindow bounds expires_at - issued_at of a request.
	MaxImagePrefetchWindow = 5 * time.Minute

	// Prefetch receipt states.
	ImagePrefetchCached  = "cached"
	ImagePrefetchPulling = "pulling"
	ImagePrefetchRefused = "refused"
)

// SandboxImagePrefetchV1 asks one miner to pull image_reference (pinned to
// image_digest) into its sandbox image cache. nonce makes it unique.
type SandboxImagePrefetchV1 struct {
	ExpiresAt      string                 `json:"expires_at"`
	ImageDigest    string                 `json:"image_digest"`
	ImageReference string                 `json:"image_reference"`
	IssuedAt       string                 `json:"issued_at"`
	MinerID        string                 `json:"miner_id"`
	Nonce          string                 `json:"nonce"`
	Schema         string                 `json:"schema"`
	SchemaVersion  int                    `json:"schema_version"`
	Signature      string                 `json:"signature"`
	Subnet         *StaticSubnetBindingV1 `json:"subnet"`
}

// SandboxImagePrefetchReceiptV1 is the miner's signed state of one prefetch:
// cached (already present), pulling (accepted; the pull continues after the
// answer) or refused with error_code.
type SandboxImagePrefetchReceiptV1 struct {
	DocumentDigest string                 `json:"document_digest"`
	ErrorCode      *string                `json:"error_code"`
	ImageDigest    string                 `json:"image_digest"`
	MinerID        string                 `json:"miner_id"`
	ObservedAt     string                 `json:"observed_at"`
	Schema         string                 `json:"schema"`
	SchemaVersion  int                    `json:"schema_version"`
	Signature      string                 `json:"signature"`
	State          string                 `json:"state"`
	Subnet         *StaticSubnetBindingV1 `json:"subnet"`
}

// Validate checks a received prefetch request; the signature must be present.
func (r SandboxImagePrefetchV1) Validate() error {
	if err := r.validateUnsigned(); err != nil {
		return err
	}
	return validateSandboxSignature(r.Signature, "image prefetch")
}

func (r SandboxImagePrefetchV1) validateUnsigned() error {
	if r.Schema != SandboxImagePrefetchSchema || r.SchemaVersion != SandboxImagePrefetchSchemaVersion {
		return errors.New("sandbox image prefetch schema is invalid")
	}
	if !organic.ValidHotkey(r.MinerID) || !lowercaseHex(r.Nonce, 32) {
		return errors.New("sandbox image prefetch identity is invalid")
	}
	if digest, ok := sandbox.ImageDigest(r.ImageReference); !ok || digest != r.ImageDigest {
		return errors.New("image_reference must pin image_digest")
	}
	if err := validateSandboxWindow(r.IssuedAt, r.ExpiresAt, MaxImagePrefetchWindow, "image_prefetch"); err != nil {
		return err
	}
	return validateSandboxBinding(r.Subnet, r.MinerID)
}

// Validate checks a received receipt; the signature must be present.
func (r SandboxImagePrefetchReceiptV1) Validate() error {
	if err := r.validateUnsigned(); err != nil {
		return err
	}
	return validateSandboxSignature(r.Signature, "image prefetch receipt")
}

func (r SandboxImagePrefetchReceiptV1) validateUnsigned() error {
	if r.Schema != SandboxImagePrefetchReceiptSchema || r.SchemaVersion != SandboxImagePrefetchSchemaVersion {
		return errors.New("sandbox image prefetch receipt schema is invalid")
	}
	if !organic.ValidHotkey(r.MinerID) || !organic.ValidDigest(r.DocumentDigest) || !organic.ValidDigest(r.ImageDigest) {
		return errors.New("sandbox image prefetch receipt identity is invalid")
	}
	switch r.State {
	case ImagePrefetchCached, ImagePrefetchPulling:
		if r.ErrorCode != nil {
			return errors.New("sandbox image prefetch receipt carries an error_code without a refusal")
		}
	case ImagePrefetchRefused:
		if r.ErrorCode == nil || !knownPrefetchCode(*r.ErrorCode) {
			return errors.New("sandbox image prefetch refusal needs a valid error_code")
		}
	default:
		return errors.New("sandbox image prefetch receipt state is invalid")
	}
	if _, err := parseStaticTime(r.ObservedAt); err != nil {
		return errors.New("sandbox image prefetch receipt observed_at is invalid")
	}
	return validateSandboxBinding(r.Subnet, r.MinerID)
}

// SandboxImagePrefetchDigestV1 is "sha256:" + hex(SHA-256(canonical JSON of
// the complete signed request or receipt)).
func SandboxImagePrefetchDigestV1(document any) (string, error) {
	switch document.(type) {
	case SandboxImagePrefetchV1, SandboxImagePrefetchReceiptV1:
		return staticDigest(document)
	}
	return "", errors.New("not a sandbox image prefetch document")
}

// SignSandboxImagePrefetchV1 signs r with the validator Go service key.
func SignSandboxImagePrefetchV1(r *SandboxImagePrefetchV1, key ed25519.PrivateKey) error {
	if r == nil {
		return errors.New("invalid sandbox image prefetch signing input")
	}
	return signSandbox(SandboxImagePrefetchSigningDomain, r.validateUnsigned, *r, key, &r.Signature)
}

// SignSandboxImagePrefetchReceiptV1 signs r with the miner Go service key.
func SignSandboxImagePrefetchReceiptV1(r *SandboxImagePrefetchReceiptV1, key ed25519.PrivateKey) error {
	if r == nil {
		return errors.New("invalid sandbox image prefetch receipt signing input")
	}
	return signSandbox(SandboxImagePrefetchReceiptSigningDomain, r.validateUnsigned, *r, key, &r.Signature)
}

// VerifySandboxImagePrefetchV1Signature verifies the bound validator service
// key signature without a wall-clock or chain decision.
func VerifySandboxImagePrefetchV1Signature(r SandboxImagePrefetchV1, key ed25519.PublicKey) error {
	return verifySandbox(SandboxImagePrefetchSigningDomain, r.Validate, r, r.Signature, bindingValidatorKey(r.Subnet), key)
}

// VerifySandboxImagePrefetchReceiptV1 verifies the bound miner service key
// signature and that the receipt answers request.
func VerifySandboxImagePrefetchReceiptV1(r SandboxImagePrefetchReceiptV1, request SandboxImagePrefetchV1, key ed25519.PublicKey) error {
	minerKey := ""
	if r.Subnet != nil {
		minerKey = r.Subnet.MinerServicePublicKey
	}
	if err := verifySandbox(SandboxImagePrefetchReceiptSigningDomain, r.Validate, r, r.Signature, minerKey, key); err != nil {
		return err
	}
	digest, err := SandboxImagePrefetchDigestV1(request)
	if err != nil {
		return err
	}
	if r.DocumentDigest != digest || r.MinerID != request.MinerID || r.ImageDigest != request.ImageDigest {
		return errors.New("sandbox image prefetch receipt does not answer the request")
	}
	return nil
}

func knownPrefetchCode(code string) bool {
	_, known := sandbox.ReceiptErrorAttribution[code]
	return known
}

// VerifyBoundSandboxImagePrefetchV1 is the miner admission check of a
// prefetch request: the bound validator signed it, it is inside its window
// and it names this miner on this subnet.
func VerifyBoundSandboxImagePrefetchV1(r SandboxImagePrefetchV1, key ed25519.PublicKey, now time.Time, currentBlock uint64, network string, netuid uint16, callerHotkey, minerHotkey string, minerUID *uint16) error {
	if err := VerifySandboxImagePrefetchV1Signature(r, key); err != nil {
		return err
	}
	return sandboxAdmission(r.Subnet, r.MinerID, r.IssuedAt, r.ExpiresAt, now, currentBlock, network, netuid, callerHotkey, minerHotkey, minerUID)
}
