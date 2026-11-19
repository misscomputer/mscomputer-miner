// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package protocol_test

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
)

func imagePrefetch(t *testing.T, signer ed25519.PrivateKey, binding *protocol.StaticSubnetBindingV1, mutate func(*protocol.SandboxImagePrefetchV1)) protocol.SandboxImagePrefetchV1 {
	t.Helper()
	digest := "sha256:" + strings.Repeat("c4", 32)
	r := protocol.SandboxImagePrefetchV1{
		ExpiresAt: stamp(sandboxNow.Add(time.Minute)), ImageDigest: digest, ImageReference: "mirror.example/library/python@" + digest,
		IssuedAt: stamp(sandboxNow), MinerID: binding.MinerHotkey, Nonce: strings.Repeat("c3", 16),
		Schema: protocol.SandboxImagePrefetchSchema, SchemaVersion: 1, Subnet: binding,
	}
	if mutate != nil {
		mutate(&r)
	}
	if err := protocol.SignSandboxImagePrefetchV1(&r, signer); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSandboxImagePrefetchSignsAndBindsItsReceipt(t *testing.T) {
	validator, miner := sandboxKeys()
	binding := sandboxLease(t, validator, miner, sandboxReservation(t, validator, miner), nil).Subnet
	request := imagePrefetch(t, validator, binding, nil)
	if err := protocol.VerifySandboxImagePrefetchV1Signature(request, validator.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("valid request refused: %v", err)
	}
	if err := protocol.VerifySandboxImagePrefetchV1Signature(imagePrefetch(t, miner, binding, nil), miner.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("request signed by a key other than the bound validator key was accepted")
	}
	tampered := request
	tampered.ImageReference = "mirror.example/library/other@" + request.ImageDigest
	if err := protocol.VerifySandboxImagePrefetchV1Signature(tampered, validator.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("altered request was accepted")
	}
	for name, mutate := range map[string]func(*protocol.SandboxImagePrefetchV1){
		"unpinned":    func(r *protocol.SandboxImagePrefetchV1) { r.ImageReference = "mirror.example/library/python:3" },
		"long window": func(r *protocol.SandboxImagePrefetchV1) { r.ExpiresAt = stamp(sandboxNow.Add(time.Hour)) },
		"short nonce": func(r *protocol.SandboxImagePrefetchV1) { r.Nonce = "ab" },
	} {
		r := imagePrefetch(t, validator, binding, nil)
		mutate(&r)
		if err := protocol.SignSandboxImagePrefetchV1(&r, validator); err == nil {
			t.Fatalf("%s: invalid request signed", name)
		}
	}
	digest, err := protocol.SandboxImagePrefetchDigestV1(request)
	if err != nil {
		t.Fatal(err)
	}
	receipt := protocol.SandboxImagePrefetchReceiptV1{
		DocumentDigest: digest, ImageDigest: request.ImageDigest, MinerID: request.MinerID, ObservedAt: stamp(sandboxNow),
		Schema: protocol.SandboxImagePrefetchReceiptSchema, SchemaVersion: 1, State: protocol.ImagePrefetchPulling, Subnet: binding,
	}
	if err := protocol.SignSandboxImagePrefetchReceiptV1(&receipt, miner); err != nil {
		t.Fatal(err)
	}
	if err := protocol.VerifySandboxImagePrefetchReceiptV1(receipt, request, miner.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("valid receipt refused: %v", err)
	}
	if err := protocol.VerifySandboxImagePrefetchReceiptV1(receipt, imagePrefetch(t, validator, binding, func(r *protocol.SandboxImagePrefetchV1) { r.Nonce = strings.Repeat("d4", 16) }), miner.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("receipt for another request was accepted")
	}
	code := "not_a_code"
	refused := receipt
	refused.State, refused.ErrorCode, refused.Signature = protocol.ImagePrefetchRefused, &code, ""
	if err := protocol.SignSandboxImagePrefetchReceiptV1(&refused, miner); err == nil {
		t.Fatal("refusal with an unknown code was signed")
	}
}
