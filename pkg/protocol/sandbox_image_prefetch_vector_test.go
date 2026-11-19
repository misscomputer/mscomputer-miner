// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package protocol_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
)

// prefetchVector pins the signed bytes of one prefetch request: the
// validator runtime that signs it is built separately, so both sides check
// the same digest and signature.
const (
	prefetchVectorSignature = "11f70a1765cb4b65546ebb0fa6d507b6918c399b7afd1340552641d876fcab72e9404356d0331a65c8cc0c3c10d424f75daa84e64805fb38882375dded172b08"
	prefetchVectorDigest    = "sha256:e20cc2f9afa75daf0bfdd90388cb1a5fae1cb16bb99722ccd690b1b70eae89e6"
)

func prefetchVectorRequest(t *testing.T) protocol.SandboxImagePrefetchV1 {
	t.Helper()
	validator := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, 32))
	miner := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, 32))
	uid := uint16(7)
	digest := "sha256:" + strings.Repeat("c4", 32)
	r := protocol.SandboxImagePrefetchV1{
		ExpiresAt: "2026-11-18T00:02:00Z", ImageDigest: digest, ImageReference: "mirror.example/docker.io/library/python@" + digest,
		IssuedAt: "2026-11-18T00:00:00Z", MinerID: "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty", Nonce: strings.Repeat("c3", 16),
		Schema: protocol.SandboxImagePrefetchSchema, SchemaVersion: 1,
		Subnet: &protocol.StaticSubnetBindingV1{
			ChainBlock: 100, Epoch: 1, ExpiresAtBlock: 112, MinerAxonURL: "http://10.0.0.7:8091",
			MinerHotkey: "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty", MinerServicePublicKey: hex.EncodeToString(miner.Public().(ed25519.PublicKey)),
			MinerTransport: "http", MinerUID: &uid, NetUID: 42, Network: "test",
			ValidatorHotkey: "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY", ValidatorServicePublicKey: hex.EncodeToString(validator.Public().(ed25519.PublicKey)),
		},
	}
	if err := protocol.SignSandboxImagePrefetchV1(&r, validator); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSandboxImagePrefetchVector(t *testing.T) {
	r := prefetchVectorRequest(t)
	digest, err := protocol.SandboxImagePrefetchDigestV1(r)
	if err != nil {
		t.Fatal(err)
	}
	if r.Signature != prefetchVectorSignature || digest != prefetchVectorDigest {
		t.Fatalf("signature %s digest %s", r.Signature, digest)
	}
}
