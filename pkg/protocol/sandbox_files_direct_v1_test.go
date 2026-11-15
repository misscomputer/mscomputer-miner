// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package protocol_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
)

func fileGrant(t *testing.T, signer ed25519.PrivateKey, lease protocol.SandboxLeaseV1, mutate func(*protocol.SandboxFileGrantV1)) protocol.SandboxFileGrantV1 {
	t.Helper()
	digest, err := protocol.SandboxDigestV1(lease)
	if err != nil {
		t.Fatal(err)
	}
	mode := uint32(0o644)
	g := protocol.SandboxFileGrantV1{
		Account: strings.Repeat("ab", 32), ExpiresAt: stamp(sandboxNow.Add(10 * time.Minute)), Generation: lease.Generation,
		IssuedAt: stamp(sandboxNow), LeaseDigest: digest, LeaseID: protocol.SandboxLeaseIDV1(lease), MaxBytes: 1 << 20,
		MinerID: lease.MinerID, Mode: &mode, Nonce: strings.Repeat("c3", 16), Op: protocol.DirectFileUpload,
		Path: "/workspace/data.bin", SandboxID: lease.SandboxID, Schema: protocol.SandboxFileGrantSchema, SchemaVersion: 1,
		Subnet: lease.Subnet,
	}
	if mutate != nil {
		mutate(&g)
	}
	if err := protocol.SignSandboxFileGrantV1(&g, signer); err != nil {
		t.Fatal(err)
	}
	return g
}

func fileReceipt(t *testing.T, miner ed25519.PrivateKey, g protocol.SandboxFileGrantV1, mutate func(*protocol.SandboxFileReceiptV1)) protocol.SandboxFileReceiptV1 {
	t.Helper()
	digest, err := protocol.SandboxFileDigestV1(g)
	if err != nil {
		t.Fatal(err)
	}
	r := protocol.SandboxFileReceiptV1{
		Account: g.Account, Bytes: g.MaxBytes, CompletedAt: stamp(sandboxNow.Add(time.Minute)), FileSize: g.Offset + g.MaxBytes,
		Generation: g.Generation, GrantDigest: digest, LeaseID: g.LeaseID, MinerID: g.MinerID, Nonce: g.Nonce, Offset: g.Offset,
		Op: g.Op, Path: g.Path, SandboxID: g.SandboxID, Schema: protocol.SandboxFileReceiptSchema, SchemaVersion: 1,
		SHA256: strings.Repeat("0d", 32), Subnet: g.Subnet,
	}
	if mutate != nil {
		mutate(&r)
	}
	if err := protocol.SignSandboxFileReceiptV1(&r, miner); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSandboxFileGrantVerifiesOnlyAgainstItsLease(t *testing.T) {
	validator, miner := sandboxKeys()
	lease := sandboxLease(t, validator, miner, sandboxReservation(t, validator, miner), nil)
	grant := fileGrant(t, validator, lease, nil)
	if err := protocol.VerifySandboxFileGrantForLeaseV1(grant, lease, sandboxNow.Add(time.Minute)); err != nil {
		t.Fatalf("valid grant refused: %v", err)
	}
	// Signed by the miner key (or any key other than the lease's validator key).
	forged := fileGrant(t, miner, lease, nil)
	if err := protocol.VerifySandboxFileGrantForLeaseV1(forged, lease, sandboxNow.Add(time.Minute)); err == nil {
		t.Fatal("grant signed by a key other than the lease validator key was accepted")
	}
	// Any member change after signing breaks the signature.
	for name, tamper := range map[string]func(*protocol.SandboxFileGrantV1){
		"max_bytes": func(g *protocol.SandboxFileGrantV1) { g.MaxBytes++ },
		"path":      func(g *protocol.SandboxFileGrantV1) { g.Path = "/workspace/other.bin" },
		"op":        func(g *protocol.SandboxFileGrantV1) { g.Op = protocol.DirectFileDownload; g.Mode = nil },
		"offset":    func(g *protocol.SandboxFileGrantV1) { g.Offset = 1; g.Mode = nil },
		"nonce":     func(g *protocol.SandboxFileGrantV1) { g.Nonce = strings.Repeat("d4", 16) },
		"account":   func(g *protocol.SandboxFileGrantV1) { g.Account = strings.Repeat("cd", 32) },
	} {
		tampered := grant
		tamper(&tampered)
		if err := protocol.VerifySandboxFileGrantForLeaseV1(tampered, lease, sandboxNow.Add(time.Minute)); err == nil {
			t.Fatalf("tampered %s accepted", name)
		}
	}
	// Another generation of the same sandbox: a different lease.
	other := sandboxLease(t, validator, miner, sandboxReservation(t, validator, miner), func(l *protocol.SandboxLeaseV1) {
		l.AssignmentNonce = strings.Repeat("e5", 16)
	})
	if err := protocol.VerifySandboxFileGrantForLeaseV1(grant, other, sandboxNow.Add(time.Minute)); err == nil {
		t.Fatal("grant accepted against a different lease")
	}
	// Window.
	if err := protocol.VerifySandboxFileGrantForLeaseV1(grant, lease, sandboxNow.Add(10*time.Minute)); err == nil {
		t.Fatal("expired grant accepted")
	}
	if err := protocol.VerifySandboxFileGrantForLeaseV1(grant, lease, sandboxNow.Add(-time.Minute)); err == nil {
		t.Fatal("not-yet-valid grant accepted")
	}
}

func TestSandboxFileGrantRejectsInvalidMembers(t *testing.T) {
	validator, miner := sandboxKeys()
	lease := sandboxLease(t, validator, miner, sandboxReservation(t, validator, miner), nil)
	sha := strings.Repeat("ee", 32)
	for name, mutate := range map[string]func(*protocol.SandboxFileGrantV1){
		"window over 15 min":    func(g *protocol.SandboxFileGrantV1) { g.ExpiresAt = stamp(sandboxNow.Add(16 * time.Minute)) },
		"dotdot path":           func(g *protocol.SandboxFileGrantV1) { g.Path = "/workspace/../etc/passwd" },
		"relative path":         func(g *protocol.SandboxFileGrantV1) { g.Path = "workspace/x" },
		"root path":             func(g *protocol.SandboxFileGrantV1) { g.Path = "/" },
		"zero bytes":            func(g *protocol.SandboxFileGrantV1) { g.MaxBytes = 0 },
		"too large":             func(g *protocol.SandboxFileGrantV1) { g.MaxBytes = protocol.MaxDirectFileBytes + 1 },
		"upload past max":       func(g *protocol.SandboxFileGrantV1) { g.Offset = protocol.MaxDirectFileBytes; g.Mode = nil },
		"upload offset no mode": func(g *protocol.SandboxFileGrantV1) { g.Mode = nil },
		"download with mode":    func(g *protocol.SandboxFileGrantV1) { g.Op = protocol.DirectFileDownload },
		"download with sha": func(g *protocol.SandboxFileGrantV1) {
			g.Op, g.Mode, g.ExpectedSHA256 = protocol.DirectFileDownload, nil, &sha
		},
		"bad sha":     func(g *protocol.SandboxFileGrantV1) { bad := "ABC"; g.ExpectedSHA256 = &bad },
		"unknown op":  func(g *protocol.SandboxFileGrantV1) { g.Op = "delete" },
		"short nonce": func(g *protocol.SandboxFileGrantV1) { g.Nonce = "c3" },
		"account":     func(g *protocol.SandboxFileGrantV1) { g.Account = "tenant" },
		"lease id":    func(g *protocol.SandboxFileGrantV1) { g.LeaseID = "lease-x" },
		"miner":       func(g *protocol.SandboxFileGrantV1) { g.MinerID = "5Fother" },
	} {
		g := fileGrant(t, validator, lease, nil)
		mutate(&g)
		if err := protocol.SignSandboxFileGrantV1(&g, validator); err == nil {
			t.Fatalf("%s: invalid grant signed", name)
		}
	}
}

func TestSandboxFileReceiptAnswersTheGrant(t *testing.T) {
	validator, miner := sandboxKeys()
	lease := sandboxLease(t, validator, miner, sandboxReservation(t, validator, miner), nil)
	grant := fileGrant(t, validator, lease, nil)
	receipt := fileReceipt(t, miner, grant, nil)
	if err := protocol.VerifySandboxFileReceiptV1(receipt, miner.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("receipt signature: %v", err)
	}
	if err := protocol.VerifySandboxFileReceiptV1(receipt, validator.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("receipt verified with a key other than the bound miner key")
	}
	if err := protocol.SandboxFileReceiptAnswersV1(receipt, grant); err != nil {
		t.Fatalf("receipt does not answer: %v", err)
	}
	for name, mutate := range map[string]func(*protocol.SandboxFileReceiptV1){
		"inflated bytes": func(r *protocol.SandboxFileReceiptV1) { r.Bytes = grant.MaxBytes + 1; r.FileSize = r.Bytes },
		"short upload":   func(r *protocol.SandboxFileReceiptV1) { r.Bytes = grant.MaxBytes - 1; r.FileSize = r.Bytes },
		"other nonce":    func(r *protocol.SandboxFileReceiptV1) { r.Nonce = strings.Repeat("d4", 16) },
		"other path":     func(r *protocol.SandboxFileReceiptV1) { r.Path = "/tmp/x" },
		"other digest":   func(r *protocol.SandboxFileReceiptV1) { r.GrantDigest = "sha256:" + strings.Repeat("00", 32) },
		"upload offset":  func(r *protocol.SandboxFileReceiptV1) { r.Offset = 1; r.FileSize = r.Bytes + 1 },
	} {
		if err := protocol.SandboxFileReceiptAnswersV1(fileReceipt(t, miner, grant, mutate), grant); err == nil {
			t.Fatalf("%s: receipt accepted", name)
		}
	}
	// Expected sha256 binds the upload receipt.
	sha := strings.Repeat("0d", 32)
	pinned := fileGrant(t, validator, lease, func(g *protocol.SandboxFileGrantV1) { g.ExpectedSHA256 = &sha })
	if err := protocol.SandboxFileReceiptAnswersV1(fileReceipt(t, miner, pinned, nil), pinned); err != nil {
		t.Fatalf("matching sha refused: %v", err)
	}
	if err := protocol.SandboxFileReceiptAnswersV1(fileReceipt(t, miner, pinned, func(r *protocol.SandboxFileReceiptV1) {
		r.SHA256 = strings.Repeat("0e", 32)
	}), pinned); err == nil {
		t.Fatal("receipt with a different sha256 than expected accepted")
	}
	// A download may be shorter than its window (end of file).
	download := fileGrant(t, validator, lease, func(g *protocol.SandboxFileGrantV1) { g.Op, g.Mode = protocol.DirectFileDownload, nil })
	short := fileReceipt(t, miner, download, func(r *protocol.SandboxFileReceiptV1) { r.Bytes = 10; r.FileSize = 10 })
	if err := protocol.SandboxFileReceiptAnswersV1(short, download); err != nil {
		t.Fatalf("short download refused: %v", err)
	}
	// A ranged download stays inside its window.
	inside := fileReceipt(t, miner, download, func(r *protocol.SandboxFileReceiptV1) { r.Offset, r.Bytes = 1<<19, 1<<19 })
	if err := protocol.SandboxFileReceiptAnswersV1(inside, download); err != nil {
		t.Fatalf("ranged download refused: %v", err)
	}
	outside := fileReceipt(t, miner, download, func(r *protocol.SandboxFileReceiptV1) { r.Offset, r.Bytes = 1<<19, 1<<19+1 })
	if err := protocol.SandboxFileReceiptAnswersV1(outside, download); err == nil {
		t.Fatal("download receipt past its window accepted")
	}
}

func TestSandboxFileSignaturesAreDomainSeparated(t *testing.T) {
	validator, miner := sandboxKeys()
	lease := sandboxLease(t, validator, miner, sandboxReservation(t, validator, miner), nil)
	grant := fileGrant(t, validator, lease, nil)
	message := signedMessage(t, protocol.SandboxFileGrantSigningDomain, grant)
	if !bytes.HasPrefix(message, []byte(protocol.SandboxFileGrantSigningDomain+"\x00")) {
		t.Fatal("grant message lacks its domain prefix")
	}
	for _, domain := range []string{protocol.SandboxOpRequestSigningDomain, protocol.SandboxLeaseSigningDomain, protocol.SandboxFileReceiptSigningDomain} {
		if ed25519.Verify(validator.Public().(ed25519.PublicKey), signedMessage(t, domain, grant), mustHex(t, grant.Signature)) {
			t.Fatalf("grant signature verifies under %s", domain)
		}
	}
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

type fileVectorSet struct {
	MinerSeed     string          `json:"miner_seed"`
	ValidatorSeed string          `json:"validator_seed"`
	Lease         json.RawMessage `json:"lease"`
	Grant         json.RawMessage `json:"grant"`
	GrantDigest   string          `json:"grant_digest"`
	Receipt       json.RawMessage `json:"receipt"`
	Download      json.RawMessage `json:"download_grant"`
}

// The grant and receipt bytes are pinned: the validator runtime (another
// implementation) must produce and accept exactly these documents.
func TestSandboxFileDocumentsMatchGoldenVectors(t *testing.T) {
	validator, miner := sandboxKeys()
	lease := sandboxLease(t, validator, miner, sandboxReservation(t, validator, miner), nil)
	sha := strings.Repeat("0d", 32)
	grant := fileGrant(t, validator, lease, func(g *protocol.SandboxFileGrantV1) { g.ExpectedSHA256 = &sha })
	receipt := fileReceipt(t, miner, grant, nil)
	download := fileGrant(t, validator, lease, func(g *protocol.SandboxFileGrantV1) {
		g.Op, g.Mode, g.Offset, g.Nonce = protocol.DirectFileDownload, nil, 4096, strings.Repeat("e7", 16)
	})
	digest, _ := protocol.SandboxFileDigestV1(grant)
	got := fileVectorSet{
		MinerSeed: hex.EncodeToString(miner.Seed()), ValidatorSeed: hex.EncodeToString(validator.Seed()),
		Lease: canonicalJSON(t, lease), Grant: canonicalJSON(t, grant), GrantDigest: digest, Receipt: canonicalJSON(t, receipt),
		Download: canonicalJSON(t, download),
	}
	rendered, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	rendered = append(rendered, '\n')
	path := filepath.Join("testdata", "sandbox-file-direct-v1-vectors.json")
	if *updateSandboxVectors {
		if err := os.WriteFile(path, rendered, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, rendered) {
		t.Fatalf("file vectors changed; rerun with -update-sandbox-vectors only for an intended contract change\n%s", rendered)
	}
}
