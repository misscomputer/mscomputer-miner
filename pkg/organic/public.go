// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package organic

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

var (
	maxManifestV2Deployments   = 4096
	maxManifestV2ReplicaRecord = 8
)

// OrganicHealthCheck is the sanitized public health predicate.
type OrganicHealthCheck struct {
	Method           string  `json:"method"`
	Path             string  `json:"path"`
	ExpectedStatuses []int   `json:"expected_statuses"`
	ResponseMarker   *string `json:"response_marker"`
}

// OrganicAssignedReplica is one active miner route after verified cutover.
type OrganicAssignedReplica struct {
	MinerUID                  int    `json:"miner_uid"`
	MinerHotkey               string `json:"miner_hotkey"`
	MinerServicePublicKey     string `json:"miner_service_public_key"`
	MinerTLSCertificateSHA256 string `json:"miner_tls_certificate_sha256"`
	Generation                int64  `json:"generation"`
	AssignmentNonce           string `json:"assignment_nonce"`
	ReplicaID                 string `json:"replica_id"`
	EndpointID                string `json:"endpoint_id"`
	TicketDigest              string `json:"ticket_digest"`
	ReceiptDigest             string `json:"receipt_digest"`
	ChainBlock                int64  `json:"chain_block"`
	ExpiresAtBlock            int64  `json:"expires_at_block"`
	ActivatedAtEpoch          int64  `json:"activated_at_epoch"`
	ExpiresAtEpoch            int64  `json:"expires_at_epoch"`
	RouteState                string `json:"route_state"`
}

// OrganicDeploymentAssignment is one published organic app route.
type OrganicDeploymentAssignment struct {
	DeploymentID           string                   `json:"deployment_id"`
	RouteHost              string                   `json:"route_host"`
	ArtifactDigest         string                   `json:"artifact_digest"`
	Health                 OrganicHealthCheck       `json:"health"`
	AttestationRequirement string                   `json:"attestation_requirement"`
	Replicas               []OrganicAssignedReplica `json:"replicas"`
	AssignmentDigestSHA256 string                   `json:"assignment_digest_sha256"`
}

// ActiveAssignmentManifestV2 is the public snapshot of organic assignments.
// It carries no synthetic challenge, customer secret or origin identity.
type ActiveAssignmentManifestV2 struct {
	Schema                            string                        `json:"schema"`
	SchemaVersion                     int                           `json:"schema_version"`
	Purpose                           string                        `json:"purpose"`
	Network                           string                        `json:"network"`
	NetUID                            int                           `json:"netuid"`
	CentralAuthorityFingerprintSHA256 string                        `json:"central_authority_fingerprint_sha256"`
	TrustPolicyDigestSHA256           string                        `json:"trust_policy_digest_sha256"`
	FinalizedHeight                   int64                         `json:"finalized_height"`
	FinalizedBlockHash                string                        `json:"finalized_block_hash"`
	FinalizedEpoch                    int64                         `json:"finalized_epoch"`
	Sequence                          int64                         `json:"sequence"`
	PreviousManifestDigestSHA256      *string                       `json:"previous_manifest_digest_sha256"`
	IssuedAtEpoch                     int64                         `json:"issued_at_epoch"`
	ExpiresAtEpoch                    int64                         `json:"expires_at_epoch"`
	RouteHostSuffix                   string                        `json:"route_host_suffix"`
	CheckScheme                       string                        `json:"probe_scheme"`
	CheckPort                         int                           `json:"probe_port"`
	Deployments                       []OrganicDeploymentAssignment `json:"deployments"`
	AssignmentVectorDigestSHA256      string                        `json:"assignment_vector_digest_sha256"`
	ManifestDigestSHA256              string                        `json:"manifest_digest_sha256"`
}

func (r OrganicAssignedReplica) validate(deploymentID string) error {
	if !between(int64(r.MinerUID), 0, 65535) || !ValidHotkey(r.MinerHotkey) || !ValidHex64(r.MinerServicePublicKey) ||
		!ValidHex64(r.MinerTLSCertificateSHA256) || r.Generation < 1 || !hex32Pattern.MatchString(r.AssignmentNonce) ||
		!ValidDigest(r.TicketDigest) || !ValidDigest(r.ReceiptDigest) || r.ChainBlock < 0 || r.ExpiresAtBlock < 1 ||
		r.ActivatedAtEpoch < 0 || r.ExpiresAtEpoch < 1 || r.RouteState != "active" {
		return errors.New("manifest replica fields are invalid")
	}
	if r.ExpiresAtBlock <= r.ChainBlock {
		return errors.New("replica_block_window_invalid")
	}
	if r.ExpiresAtEpoch <= r.ActivatedAtEpoch {
		return errors.New("replica_activation_window_invalid")
	}
	if r.TicketDigest == r.ReceiptDigest {
		return errors.New("replica_digest_collision")
	}
	replica := deploymentID + "-" + r.MinerHotkey
	if r.ReplicaID != replica || r.EndpointID != fmt.Sprintf("%s-g%d-%s", replica, r.Generation, r.AssignmentNonce) {
		return errors.New("assignment_replica_identity_invalid")
	}
	return nil
}

func (a OrganicDeploymentAssignment) validate() error {
	if !ValidRouteLabel(a.DeploymentID) || !ValidHostname(a.RouteHost) || !ValidDigest(a.ArtifactDigest) ||
		a.AttestationRequirement != "miner_service_key_v2" || !ValidHex64(a.AssignmentDigestSHA256) {
		return errors.New("manifest assignment fields are invalid")
	}
	if err := validateHealthRequest(a.Health.Method, a.Health.Path, a.Health.ExpectedStatuses, a.Health.ResponseMarker); err != nil {
		return err
	}
	if len(a.Replicas) < 1 || len(a.Replicas) > maxManifestV2ReplicaRecord {
		return errors.New("assignment must list 1-8 replicas")
	}
	sorted := sort.SliceIsSorted(a.Replicas, func(i, j int) bool {
		left, right := a.Replicas[i], a.Replicas[j]
		return left.MinerUID < right.MinerUID || (left.MinerUID == right.MinerUID && left.MinerHotkey < right.MinerHotkey)
	})
	for index, replica := range a.Replicas {
		if err := replica.validate(a.DeploymentID); err != nil {
			return err
		}
		if index > 0 && a.Replicas[index-1].MinerUID == replica.MinerUID && a.Replicas[index-1].MinerHotkey == replica.MinerHotkey {
			sorted = false
		}
	}
	if !sorted {
		return errors.New("assignment_replicas_not_canonical")
	}
	digest, err := DigestWithout(a, "assignment_digest_sha256")
	if err != nil || digest != a.AssignmentDigestSHA256 {
		return errors.New("assignment_digest_sha256_mismatch")
	}
	return nil
}

func (m ActiveAssignmentManifestV2) Validate() error {
	if err := validSchema(m.Schema, "active-assignment-manifest"); err != nil || m.SchemaVersion != 2 ||
		m.Purpose != "active_assignment_manifest_publication_v2" || m.Network != "finney" || m.NetUID != 24 {
		return errors.New("unsupported active assignment manifest schema")
	}
	if !ValidHex64(m.CentralAuthorityFingerprintSHA256) || !ValidHex64(m.TrustPolicyDigestSHA256) ||
		m.FinalizedHeight < 0 || !ValidHex64(m.FinalizedBlockHash) || m.FinalizedEpoch < 0 || m.Sequence < 1 ||
		(m.PreviousManifestDigestSHA256 != nil && !ValidHex64(*m.PreviousManifestDigestSHA256)) ||
		m.IssuedAtEpoch < 0 || m.ExpiresAtEpoch < 1 || !ValidHostname(m.RouteHostSuffix) || m.CheckScheme != "https" ||
		!between(int64(m.CheckPort), 1, 65535) || !ValidHex64(m.AssignmentVectorDigestSHA256) ||
		!ValidHex64(m.ManifestDigestSHA256) || m.Deployments == nil || len(m.Deployments) > maxManifestV2Deployments {
		return errors.New("active assignment manifest fields are invalid")
	}
	if m.ExpiresAtEpoch <= m.IssuedAtEpoch {
		return errors.New("manifest_validity_window_invalid")
	}
	if (m.Sequence == 1) != (m.PreviousManifestDigestSHA256 == nil) {
		return errors.New("manifest_previous_link_invalid")
	}
	endpoints := map[string]bool{}
	// One public host carries one deployment: a route label and its blue-green
	// attempts never appear together, so a host is checked and scored once.
	hosts := map[string]bool{}
	hostDuplicate := false
	for index, deployment := range m.Deployments {
		if err := deployment.validate(); err != nil {
			return err
		}
		if index > 0 && m.Deployments[index-1].DeploymentID >= deployment.DeploymentID {
			return errors.New("manifest_deployments_not_canonical")
		}
		if deployment.RouteHost != manifestRouteLabel(deployment.DeploymentID)+"."+m.RouteHostSuffix {
			return errors.New("manifest_route_host_invalid")
		}
		if hosts[deployment.RouteHost] {
			hostDuplicate = true
		}
		hosts[deployment.RouteHost] = true
		for _, replica := range deployment.Replicas {
			if replica.ExpiresAtBlock <= m.FinalizedHeight {
				return errors.New("manifest_replica_block_expired")
			}
			if replica.ExpiresAtEpoch <= m.IssuedAtEpoch {
				return errors.New("manifest_replica_expired")
			}
			if endpoints[replica.EndpointID] {
				return errors.New("manifest_endpoint_duplicate")
			}
			endpoints[replica.EndpointID] = true
		}
	}
	if hostDuplicate {
		return errors.New("manifest_route_host_duplicate")
	}
	vector, err := DigestHex(m.Deployments)
	if err != nil || vector != m.AssignmentVectorDigestSHA256 {
		return errors.New("assignment_vector_digest_sha256_mismatch")
	}
	digest, err := DigestWithout(m, "manifest_digest_sha256")
	if err != nil || digest != m.ManifestDigestSHA256 {
		return errors.New("manifest_digest_sha256_mismatch")
	}
	return nil
}

// ResponseHeaderSHA256 digests end-to-end response headers as the canonical
// JSON list of [lowercase name, value] pairs, stably sorted by name.
func ResponseHeaderSHA256(headers [][2]string) (string, error) {
	pairs := make([][]string, len(headers))
	for index, header := range headers {
		pairs[index] = []string{strings.ToLower(header[0]), header[1]}
	}
	sort.SliceStable(pairs, func(i, j int) bool { return pairs[i][0] < pairs[j][0] })
	encoded, err := Canonical(pairs)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}
