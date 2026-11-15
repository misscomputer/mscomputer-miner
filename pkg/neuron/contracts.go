// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

// Package neuron defines the JSON seam between the Bittensor v11 Python
// neurons and the Go deployment core. These structs mirror the Pydantic models
// in mscomputer_subnet.protocol and are pinned by shared fixtures.
package neuron

import (
	"encoding/hex"
	"encoding/json"
	"errors"
)

const (
	SynapseVersion = "subnet-synapse.v2"
	// HealthObservationVersion is intentionally message-scoped. Health v2
	// lacked an endpoint incarnation and cannot safely be replayed across a
	// replacement, while the other v2 neuron contracts remain current.
	HealthObservationVersion = "subnet-synapse.v3"
	ServiceBindingVersion    = "service-binding.v2"
	TransportLocal           = "local"
	TransportHTTPS           = "https"
	TransportHTTP            = "http"
)

type LocalCapabilities struct {
	Protocol                   string   `json:"protocol"`
	Network                    string   `json:"network"`
	NetUID                     uint16   `json:"netuid"`
	MinerHotkey                string   `json:"miner_hotkey"`
	MinerUID                   *uint16  `json:"miner_uid,omitempty"`
	ServicePublicKey           string   `json:"service_public_key"`
	Transport                  string   `json:"transport"`
	TransportCertificateSHA256 *string  `json:"transport_certificate_sha256"`
	Features                   []string `json:"features"`
	MaxBodyBytes               int      `json:"max_body_bytes"`
	// CachedImages is the sandbox image inventory (ValidateCachedImages),
	// most recently used first. Omitted when empty.
	CachedImages []string `json:"cached_images,omitempty"`
}

type ControlCapabilities struct {
	Protocol         string   `json:"protocol"`
	ServicePublicKey string   `json:"service_public_key"`
	Features         []string `json:"features"`
	WeightsEnabled   bool     `json:"weights_enabled"`
}

type RecoveryResponse struct {
	Protocol                  string `json:"protocol"`
	NonDeactivatedAssignments int    `json:"non_deactivated_assignments"`
	// PendingStartupAssignments counts the members of the immutable startup
	// recovery snapshot that no exact-identity registration has cleaned yet.
	// Assignments created by the running process never enter this set.
	PendingStartupAssignments int `json:"pending_startup_assignments"`
}

type ServiceKeyBinding struct {
	Protocol                   string  `json:"protocol"`
	Role                       string  `json:"role"`
	Network                    string  `json:"network"`
	NetUID                     uint16  `json:"netuid"`
	Hotkey                     string  `json:"hotkey"`
	UID                        *uint16 `json:"uid,omitempty"`
	ServicePublicKey           string  `json:"service_public_key"`
	Transport                  string  `json:"transport"`
	TransportCertificateSHA256 *string `json:"transport_certificate_sha256"`
	Generation                 uint64  `json:"generation"`
	ValidFromBlock             uint64  `json:"valid_from_block"`
	ExpiresAtBlock             uint64  `json:"expires_at_block"`
	Challenge                  string  `json:"challenge"`
	Signature                  string  `json:"signature"`
}

type CapabilitiesSynapse struct {
	Protocol     string `json:"protocol"`
	RequestID    string `json:"request_id"`
	Network      string `json:"network"`
	NetUID       uint16 `json:"netuid"`
	ChainBlock   uint64 `json:"chain_block"`
	CallerHotkey string `json:"caller_hotkey"`
	Challenge    string `json:"challenge"`
}

type CapabilitiesResponse struct {
	Protocol       string            `json:"protocol"`
	RequestID      string            `json:"request_id"`
	MinerHotkey    string            `json:"miner_hotkey"`
	MinerUID       *uint16           `json:"miner_uid,omitempty"`
	Features       []string          `json:"features"`
	MaxBodyBytes   int               `json:"max_body_bytes"`
	ServiceBinding ServiceKeyBinding `json:"service_binding"`
	// CachedImages is optional (ValidateCachedImages); a response without
	// it is unchanged from before the member existed.
	CachedImages []string `json:"cached_images,omitempty"`
}

type StatusSynapse struct {
	Protocol     string `json:"protocol"`
	RequestID    string `json:"request_id"`
	CurrentBlock uint64 `json:"current_block"`
	CallerHotkey string `json:"caller_hotkey"`
	EndpointID   string `json:"endpoint_id"`
}

type DeactivateSynapse struct {
	Protocol     string `json:"protocol"`
	RequestID    string `json:"request_id"`
	CurrentBlock uint64 `json:"current_block"`
	CallerHotkey string `json:"caller_hotkey"`
	EndpointID   string `json:"endpoint_id"`
	DeploymentID string `json:"deployment_id"`
}

type DeactivateResponse struct {
	Protocol  string `json:"protocol"`
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
}

// BridgeDeactivateRequest binds cleanup of an existing assignment to the
// exact authenticated miner identity that received its signed ticket. The
// Python bridge resolves cleanup independently of schedule eligibility and
// fails closed unless a retained authenticated handle still has one exact
// active hotkey record, a unique matching UID, the assignment axon/service
// key, and a current binding. A rebound or ambiguous identity can therefore
// never receive another assignment's deactivation.
type BridgeDeactivateRequest struct {
	Protocol                  string  `json:"protocol"`
	RequestID                 string  `json:"request_id"`
	EndpointID                string  `json:"endpoint_id"`
	DeploymentID              string  `json:"deployment_id"`
	MinerHotkey               string  `json:"miner_hotkey"`
	MinerUID                  *uint16 `json:"miner_uid,omitempty"`
	AxonURL                   string  `json:"axon_url"`
	MinerServicePublicKey     string  `json:"miner_service_public_key"`
	MinerTransport            string  `json:"miner_transport"`
	MinerTLSCertificateSHA256 *string `json:"miner_tls_certificate_sha256"`
}

type MinerRegistration struct {
	Protocol                      string            `json:"protocol"`
	Network                       string            `json:"network"`
	NetUID                        uint16            `json:"netuid"`
	Hotkey                        string            `json:"hotkey"`
	UID                           *uint16           `json:"uid,omitempty"`
	AxonURL                       string            `json:"axon_url"`
	BridgeURL                     string            `json:"bridge_url"`
	TransportCertificateDERBase64 string            `json:"transport_certificate_der_base64"`
	ServiceBinding                ServiceKeyBinding `json:"service_binding"`
	// Features is present exactly in miner-registration.v3 (protocol
	// subnet-synapse.v3): the normalized capability features of the same
	// handshake response that carried ServiceBinding. v2 omits it.
	Features *[]string `json:"features,omitempty"`
}

type MinerSet struct {
	Protocol string   `json:"protocol"`
	Network  string   `json:"network"`
	NetUID   uint16   `json:"netuid"`
	Block    uint64   `json:"block"`
	Hotkeys  []string `json:"hotkeys"`
}

type ChainState struct {
	Protocol         string            `json:"protocol"`
	Network          string            `json:"network"`
	NetUID           uint16            `json:"netuid"`
	Block            uint64            `json:"block"`
	Epoch            uint64            `json:"epoch"`
	Tempo            uint64            `json:"tempo"`
	ValidatorHotkey  string            `json:"validator_hotkey"`
	ValidatorBinding ServiceKeyBinding `json:"validator_binding"`
}

func BindingJSON(binding ServiceKeyBinding) []byte {
	payload, _ := json.Marshal(binding)
	return payload
}

// ValidateServiceBindingTransport enforces the role-specific transport
// contract independently of hotkey signature verification. A validator's Go
// bridge is local and pinless. A miner is HTTPS with a canonical leaf pin;
// pinless HTTP exists only for an explicitly enabled local mock subnet.
func ValidateServiceBindingTransport(binding ServiceKeyBinding, allowInsecureMockHTTP bool) error {
	switch binding.Role {
	case "validator":
		if binding.Transport != TransportLocal || binding.TransportCertificateSHA256 != nil {
			return errors.New("validator service binding must use local transport without a certificate pin")
		}
	case "miner":
		if binding.Transport == TransportHTTPS && binding.TransportCertificateSHA256 != nil && CanonicalSHA256(*binding.TransportCertificateSHA256) {
			return nil
		}
		if allowInsecureMockHTTP && binding.Transport == TransportHTTP && binding.TransportCertificateSHA256 == nil {
			return nil
		}
		return errors.New("miner service binding must use HTTPS with a canonical certificate pin")
	default:
		return errors.New("service binding role is invalid")
	}
	return nil
}

func CanonicalSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(value) == 64 && len(decoded) == 32 && value == hex.EncodeToString(decoded)
}
