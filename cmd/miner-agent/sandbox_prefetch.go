// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package main

import (
	"errors"
	"io"
	"net/http"

	"github.com/misscomputer/mscomputer-miner/pkg/bridge"
	"github.com/misscomputer/mscomputer-miner/pkg/miner"
	"github.com/misscomputer/mscomputer-miner/pkg/neuron"
	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
)

// sandboxPrefetchSynapseVersion is the envelope of one validator image
// prefetch request, forwarded by the miner neuron after it authenticated the
// validator exactly as for sandbox lease documents.
const sandboxPrefetchSynapseVersion = "subnet-sandbox-image-prefetch-synapse.v1"

type sandboxPrefetchRequest struct {
	Protocol         string                          `json:"protocol"`
	RequestID        string                          `json:"request_id"`
	CurrentBlock     uint64                          `json:"current_block"`
	CallerHotkey     string                          `json:"caller_hotkey"`
	BindingVerified  bool                            `json:"binding_verified"`
	ValidatorBinding neuron.ServiceKeyBinding        `json:"validator_binding"`
	Document         protocol.SandboxImagePrefetchV1 `json:"document"`
}

type sandboxPrefetchResponse struct {
	Protocol  string                                 `json:"protocol"`
	RequestID string                                 `json:"request_id"`
	Receipt   protocol.SandboxImagePrefetchReceiptV1 `json:"receipt"`
}

func (a *api) sandboxImagePrefetch(w http.ResponseWriter, req *http.Request) {
	var input sandboxPrefetchRequest
	if err := decodeJSON(io.LimitReader(req.Body, bridge.MaxBodyBytes), &input); err != nil {
		bridge.WriteError(w, http.StatusBadRequest, "invalid_request", err.Error(), false)
		return
	}
	if input.Protocol != sandboxPrefetchSynapseVersion || input.RequestID == "" {
		bridge.WriteError(w, http.StatusBadRequest, "version_mismatch", "only "+sandboxPrefetchSynapseVersion+" prefetch requests are accepted", false)
		return
	}
	if !input.BindingVerified {
		bridge.WriteError(w, http.StatusForbidden, "binding_unverified", "validator hotkey service binding was not verified", false)
		return
	}
	key, err := a.acceptValidatorBinding(req, input.CurrentBlock, input.CallerHotkey, input.ValidatorBinding)
	if err != nil {
		status, code, retryable := assignmentError(err)
		bridge.WriteError(w, status, code, err.Error(), retryable)
		return
	}
	receipt, err := a.sandbox.PrefetchImage(req.Context(), input.Document, miner.SandboxRequest{
		ValidatorKey: key, CurrentBlock: input.CurrentBlock, Network: a.network, NetUID: a.netuid,
		CallerHotkey: input.CallerHotkey, MinerHotkey: a.hotkey, MinerUID: a.uid,
	})
	switch {
	case errors.Is(err, miner.ErrSandboxLaneClosed):
		bridge.WriteError(w, http.StatusServiceUnavailable, "sandbox_lane_closed", err.Error(), true)
	case err != nil:
		status, code, retryable := assignmentError(err)
		bridge.WriteError(w, status, code, err.Error(), retryable)
	default:
		writeJSON(w, http.StatusOK, sandboxPrefetchResponse{Protocol: sandboxPrefetchSynapseVersion, RequestID: input.RequestID, Receipt: receipt})
	}
}
