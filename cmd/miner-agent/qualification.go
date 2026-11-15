// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/misscomputer/mscomputer-miner/pkg/bridge"
	"github.com/misscomputer/mscomputer-miner/pkg/qualification"
)

// qualificationSynapseVersion is the loopback envelope of qualification
// documents between the Python miner neuron and this agent.
const qualificationSynapseVersion = "subnet-qualification-synapse.v1"

// qualificationDisabled is the stable answer of an agent started without
// --qualification on, like sandbox_disabled.
const qualificationDisabled = "qualification_disabled"

// maxQualificationRequestBytes bounds an envelope; challenges and openings
// requests are small.
const maxQualificationRequestBytes = 16 << 10

// openQualification builds the runner only for --qualification on.
func openQualification(mode string, policy qualificationPolicy) (*qualification.Runner, error) {
	switch mode {
	case "off":
		if policy != (qualificationPolicy{}) {
			return nil, errors.New("--qualification-* settings require --qualification on")
		}
		return nil, nil
	case "on":
		if policy.MaxFillMiB < 0 || policy.MaxFillMiB*(1<<20)/qualification.BlockSize > qualification.MaxFillBlocks ||
			policy.MaxWindow < 0 || policy.MaxWindow > qualification.DefaultMaxWindow || policy.JobsPerHour < 0 {
			return nil, errors.New("--qualification-max-fill-mib, --qualification-max-window or --qualification-jobs-per-hour is out of range")
		}
		return &qualification.Runner{
			MaxFillBlocks: policy.MaxFillMiB * (1 << 20) / qualification.BlockSize, MaxWindow: policy.MaxWindow,
			JobsPerValidator: policy.JobsPerHour, JobsWindow: time.Hour,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported --qualification mode %q", mode)
	}
}

// qualificationPolicy is the operator's --qualification-* policy; zero
// values keep the PROVISIONAL defaults.
type qualificationPolicy struct {
	MaxFillMiB  int
	MaxWindow   time.Duration
	JobsPerHour int
}

type qualificationRequest struct {
	Protocol     string          `json:"protocol"`
	RequestID    string          `json:"request_id"`
	CallerHotkey string          `json:"caller_hotkey"`
	Challenge    json.RawMessage `json:"challenge,omitempty"`
	Request      json.RawMessage `json:"request,omitempty"`
}

type commitmentResponse struct {
	Protocol   string                   `json:"protocol"`
	RequestID  string                   `json:"request_id"`
	Commitment qualification.Commitment `json:"commitment"`
}

type openingsResponse struct {
	Protocol  string                 `json:"protocol"`
	RequestID string                 `json:"request_id"`
	Openings  qualification.Openings `json:"openings"`
}

var qualificationRefusals = []struct {
	err       error
	status    int
	retryable bool
}{
	{qualification.ErrBusy, http.StatusTooManyRequests, true},
	{qualification.ErrMemory, http.StatusServiceUnavailable, false},
	{qualification.ErrIdentity, http.StatusForbidden, false},
	{qualification.ErrExpired, http.StatusGone, false},
	{qualification.ErrReplayed, http.StatusConflict, false},
	{qualification.ErrDeadline, http.StatusGatewayTimeout, false},
	{qualification.ErrFillAbsent, http.StatusNotFound, false},
	{qualification.ErrRequestMismatch, http.StatusConflict, false},
	{qualification.ErrOpeningsExhausted, http.StatusConflict, false},
	{qualification.ErrOpeningsServed, http.StatusTooManyRequests, false},
	{qualification.ErrRateLimited, http.StatusTooManyRequests, false},
	{qualification.ErrPolicy, http.StatusUnprocessableEntity, false},
}

// readQualification decodes one envelope; it answers the request itself and
// returns false when the request is refused.
func (a *api) readQualification(w http.ResponseWriter, req *http.Request, member string) (qualificationRequest, []byte, bool) {
	var input qualificationRequest
	if a.qualification == nil {
		bridge.WriteError(w, http.StatusNotImplemented, qualificationDisabled, "miner qualification is not enabled", false)
		return input, nil, false
	}
	if err := decodeJSON(io.LimitReader(req.Body, maxQualificationRequestBytes), &input); err != nil {
		bridge.WriteError(w, http.StatusBadRequest, "invalid_request", err.Error(), false)
		return input, nil, false
	}
	document := input.Challenge
	other := input.Request
	if member == "request" {
		document, other = input.Request, input.Challenge
	}
	if input.Protocol != qualificationSynapseVersion || input.RequestID == "" || len(input.RequestID) > 128 ||
		document == nil || other != nil {
		bridge.WriteError(w, http.StatusBadRequest, "version_mismatch", "only "+qualificationSynapseVersion+" requests are accepted", false)
		return input, nil, false
	}
	return input, document, true
}

func writeQualificationError(w http.ResponseWriter, err error) {
	for _, refusal := range qualificationRefusals {
		if errors.Is(err, refusal.err) {
			bridge.WriteError(w, refusal.status, refusal.err.Error(), refusal.err.Error(), refusal.retryable)
			return
		}
	}
	if code := qualification.CodeOf(err); code != "" {
		bridge.WriteError(w, http.StatusBadRequest, code, err.Error(), false)
		return
	}
	bridge.WriteError(w, http.StatusInternalServerError, "qualification_failed", err.Error(), false)
}

// qualificationJob is round one, forwarded by the miner neuron after it
// authenticated the validator (btauth/1) and checked the challenge
// identity; the runner checks the identity again against this agent.
func (a *api) qualificationJob(w http.ResponseWriter, req *http.Request) {
	input, raw, ok := a.readQualification(w, req, "challenge")
	if !ok {
		return
	}
	challenge, err := qualification.DecodeChallenge(raw)
	if err != nil {
		writeQualificationError(w, err)
		return
	}
	commitment, err := a.qualification.Commit(req.Context(), challenge, input.CallerHotkey)
	if err != nil {
		writeQualificationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, commitmentResponse{Protocol: qualificationSynapseVersion, RequestID: input.RequestID, Commitment: commitment})
}

// qualificationOpenings is round two for the held fill.
func (a *api) qualificationOpenings(w http.ResponseWriter, req *http.Request) {
	input, raw, ok := a.readQualification(w, req, "request")
	if !ok {
		return
	}
	request, err := qualification.DecodeOpeningsRequest(raw)
	if err != nil {
		writeQualificationError(w, err)
		return
	}
	openings, err := a.qualification.Open(request, input.CallerHotkey)
	if err != nil {
		writeQualificationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, openingsResponse{Protocol: qualificationSynapseVersion, RequestID: input.RequestID, Openings: openings})
}
