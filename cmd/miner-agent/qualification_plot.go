// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package main

import (
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/misscomputer/mscomputer-miner/pkg/bridge"
	"github.com/misscomputer/mscomputer-miner/pkg/qualification"
)

// qualificationPlotDisabled answers the plot routes of an agent started
// without --qualification on and --qualification-plot-dir.
const qualificationPlotDisabled = "qualification_plot_disabled"

// plotPolicy is the operator's --qualification-plot-* policy; zero values
// keep the PROVISIONAL defaults.
type plotPolicy struct {
	Dir     string
	Workers int
	MaxMiB  int
	Idle    time.Duration
	Rehash  bool
}

// validatePlotPolicy refuses plot settings without --qualification on and
// a plot directory, and out-of-range values.
func validatePlotPolicy(mode string, policy plotPolicy) error {
	if policy.Dir == "" {
		if policy != (plotPolicy{}) {
			return errors.New("--qualification-plot-* settings require --qualification-plot-dir")
		}
		return nil
	}
	if mode != "on" {
		return errors.New("--qualification-plot-dir requires --qualification on")
	}
	if policy.Workers < 0 || policy.Workers > qualification.MaxPlotWorkers || policy.MaxMiB < 0 || policy.Idle < 0 {
		return errors.New("--qualification-plot-workers, --qualification-plot-max-mib or --qualification-plot-idle is out of range")
	}
	return nil
}

type plotStatusResponse struct {
	Protocol   string                        `json:"protocol"`
	RequestID  string                        `json:"request_id"`
	State      string                        `json:"state"`
	ChunksDone int                           `json:"chunks_done"`
	Commitment *qualification.PlotCommitment `json:"commitment"`
}

type plotSealResponse struct {
	Protocol  string                 `json:"protocol"`
	RequestID string                 `json:"request_id"`
	Seal      qualification.PlotSeal `json:"seal"`
}

type plotSpotResponse struct {
	Protocol  string                 `json:"protocol"`
	RequestID string                 `json:"request_id"`
	Spot      qualification.PlotSpot `json:"spot"`
}

var plotRefusals = []struct {
	err       error
	status    int
	retryable bool
}{
	{qualification.ErrPlotSealPending, http.StatusConflict, true},
	{qualification.ErrPlotSlotsFull, http.StatusConflict, false},
	{qualification.ErrPlotWriteFailed, http.StatusInsufficientStorage, false},
	{qualification.ErrPlotReadFailed, http.StatusInternalServerError, false},
	{qualification.ErrPlotAbsent, http.StatusNotFound, false},
	{qualification.ErrPlotBuilding, http.StatusConflict, false},
	{qualification.ErrPlotDeadline, http.StatusGatewayTimeout, false},
	{qualification.ErrPlotRequestMismatch, http.StatusConflict, false},
	{qualification.ErrPlotChunkSealed, http.StatusConflict, false},
}

func writePlotError(w http.ResponseWriter, err error) {
	for _, refusal := range plotRefusals {
		if errors.Is(err, refusal.err) {
			bridge.WriteError(w, refusal.status, refusal.err.Error(), refusal.err.Error(), refusal.retryable)
			return
		}
	}
	writeQualificationError(w, err)
}

// readPlot decodes one plot envelope carrying member; it answers the
// request itself and returns false when the request is refused.
func (a *api) readPlot(w http.ResponseWriter, req *http.Request, member string) (qualificationRequest, []byte, bool) {
	var input qualificationRequest
	if a.plots == nil {
		bridge.WriteError(w, http.StatusNotImplemented, qualificationPlotDisabled, "miner qualification plots are not enabled", false)
		return input, nil, false
	}
	if err := decodeJSON(io.LimitReader(req.Body, maxQualificationRequestBytes), &input); err != nil {
		bridge.WriteError(w, http.StatusBadRequest, "invalid_request", err.Error(), false)
		return input, nil, false
	}
	document, other := input.Challenge, input.Request
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

func writePlotStatus(w http.ResponseWriter, requestID string, status qualification.PlotStatus) {
	writeJSON(w, http.StatusOK, plotStatusResponse{
		Protocol: qualificationSynapseVersion, RequestID: requestID, State: status.State, ChunksDone: status.ChunksDone,
		Commitment: status.Commitment,
	})
}

// qualificationPlot starts or resumes a plot build in the background.
func (a *api) qualificationPlot(w http.ResponseWriter, req *http.Request) {
	a.plotChallengeRoute(w, req, a.plots.Start)
}

// qualificationPlotStatus answers building (with chunks_done) or the signed
// commitment.
func (a *api) qualificationPlotStatus(w http.ResponseWriter, req *http.Request) {
	a.plotChallengeRoute(w, req, a.plots.Status)
}

func (a *api) plotChallengeRoute(w http.ResponseWriter, req *http.Request, run func(qualification.PlotChallenge, string) (qualification.PlotStatus, error)) {
	input, raw, ok := a.readPlot(w, req, "challenge")
	if !ok {
		return
	}
	challenge, err := qualification.DecodePlotChallenge(raw)
	if err != nil {
		writePlotError(w, err)
		return
	}
	status, err := run(challenge, input.CallerHotkey)
	if err != nil {
		writePlotError(w, err)
		return
	}
	writePlotStatus(w, input.RequestID, status)
}

// qualificationPlotSpot answers one spot read from disk.
func (a *api) qualificationPlotSpot(w http.ResponseWriter, req *http.Request) {
	input, raw, ok := a.readPlot(w, req, "request")
	if !ok {
		return
	}
	request, err := qualification.DecodePlotSpotRequest(raw)
	if err != nil {
		writePlotError(w, err)
		return
	}
	spot, err := a.plots.Spot(request, input.CallerHotkey)
	if err != nil {
		writePlotError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, plotSpotResponse{Protocol: qualificationSynapseVersion, RequestID: input.RequestID, Spot: spot})
}

// qualificationPlotSeal answers one seal request; the first request for a
// chunk answers the retryable qualification_plot_seal_pending; another
// request for an already sealed chunk answers qualification_plot_chunk_sealed.
func (a *api) qualificationPlotSeal(w http.ResponseWriter, req *http.Request) {
	input, raw, ok := a.readPlot(w, req, "request")
	if !ok {
		return
	}
	request, err := qualification.DecodePlotSealRequest(raw)
	if err != nil {
		writePlotError(w, err)
		return
	}
	seal, err := a.plots.Seal(request, input.CallerHotkey)
	if err != nil {
		writePlotError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, plotSealResponse{Protocol: qualificationSynapseVersion, RequestID: input.RequestID, Seal: seal})
}
