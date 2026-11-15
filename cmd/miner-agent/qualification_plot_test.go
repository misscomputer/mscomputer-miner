// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/misscomputer/mscomputer-miner/pkg/qualification"
)

const (
	plotsPath      = "/v1/qualification/plots"
	plotStatusPath = "/v1/qualification/plots/status"
	plotSpotsPath  = "/v1/qualification/plot-spots"
	plotSealsPath  = "/v1/qualification/plot-seals"
)

func plotChallenge() qualification.PlotChallenge {
	now := time.Now().Unix()
	return qualification.PlotChallenge{
		Schema: qualification.PlotChallengeSchema, Network: "finney", NetUID: 24, ValidatorHotkey: qualificationValidator,
		MinerHotkey: qualificationMiner, MinerUID: 3, PlotID: strings.Repeat("c1", 32), Seed: strings.Repeat("d2", 32),
		Chunks: 2, ChunkBlocksPerSlice: 2, IssuedAtUnix: now, BuildExpiresAtUnix: now + 600,
	}
}

func plotAPI(t *testing.T) (*api, ed25519.PublicKey) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	public, key, _ := ed25519.GenerateKey(nil)
	uid := uint16(3)
	plots, err := qualification.OpenPlots(qualification.PlotConfig{
		Dir: dir, Key: key, Network: "finney", NetUID: 24, Hotkey: qualificationMiner, UID: &uid,
		MemAvailableMiB: func() (int64, error) { return 4096, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(plots.Close)
	return &api{plots: plots}, public
}

func TestPlotSettingsRequireQualificationAndADirectory(t *testing.T) {
	if err := validatePlotPolicy("off", plotPolicy{}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		mode   string
		policy plotPolicy
	}{
		{"off", plotPolicy{Dir: "/plots"}},
		{"on", plotPolicy{Workers: 2}},
		{"on", plotPolicy{Dir: "/plots", Workers: qualification.MaxPlotWorkers + 1}},
		{"on", plotPolicy{Dir: "/plots", MaxMiB: -1}},
	} {
		if validatePlotPolicy(tc.mode, tc.policy) == nil {
			t.Fatalf("%+v accepted", tc)
		}
	}
	if err := validatePlotPolicy("on", plotPolicy{Dir: "/plots", Workers: 4}); err != nil {
		t.Fatal(err)
	}
}

func TestPlotRoutesAreDisabledWithoutAPlotDirectory(t *testing.T) {
	a := qualificationAPI(t)
	for _, path := range []string{plotsPath, plotStatusPath, plotSpotsPath, plotSealsPath} {
		if response, code := postQualification(t, a, path, envelope("challenge", plotChallenge())); response.Code != http.StatusNotImplemented ||
			code != qualificationPlotDisabled {
			t.Fatalf("%s: %d %s", path, response.Code, code)
		}
	}
}

func TestPlotRoutesBuildAndAnswerOneSpot(t *testing.T) {
	a, public := plotAPI(t)
	c := plotChallenge()
	if response, code := postQualification(t, a, plotsPath, envelope("request", c)); response.Code != http.StatusBadRequest ||
		code != "version_mismatch" {
		t.Fatalf("wrong member: %d %s", response.Code, code)
	}
	if response, _ := postQualification(t, a, plotsPath, envelope("challenge", c)); response.Code != http.StatusOK {
		t.Fatalf("start: %d %s", response.Code, response.Body)
	}
	var status struct {
		State      string                        `json:"state"`
		ChunksDone int                           `json:"chunks_done"`
		Commitment *qualification.PlotCommitment `json:"commitment"`
	}
	for deadline := time.Now().Add(10 * time.Second); status.State != qualification.PlotComplete; time.Sleep(2 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("plot did not complete")
		}
		response, _ := postQualification(t, a, plotStatusPath, envelope("challenge", c))
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &status) != nil {
			t.Fatalf("status: %d %s", response.Code, response.Body)
		}
		if (status.State == qualification.PlotBuilding) != (status.Commitment == nil) {
			t.Fatalf("status %+v", status)
		}
	}
	bound := hex.EncodeToString(public)
	if err := qualification.VerifyPlotCommitment(*status.Commitment, c, bound); err != nil || status.ChunksDone != c.Chunks {
		t.Fatalf("commitment: %v", err)
	}
	request := qualification.PlotSpotRequest{
		Schema: qualification.PlotSpotRequestSchema, PlotID: c.PlotID, PlotChallengeSHA256: status.Commitment.PlotChallengeSHA256,
		Root: status.Commitment.Root, RequestID: strings.Repeat("e3", 32),
		Picks: []qualification.PlotPick{{Chunk: 1, Index: 5}, {Chunk: 0, Index: 0}},
	}
	response, _ := postQualification(t, a, plotSpotsPath, envelope("request", request))
	var answer struct {
		Spot qualification.PlotSpot `json:"spot"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &answer) != nil {
		t.Fatalf("spot: %d %s", response.Code, response.Body)
	}
	if err := qualification.VerifyPlotSpot(answer.Spot, request, *status.Commitment, c, bound); err != nil {
		t.Fatal(err)
	}
	// The seal: pending (retryable) while the chunk is recomputed, then answered.
	sealRequest := qualification.PlotSealRequest{
		Schema: qualification.PlotSealRequestSchema, PlotID: c.PlotID, PlotChallengeSHA256: status.Commitment.PlotChallengeSHA256,
		Root: status.Commitment.Root, RequestID: strings.Repeat("e4", 32), Chunk: 1, Openings: []qualification.PlotSealPoint{{Layer: 3, Index: 0}, {Layer: qualification.PlotLayers - 1, Index: 7}},
	}
	var sealed struct {
		Seal qualification.PlotSeal `json:"seal"`
	}
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
		response, code := postQualification(t, a, plotSealsPath, envelope("request", sealRequest))
		if code == qualification.ErrPlotSealPending.Error() && response.Code == http.StatusConflict && time.Now().Before(deadline) {
			continue
		}
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &sealed) != nil {
			t.Fatalf("seal: %d %s", response.Code, response.Body)
		}
		break
	}
	if err := qualification.VerifyPlotSeal(sealed.Seal, sealRequest, *status.Commitment, c, bound); err != nil {
		t.Fatal(err)
	}
	other := c
	other.ValidatorHotkey = qualificationMiner
	other.PlotID = strings.Repeat("c2", 32)
	if response, code := postQualification(t, a, plotsPath, map[string]any{
		"protocol": qualificationSynapseVersion, "request_id": "r2", "caller_hotkey": qualificationMiner, "challenge": other,
	}); response.Code != http.StatusConflict || code != qualification.ErrPlotSlotsFull.Error() {
		t.Fatalf("second validator: %d %s", response.Code, code)
	}
	request.Picks = []qualification.PlotPick{{Chunk: 0, Index: c.ChunkBlocksPerSlice * 4}}
	if response, code := postQualification(t, a, plotSpotsPath, envelope("request", request)); response.Code != http.StatusConflict ||
		code != qualification.ErrPlotRequestMismatch.Error() {
		t.Fatalf("index outside: %d %s", response.Code, code)
	}
}
