// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/misscomputer/mscomputer-miner/pkg/qualification"
)

const (
	qualificationValidator = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
	qualificationMiner     = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
)

func qualificationChallenge(id string) qualification.Challenge {
	now := time.Now().Unix()
	return qualification.Challenge{
		Schema: qualification.ChallengeSchema, Network: "finney", NetUID: 24, ValidatorHotkey: qualificationValidator,
		MinerHotkey: qualificationMiner, MinerUID: 3, ChallengeID: strings.Repeat(id, 64), Nonce: strings.Repeat("ab", 32),
		IssuedAtUnix: now, ExpiresAtUnix: now + 60, Fill: qualification.Fill{Lanes: 2, BlocksPerSlice: 4}, Openings: 2,
		PayloadBytes: 1024,
	}
}

func qualificationAPI(t *testing.T) *api {
	t.Helper()
	runner, err := openQualification("on", qualificationPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	uid := uint16(3)
	_, key, _ := ed25519.GenerateKey(nil)
	runner.Key, runner.Network, runner.NetUID, runner.Hotkey, runner.UID = key, "finney", 24, qualificationMiner, &uid
	runner.MemAvailableMiB = func() (int64, error) { return 4096, nil }
	return &api{qualification: runner}
}

func postQualification(t *testing.T, a *api, path string, body any) (*httptest.ResponseRecorder, string) {
	t.Helper()
	raw, ok := body.([]byte)
	if !ok {
		raw, _ = json.Marshal(body)
	}
	response := httptest.NewRecorder()
	a.routes().ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw)))
	var decoded struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(response.Body.Bytes(), &decoded)
	return response, decoded.Error.Code
}

func envelope(member string, document any) map[string]any {
	return map[string]any{
		"protocol": qualificationSynapseVersion, "request_id": "r1", "caller_hotkey": qualificationValidator, member: document,
	}
}

const (
	jobsPath     = "/v1/qualification/jobs"
	openingsPath = "/v1/qualification/openings"
)

func TestQualificationDisabledByDefault(t *testing.T) {
	if runner, err := openQualification("off", qualificationPolicy{}); runner != nil || err != nil {
		t.Fatalf("off = %v, %v", runner, err)
	}
	if _, err := openQualification("yes", qualificationPolicy{}); err == nil {
		t.Fatal("unknown mode accepted")
	}
	if _, err := openQualification("off", qualificationPolicy{JobsPerHour: 1}); err == nil {
		t.Fatal("a policy without --qualification on was accepted")
	}
	for _, policy := range []qualificationPolicy{{MaxFillMiB: 32769}, {MaxFillMiB: -1}, {MaxWindow: 301 * time.Second}, {JobsPerHour: -1}} {
		if _, err := openQualification("on", policy); err == nil {
			t.Fatalf("policy %+v accepted", policy)
		}
	}
	runner, err := openQualification("on", qualificationPolicy{MaxFillMiB: 1024, MaxWindow: time.Minute, JobsPerHour: 2})
	if err != nil || runner.MaxFillBlocks != 1024*64 || runner.MaxWindow != time.Minute || runner.JobsPerValidator != 2 || runner.JobsWindow != time.Hour {
		t.Fatalf("policy = %+v, %v", runner, err)
	}
	for path, member := range map[string]string{jobsPath: "challenge", openingsPath: "request"} {
		response, code := postQualification(t, &api{}, path, envelope(member, qualificationChallenge("1")))
		if response.Code != http.StatusNotImplemented || code != qualificationDisabled {
			t.Fatalf("%s disabled = %d %s", path, response.Code, response.Body)
		}
	}
}

func TestQualificationRoutes(t *testing.T) {
	a := qualificationAPI(t)
	challenge := qualificationChallenge("1")
	response, _ := postQualification(t, a, jobsPath, envelope("challenge", challenge))
	if response.Code != http.StatusOK {
		t.Fatalf("job = %d %s", response.Code, response.Body)
	}
	var round1 commitmentResponse
	if err := json.Unmarshal(response.Body.Bytes(), &round1); err != nil || round1.RequestID != "r1" {
		t.Fatalf("%v %+v", err, round1)
	}
	key := round1.Commitment.ServicePublicKey
	if err := qualification.VerifyCommitment(round1.Commitment, challenge, key); err != nil {
		t.Fatal(err)
	}
	request := qualification.OpeningsRequest{
		Schema: qualification.OpeningsRequestSchema, ChallengeID: challenge.ChallengeID,
		ChallengeSHA256: round1.Commitment.ChallengeSHA256, Root: round1.Commitment.Root, Indices: []int{5, 16},
	}
	for name, test := range map[string]struct {
		path   string
		body   any
		status int
		code   string
	}{
		"busy while held":  {jobsPath, envelope("challenge", qualificationChallenge("2")), http.StatusTooManyRequests, "qualification_busy"},
		"wrong protocol":   {jobsPath, map[string]any{"protocol": "x", "request_id": "r", "caller_hotkey": qualificationValidator, "challenge": challenge}, http.StatusBadRequest, "version_mismatch"},
		"both members":     {openingsPath, map[string]any{"protocol": qualificationSynapseVersion, "request_id": "r", "caller_hotkey": qualificationValidator, "challenge": challenge, "request": request}, http.StatusBadRequest, "version_mismatch"},
		"wrong member":     {openingsPath, envelope("challenge", challenge), http.StatusBadRequest, "version_mismatch"},
		"unknown envelope": {jobsPath, map[string]any{"protocol": qualificationSynapseVersion, "request_id": "r", "caller_hotkey": qualificationValidator, "challenge": challenge, "path": "/"}, http.StatusBadRequest, "invalid_request"},
		"unknown member":   {jobsPath, []byte(strings.Replace(mustJSON(envelope("challenge", qualificationChallenge("3"))), `"nonce"`, `"path":"/etc","nonce"`, 1)), http.StatusBadRequest, qualification.CodeChallengeInvalid},
		"bad request":      {openingsPath, envelope("request", map[string]any{"schema": "x"}), http.StatusBadRequest, qualification.CodeRequestInvalid},
		"other caller":     {openingsPath, map[string]any{"protocol": qualificationSynapseVersion, "request_id": "r", "caller_hotkey": qualificationMiner, "request": request}, http.StatusForbidden, "qualification_identity_mismatch"},
		"too large":        {jobsPath, []byte(`{"protocol":"` + strings.Repeat("x", maxQualificationRequestBytes) + `"}`), http.StatusBadRequest, "invalid_request"},
	} {
		t.Run(name, func(t *testing.T) {
			response, code := postQualification(t, a, test.path, test.body)
			if response.Code != test.status || code != test.code {
				t.Fatalf("%d %s, want %d %s", response.Code, response.Body, test.status, test.code)
			}
		})
	}
	response, _ = postQualification(t, a, openingsPath, envelope("request", request))
	if response.Code != http.StatusOK {
		t.Fatalf("openings = %d %s", response.Code, response.Body)
	}
	var round2 openingsResponse
	if err := json.Unmarshal(response.Body.Bytes(), &round2); err != nil {
		t.Fatal(err)
	}
	if err := qualification.VerifyOpenings(round2.Openings, request, round1.Commitment, challenge, key); err != nil {
		t.Fatal(err)
	}
	if response, code := postQualification(t, a, openingsPath, envelope("request", request)); response.Code != http.StatusNotFound || code != "qualification_fill_absent" {
		t.Fatalf("after budget = %d %s", response.Code, response.Body)
	}
	if response, code := postQualification(t, a, jobsPath, envelope("challenge", challenge)); response.Code != http.StatusConflict || code != "qualification_challenge_replayed" {
		t.Fatalf("replay = %d %s", response.Code, response.Body)
	}
	a.qualification.MemAvailableMiB = func() (int64, error) { return 1, nil }
	if response, code := postQualification(t, a, jobsPath, envelope("challenge", qualificationChallenge("4"))); response.Code != http.StatusServiceUnavailable || code != "qualification_memory_unavailable" {
		t.Fatalf("memory = %d %s", response.Code, response.Body)
	}
}

func mustJSON(value any) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}
