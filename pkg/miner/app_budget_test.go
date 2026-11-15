// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package miner

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
)

var defaultAppBudgetConfig = AppBudgetConfig{
	SystemReserveMiB: DefaultSystemReserveMiB, SandboxReserveMiB: DefaultSandboxReserveMiB,
	AppBudgetMiB: DefaultAppBudgetMiB, AppCopyMiB: DefaultAppCopyMiB,
}

func TestPlanAppBudgetScalesWithHostSize(t *testing.T) {
	for _, test := range []struct {
		memMiB, vcpus                int
		sandboxes, budgetMiB, copies int
	}{
		// The reference host: one 6 GiB sandbox reserve and a 5 GiB budget.
		{memMiB: 16384, vcpus: 4, sandboxes: 1, budgetMiB: 5120, copies: 20},
		{memMiB: 32768, vcpus: 8, sandboxes: 3, budgetMiB: 10769, copies: 42},
		{memMiB: 65536, vcpus: 16, sandboxes: 6, budgetMiB: 22068, copies: 86},
		// vCPUs bound the sandboxes; the memory they free is not given to apps
		// beyond the proportional target.
		{memMiB: 65536, vcpus: 4, sandboxes: 2, budgetMiB: 22068, copies: 86},
		// A small host keeps its one sandbox reserve before any app budget.
		{memMiB: 8192, vcpus: 2, sandboxes: 1, budgetMiB: 512, copies: 2},
		// One vCPU holds no sandbox, so apps get their proportional share.
		{memMiB: 4096, vcpus: 1, sandboxes: 0, budgetMiB: 882, copies: 3},
		// Nothing beyond the system reserve.
		{memMiB: 1536, vcpus: 4, sandboxes: 0, budgetMiB: 0, copies: 0},
	} {
		t.Run(fmt.Sprintf("%dMiB-%dvcpu", test.memMiB, test.vcpus), func(t *testing.T) {
			plan, err := PlanAppBudget(test.memMiB, test.vcpus, defaultAppBudgetConfig)
			if err != nil {
				t.Fatal(err)
			}
			if plan.Sandboxes != test.sandboxes || plan.AppBudgetMiB != test.budgetMiB || plan.AppCopies != test.copies {
				t.Fatalf("plan = %+v, want sandboxes=%d budget=%d copies=%d", plan, test.sandboxes, test.budgetMiB, test.copies)
			}
			if guaranteed := plan.SystemReserveMiB + plan.Sandboxes*plan.SandboxReserveMiB + plan.AppBudgetMiB; test.memMiB > plan.SystemReserveMiB && guaranteed > test.memMiB {
				t.Fatalf("plan overcommits the host: %d MiB of %d", guaranteed, test.memMiB)
			}
			if plan.Sandboxes > test.vcpus/2 {
				t.Fatalf("sandboxes %d exceed vcpus/2", plan.Sandboxes)
			}
		})
	}
}

func TestPlanAppBudgetFollowsFlags(t *testing.T) {
	config := defaultAppBudgetConfig
	config.AppCopyMiB = 512
	plan, err := PlanAppBudget(16384, 4, config)
	if err != nil || plan.AppCopies != 10 {
		t.Fatalf("512 MiB copies: plan=%+v err=%v", plan, err)
	}
	config = defaultAppBudgetConfig
	config.AppBudgetMiB = 2048
	if plan, err = PlanAppBudget(16384, 4, config); err != nil || plan.AppBudgetMiB != 2048 || plan.AppCopies != 8 {
		t.Fatalf("2 GiB budget: plan=%+v err=%v", plan, err)
	}
	config = defaultAppBudgetConfig
	config.SandboxReserveMiB = 10240
	if plan, err = PlanAppBudget(16384, 4, config); err != nil || plan.Sandboxes != 1 || plan.AppBudgetMiB != 16384-1536-10240 {
		t.Fatalf("10 GiB sandbox reserve must squeeze apps, not sandboxes: plan=%+v err=%v", plan, err)
	}
	for _, bad := range []AppBudgetConfig{
		{SystemReserveMiB: -1, SandboxReserveMiB: 6144, AppBudgetMiB: 5120, AppCopyMiB: 256},
		{SystemReserveMiB: 1536, SandboxReserveMiB: 0, AppBudgetMiB: 5120, AppCopyMiB: 256},
		{SystemReserveMiB: 1536, SandboxReserveMiB: 6144, AppBudgetMiB: -1, AppCopyMiB: 256},
		{SystemReserveMiB: 1536, SandboxReserveMiB: 6144, AppBudgetMiB: 5120, AppCopyMiB: 0},
		{SystemReserveMiB: ReferenceHostMemoryMiB, SandboxReserveMiB: 6144, AppBudgetMiB: 5120, AppCopyMiB: 256},
	} {
		if _, err := PlanAppBudget(16384, 4, bad); err == nil {
			t.Fatalf("config %+v accepted", bad)
		}
	}
	if _, err := PlanAppBudget(0, 4, defaultAppBudgetConfig); err == nil {
		t.Fatal("zero host memory accepted")
	}
}

func TestAppCopiesFeatureRoundTrip(t *testing.T) {
	for _, copies := range []int{0, 1, 20, 999999} {
		feature := AppCopiesFeature(copies)
		got, ok := ParseAppCopiesFeature(feature)
		if !ok || got != copies {
			t.Fatalf("%q parsed as %d %t", feature, got, ok)
		}
	}
	for _, bad := range []string{"organic-app-copies-v1.", "organic-app-copies-v1.-1", "organic-app-copies-v1.01",
		"organic-app-copies-v1.1x", "organic-app-copies-v1.1000000", "organic-app-copies-v2.4", "organic-oci-v1"} {
		if _, ok := ParseAppCopiesFeature(bad); ok {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestReserveAppCopyCountsRunningAndPendingCopies(t *testing.T) {
	agent := NewAgent("miner", nil, nil, nil, nil, nil)
	if release, err := agent.reserveAppCopy("unbudgeted"); err != nil {
		t.Fatalf("an agent without a budget refused: %v", err)
	} else {
		release()
	}
	agent.EnableAppBudget(2)
	agent.mu.Lock()
	agent.instances["running"] = "instance"
	agent.mu.Unlock()
	releasePending, err := agent.reserveAppCopy("pending")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agent.reserveAppCopy("third"); !errors.Is(err, ErrAppBudgetExhausted) {
		t.Fatalf("third copy err = %v, want ErrAppBudgetExhausted", err)
	}
	if in := agent.AppCopiesInUse(); in != 2 {
		t.Fatalf("copies in use = %d, want 2", in)
	}
	// An exact replay of a running endpoint is never refused.
	if release, err := agent.reserveAppCopy("running"); err != nil {
		t.Fatalf("replay of a running endpoint refused: %v", err)
	} else {
		release()
	}
	// A pending endpoint that starts running still counts once.
	agent.mu.Lock()
	agent.instances["pending"] = "instance"
	agent.mu.Unlock()
	if in := agent.AppCopiesInUse(); in != 2 {
		t.Fatalf("copies in use = %d, want 2", in)
	}
	releasePending()
	agent.mu.Lock()
	delete(agent.instances, "pending")
	agent.mu.Unlock()
	release, err := agent.reserveAppCopy("third")
	if err != nil {
		t.Fatalf("freed copy not reusable: %v", err)
	}
	release()

	agent.EnableAppBudget(0)
	agent.mu.Lock()
	delete(agent.instances, "running")
	agent.mu.Unlock()
	if _, err := agent.reserveAppCopy("any"); !errors.Is(err, ErrAppBudgetExhausted) {
		t.Fatalf("zero-copy budget err = %v", err)
	}
	if copies, enforced := agent.AppCopies(); copies != 0 || !enforced {
		t.Fatalf("AppCopies = %d %t", copies, enforced)
	}
}

// Over budget, an assignment is refused before admission: nothing launches,
// no receipt is signed, and the nonce stays unspent so the same ticket can
// still be accepted once a copy frees up.
func TestAssignBoundV4RefusesOverBudgetBeforeAdmission(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer server.Close()
	h := newOrganicHarness(t, server.URL)
	h.agent.HTTPClient = server.Client()
	h.agent.EnableAppBudget(1)

	first := h.ticket(t, fmt.Sprintf("%032x", 1), nil)
	ready, err := h.assign(first)
	if err != nil || ready.Receipt.Stage != protocol.StageReady {
		t.Fatalf("first assignment: %+v err=%v", ready.Receipt, err)
	}
	second := h.ticket(t, fmt.Sprintf("%032x", 2), nil)
	refused, err := h.assign(second)
	if !errors.Is(err, ErrAppBudgetExhausted) || refused.Receipt.Signature != "" {
		t.Fatalf("over-budget assignment: err=%v receipt signed=%t", err, refused.Receipt.Signature != "")
	}
	h.runtime.mu.Lock()
	launches := len(h.runtime.launches)
	h.runtime.mu.Unlock()
	if launches != 1 {
		t.Fatalf("launches = %d, want 1", launches)
	}
	if _, found, err := h.state.StoredReceiptV4(context.Background(), protocol.EndpointIDV4(second)); err != nil || found {
		t.Fatalf("refused assignment stored a receipt: found=%t err=%v", found, err)
	}
	// The exact replay of the running assignment is still answered.
	if replay, err := h.assign(first); err != nil || !replay.Idempotent {
		t.Fatalf("replay of the running assignment: %+v err=%v", replay, err)
	}
	if err := h.agent.Deactivate(context.Background(), protocol.EndpointIDV4(first)); err != nil {
		t.Fatal(err)
	}
	if accepted, err := h.assign(second); err != nil || accepted.Receipt.Stage != protocol.StageReady {
		t.Fatalf("refused ticket after a copy freed: %+v err=%v", accepted.Receipt, err)
	}
}

// A copy reserved for an assignment that fails is freed, and the replay of
// a known assignment gets its replay answer, not a capacity refusal, even
// when the budget is full.
func TestAppCopyFreedOnFailureAndReadyReplayAnsweredWhenFull(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer server.Close()
	h := newOrganicHarness(t, server.URL)
	h.agent.HTTPClient = server.Client()
	h.agent.EnableAppBudget(1)

	h.runtime.launchErr = errors.New("engine refused")
	failed := h.ticket(t, fmt.Sprintf("%032x", 1), nil)
	if result, err := h.assign(failed); err == nil || result.Receipt.Stage != protocol.StageFailed {
		t.Fatalf("failing launch: %+v err=%v", result.Receipt, err)
	}
	if in := h.agent.AppCopiesInUse(); in != 0 {
		t.Fatalf("failed assignment kept %d copies", in)
	}
	h.runtime.launchErr = nil

	first := h.ticket(t, fmt.Sprintf("%032x", 2), nil)
	ready, err := h.assign(first)
	if err != nil || ready.Receipt.Stage != protocol.StageReady {
		t.Fatalf("first assignment: %+v err=%v", ready.Receipt, err)
	}
	if err := h.agent.Deactivate(context.Background(), protocol.EndpointIDV4(first)); err != nil {
		t.Fatal(err)
	}
	second := h.ticket(t, fmt.Sprintf("%032x", 3), nil)
	if result, err := h.assign(second); err != nil || result.Receipt.Stage != protocol.StageReady {
		t.Fatalf("second assignment: %+v err=%v", result.Receipt, err)
	}
	replay, err := h.assign(first)
	if errors.Is(err, ErrAppBudgetExhausted) {
		t.Fatalf("ready replay refused as over budget: %v", err)
	}
	// The endpoint was deactivated, so its nonce is spent: replay refusal.
	if err == nil || replay.Receipt.Signature != "" || !strings.Contains(err.Error(), "replayed") {
		t.Fatalf("replay of a deactivated assignment err = %v, want the replay refusal", err)
	}
	if in := h.agent.AppCopiesInUse(); in != 1 {
		t.Fatalf("copies in use = %d, want 1", in)
	}
}
