// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package miner

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
)

// App budget defaults describe the reference miner host: 4 vCPU and
// 16 GiB of memory. Priority is sandboxes, then app sites, then plain
// (static) sites, whose file cache is separate and unchanged.
const (
	DefaultSystemReserveMiB  = 1536
	DefaultSandboxReserveMiB = 6144
	DefaultAppBudgetMiB      = 5120
	DefaultAppCopyMiB        = 256
	// DefaultAppCPUWeight is the cgroup v2 cpu.weight of the app slice. It
	// is below the default weight (100) that the sandbox lease slice and the
	// agent's own health checks run with.
	DefaultAppCPUWeight = 50
	// ReferenceHostMemoryMiB is the host size the default app budget is
	// stated for. Other hosts scale the budget by their memory left after
	// the system reserve.
	ReferenceHostMemoryMiB = 16384
)

// AppCopiesFeaturePrefix starts the capability feature that advertises how
// many app copies (deployment.v4 replicas) this miner accepts in total:
// "organic-app-copies-v1.<n>". A miner without the feature advertises no
// budget, and validators treat it conservatively.
const AppCopiesFeaturePrefix = "organic-app-copies-v1."

// ErrAppBudgetExhausted refuses an organic assignment when every app copy
// of the budget is in use. It is returned before the ticket nonce is
// admitted and before any artifact is fetched.
var ErrAppBudgetExhausted = errors.New("miner app budget is full")

// AppBudgetConfig holds the operator settings of the app budget, in MiB.
type AppBudgetConfig struct {
	SystemReserveMiB  int
	SandboxReserveMiB int
	// AppBudgetMiB is the app budget of the reference host; it scales with
	// the host's memory. Zero disables app budget accounting.
	AppBudgetMiB int
	AppCopyMiB   int
}

// AppBudgetPlan is the budget of one host.
type AppBudgetPlan struct {
	HostMemoryMiB int `json:"host_memory_mib"`
	HostVCPUs     int `json:"host_vcpus"`
	// Sandboxes is the number of sandbox reserves the host guarantees:
	// at most floor(vcpus/2), each SandboxReserveMiB.
	Sandboxes         int `json:"sandboxes"`
	SystemReserveMiB  int `json:"system_reserve_mib"`
	SandboxReserveMiB int `json:"sandbox_reserve_mib"`
	AppBudgetMiB      int `json:"app_budget_mib"`
	AppCopyMiB        int `json:"app_copy_mib"`
	AppCopies         int `json:"app_copies"`
}

// PlanAppBudget sizes the app budget of a host with memMiB of memory and
// vcpus CPUs.
//
//	target    = AppBudgetMiB * (mem - system) / (16384 - system)
//	sandboxes = min(floor((mem - system - target) / reserve), floor(vcpus/2)),
//	            raised to 1 when one reserve fits beside the system and the
//	            host has 2 vCPUs (sandboxes come first)
//	app       = min(target, mem - system - sandboxes*reserve)
//	copies    = floor(app / AppCopyMiB)
//
// On the reference host (16 GiB, 4 vCPU) with the defaults this is one
// 6 GiB sandbox reserve and a 5 GiB app budget of 20 copies.
func PlanAppBudget(memMiB, vcpus int, config AppBudgetConfig) (AppBudgetPlan, error) {
	if memMiB <= 0 || vcpus <= 0 {
		return AppBudgetPlan{}, errors.New("host memory and vCPUs must be positive")
	}
	if config.SystemReserveMiB < 0 || config.SandboxReserveMiB <= 0 || config.AppBudgetMiB < 0 || config.AppCopyMiB <= 0 {
		return AppBudgetPlan{}, errors.New("system reserve and app budget must not be negative; sandbox reserve and app copy must be positive")
	}
	if config.SystemReserveMiB >= ReferenceHostMemoryMiB {
		return AppBudgetPlan{}, fmt.Errorf("system reserve must be below the %d MiB reference host", ReferenceHostMemoryMiB)
	}
	plan := AppBudgetPlan{
		HostMemoryMiB: memMiB, HostVCPUs: vcpus, SystemReserveMiB: config.SystemReserveMiB,
		SandboxReserveMiB: config.SandboxReserveMiB, AppCopyMiB: config.AppCopyMiB,
	}
	usable := memMiB - config.SystemReserveMiB
	if usable <= 0 {
		return plan, nil
	}
	target := int(int64(config.AppBudgetMiB) * int64(usable) / int64(ReferenceHostMemoryMiB-config.SystemReserveMiB))
	sandboxes := min(max(usable-target, 0)/config.SandboxReserveMiB, vcpus/2)
	if sandboxes == 0 && usable >= config.SandboxReserveMiB && vcpus >= 2 {
		sandboxes = 1
	}
	plan.Sandboxes = sandboxes
	plan.AppBudgetMiB = max(min(target, usable-sandboxes*config.SandboxReserveMiB), 0)
	plan.AppCopies = plan.AppBudgetMiB / config.AppCopyMiB
	return plan, nil
}

// AppCopiesFeature is the capability feature advertising copies.
func AppCopiesFeature(copies int) string {
	return AppCopiesFeaturePrefix + strconv.Itoa(max(copies, 0))
}

// ParseAppCopiesFeature returns the copies a feature advertises.
func ParseAppCopiesFeature(feature string) (int, bool) {
	digits, ok := strings.CutPrefix(feature, AppCopiesFeaturePrefix)
	if !ok || digits == "" || len(digits) > 6 || (len(digits) > 1 && digits[0] == '0') {
		return 0, false
	}
	copies, err := strconv.Atoi(digits)
	if err != nil || copies < 0 {
		return 0, false
	}
	return copies, true
}

// EnableAppBudget makes the agent accept at most copies concurrent organic
// replicas. Without it, organic assignments are not counted.
func (a *Agent) EnableAppBudget(copies int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.appBudgetOn = true
	a.appCopyLimit = max(copies, 0)
	if a.appPending == nil {
		a.appPending = make(map[string]struct{})
	}
}

// AppCopies reports the app copy limit and whether a budget is enforced.
func (a *Agent) AppCopies() (int, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.appCopyLimit, a.appBudgetOn
}

// AppCopiesInUse counts the organic replicas that hold a copy: running or
// recovering endpoints plus assignments still being admitted.
func (a *Agent) AppCopiesInUse() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.appCopiesInUseLocked()
}

func (a *Agent) appCopiesInUseLocked() int {
	used := len(a.instances)
	for endpointID := range a.appPending {
		if _, running := a.instances[endpointID]; !running {
			used++
		}
	}
	return used
}

// reserveAppCopy holds one copy for endpointID until release. An endpoint
// that already holds a copy (an exact replay of a running assignment) is
// never refused.
func (a *Agent) reserveAppCopy(endpointID string) (func(), error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.appBudgetOn {
		return func() {}, nil
	}
	if _, running := a.instances[endpointID]; running {
		return func() {}, nil
	}
	if _, pending := a.appPending[endpointID]; pending {
		return func() {}, nil
	}
	if a.appCopiesInUseLocked() >= a.appCopyLimit {
		return nil, ErrAppBudgetExhausted
	}
	a.appPending[endpointID] = struct{}{}
	return func() {
		a.mu.Lock()
		delete(a.appPending, endpointID)
		a.mu.Unlock()
	}, nil
}

// knownAssignmentV4 reports whether ticket's endpoint (which embeds the
// nonce) was already admitted, so admitV4 answers its replay.
func (a *Agent) knownAssignmentV4(ctx context.Context, ticket protocol.TicketV4) (bool, error) {
	if a.State == nil {
		return false, nil
	}
	_, _, found, err := a.State.AssignmentTicketV4(ctx, protocol.EndpointIDV4(ticket))
	return found, err
}
