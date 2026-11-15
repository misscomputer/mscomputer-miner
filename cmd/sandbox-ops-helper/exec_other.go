// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

//go:build !linux

package main

import (
	"github.com/misscomputer/mscomputer-miner/pkg/sandbox"
	"github.com/misscomputer/mscomputer-miner/pkg/sandboxops"
)

const selfExecutable = ""

func scrubEnvironment() {}

// The helper runs only inside a Linux sandbox; elsewhere every exec op is
// ops_unsupported, as file ops are through fsroot.
type unsupportedExecs struct{}

func newExecRunner(string, string) execRunner { return unsupportedExecs{} }

func (unsupportedExecs) start(string, sandboxops.ExecSpec) sandboxops.Response { return unsupported() }
func (unsupportedExecs) read(string, string, uint64, uint64) sandboxops.Response {
	return unsupported()
}
func (unsupportedExecs) cancel(string, bool) sandboxops.Response { return unsupported() }
func (unsupportedExecs) status(string) sandboxops.Response       { return unsupported() }

func unsupported() sandboxops.Response { return sandboxops.Failure(sandbox.OpCodeOpsUnsupport) }

func supervise(string, string) int { return 2 }

func keepalive([]string) int { return 2 }
