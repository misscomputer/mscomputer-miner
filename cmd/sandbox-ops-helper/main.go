// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

// Command sandbox-ops-helper is the in-sandbox helper of sandbox-ops-v1.
// A miner backend
// runs it with docker exec at the fixed path /.mscomputer/sandbox-ops-helper,
// as the image's default user, with the image's environment and no TTY. It reads
// one bounded request (pkg/sandboxops) on stdin, performs one file or exec
// operation inside the sandbox, writes one bounded response on stdout, and
// exits.
//
// It keeps only PATH from that environment, as its execs' search path, and
// has no flags, configuration files, network or other environment-driven
// behavior. File operations resolve through fsroot (openat2 in-root from "/").
// An exec runs under a supervisor process the helper starts in its own
// session; the supervisor captures each stream's first max_output_bytes under
// /tmp/.mscomputer-ops/<exec_id>, enforces the exec deadline, and kills the
// exec's process group on cancel. Only in keepalive mode, which the miner
// opts into, is the helper the sandbox's PID 1: it runs the image's own
// command as its child and keeps the sandbox running after it exits.
package main

import (
	"os"

	"github.com/misscomputer/mscomputer-miner/pkg/sandboxops"
)

// superviseArg is the internal first argument that turns a helper process
// started by the helper itself into an exec supervisor:
// supervise <capture root> <exec id>. The miner never passes arguments.
const superviseArg = "supervise"

func main() {
	if len(os.Args) == 4 && os.Args[1] == superviseArg {
		os.Exit(supervise(os.Args[2], os.Args[3]))
	}
	if len(os.Args) >= 2 && os.Args[1] == sandboxops.KeepaliveArg {
		os.Exit(keepalive(os.Args[2:]))
	}
	if len(os.Args) != 1 {
		os.Exit(2)
	}
	scrubEnvironment()
	os.Exit(serveProcess(os.Stdin, os.Stdout))
}
