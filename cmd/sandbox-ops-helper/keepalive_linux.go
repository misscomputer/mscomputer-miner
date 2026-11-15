// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

// keepalive is the sandbox's PID 1 when the miner runs the helper's
// keepalive mode (--sandbox-ops-config "helper_keepalive"): it starts the
// image's own command, if any, as its child with the image's environment,
// user and working directory, and stays alive after that command exits, so
// the sandbox keeps running for ops as a sandbox product's does. It reaps
// every child reparented to it, including the exec supervisors the helper
// leaves behind. SIGTERM, SIGINT, SIGHUP and SIGQUIT are forwarded to the
// image command while it runs, and keepalive ends once that command has
// exited after one, so it keeps the engine's stop grace; with no image
// command running, such a signal ends keepalive at once.
func keepalive(argv []string) int {
	signals := make(chan os.Signal, 16)
	signal.Notify(signals, syscall.SIGCHLD, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT)
	child := 0
	if len(argv) != 0 {
		path, err := exec.LookPath(argv[0])
		if err == nil {
			var process *os.Process
			process, err = os.StartProcess(path, argv, &os.ProcAttr{
				Env: os.Environ(), Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
			})
			if err == nil {
				child = process.Pid
				// The pid is reaped below with every other child.
				_ = process.Release()
			}
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "sandbox keepalive: image command did not start: %v\n", err)
		}
	}
	stopping := false
	for received := range signals {
		if received == syscall.SIGCHLD {
			child = reapAll(child)
		} else if child != 0 {
			stopping = true
			_ = syscall.Kill(child, received.(syscall.Signal))
		} else {
			return 0
		}
		if stopping && child == 0 {
			// The image command had the engine's stop grace to end.
			return 0
		}
	}
	return 0
}

// reapAll reaps every exited child without blocking and returns child, or 0
// once it was reaped.
func reapAll(child int) int {
	for {
		var status syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &status, syscall.WNOHANG, nil)
		if pid <= 0 || err != nil {
			return child
		}
		if pid == child {
			child = 0
		}
	}
}
