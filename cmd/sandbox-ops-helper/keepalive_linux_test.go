// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

//go:build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/misscomputer/mscomputer-miner/pkg/sandboxops"
)

// startKeepalive runs this test binary as the helper in keepalive mode with
// the image argv, in the image's environment and working directory.
type keepaliveRun struct {
	cmd  *exec.Cmd
	done chan struct{}
}

func startKeepalive(t *testing.T, dir string, argv ...string) *keepaliveRun {
	t.Helper()
	cmd := exec.Command("/proc/self/exe", append([]string{sandboxops.KeepaliveArg}, argv...)...)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=/usr/bin:/bin", "IMAGE_ENV=kept"}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	run := &keepaliveRun{cmd: cmd, done: make(chan struct{})}
	go func() { _ = cmd.Wait(); close(run.done) }()
	t.Cleanup(func() { _ = cmd.Process.Kill(); <-run.done })
	return run
}

func waitExit(t *testing.T, run *keepaliveRun, within time.Duration) (exited bool, code int) {
	t.Helper()
	select {
	case <-run.done:
		return true, run.cmd.ProcessState.ExitCode()
	case <-time.After(within):
		return false, 0
	}
}

// The image's own command runs with the image's environment and working
// directory, and keepalive outlives it: a sandbox whose command exits
// (python3 without stdin) keeps running. A stop signal ends keepalive.
func TestKeepaliveOutlivesTheImageCommand(t *testing.T) {
	dir := t.TempDir()
	run := startKeepalive(t, dir, "sh", "-c", `printf "%s %s" "$IMAGE_ENV" "$PWD" > ran`)
	deadline := time.Now().Add(5 * time.Second)
	var got []byte
	for time.Now().Before(deadline) {
		if got, _ = os.ReadFile(filepath.Join(dir, "ran")); len(got) != 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if want := "kept " + dir; string(got) != want {
		t.Fatalf("image command wrote %q, want %q", got, want)
	}
	if exited, code := waitExit(t, run, time.Second); exited {
		t.Fatalf("keepalive exited %d after the image command ended", code)
	}
	if err := run.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if exited, code := waitExit(t, run, 5*time.Second); !exited || code != 0 {
		t.Fatalf("keepalive after SIGTERM: exited %v code %d, want exit 0", exited, code)
	}
}

// A stop signal reaches the image's command while it runs, and keepalive
// waits for that command to end.
func TestKeepaliveForwardsStopToTheImageCommand(t *testing.T) {
	dir := t.TempDir()
	run := startKeepalive(t, dir, "sh", "-c", `trap 'sleep 0.3; echo term > got; exit 0' TERM; echo up > up; while :; do sleep 0.05; done`)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(dir, "up")); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := run.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if exited, _ := waitExit(t, run, 5*time.Second); !exited {
		t.Fatal("keepalive did not end on SIGTERM")
	}
	// Keepalive ends only after the image command finished its shutdown.
	if got, _ := os.ReadFile(filepath.Join(dir, "got")); strings.TrimSpace(string(got)) != "term" {
		t.Fatalf("keepalive ended before the image command's shutdown finished (got %q)", got)
	}
}

// An image command that cannot start leaves the sandbox running.
func TestKeepaliveSurvivesAnUnstartableCommand(t *testing.T) {
	run := startKeepalive(t, t.TempDir(), "/no/such/command")
	if exited, code := waitExit(t, run, time.Second); exited {
		t.Fatalf("keepalive exited %d when the image command could not start", code)
	}
}
