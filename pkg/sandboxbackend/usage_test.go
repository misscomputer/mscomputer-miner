// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package sandboxbackend

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/misscomputer/mscomputer-miner/pkg/miner"
)

const testNetDev = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:     500       5    0    0    0     0          0         0      500       5    0    0    0     0       0          0
  eth0:    1000      10    0    0    0     0          0         0      234       3    0    0    0     0       0          0
`

func usageBackend(t *testing.T, inspect string) *GVisor {
	t.Helper()
	dir, err := os.MkdirTemp("", "us")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	proc, cgroups := filepath.Join(dir, "proc"), filepath.Join(dir, "cg")
	leaf := filepath.Join(cgroups, "mc.slice", "docker-x.scope")
	for _, d := range []string{filepath.Join(proc, "42", "net"), leaf} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		filepath.Join(proc, "42", "cgroup"):     "0::/mc.slice/docker-x.scope\n",
		filepath.Join(proc, "42", "net", "dev"): testNetDev,
		filepath.Join(leaf, "cpu.stat"):         "usage_usec 2500000\nuser_usec 2000000\n",
		filepath.Join(leaf, "memory.peak"):      "7340032\n",
	}
	for name, content := range files {
		if err := os.WriteFile(name, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	socket := filepath.Join(dir, "e.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/containers/s1/json") || r.URL.Query().Get("size") != "true" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(inspect))
	})}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	b := &GVisor{engine: newEngine(socket), sliceCgroup: "/mc.slice"}
	b.config.ProcRoot, b.config.CgroupRoot = proc, cgroups
	return b
}

func TestUsageReadsCgroupNetworkAndWritableLayer(t *testing.T) {
	b := usageBackend(t, `{"SizeRw":12345,"State":{"Running":true,"Pid":42}}`)
	u, err := b.Usage(context.Background(), "s1")
	if err != nil {
		t.Fatal(err)
	}
	if u.CPUSeconds == nil || *u.CPUSeconds != 2.5 || u.MemoryPeakBytes == nil || *u.MemoryPeakBytes != 7340032 ||
		u.DiskBytes == nil || *u.DiskBytes != 12345 || u.NetworkBytes == nil || *u.NetworkBytes != 1234 {
		t.Fatalf("usage %+v", u)
	}
}

func TestUsageOfAStoppedOrMissingSandboxIsNotRunning(t *testing.T) {
	b := usageBackend(t, `{"State":{"Running":false,"Pid":0}}`)
	if _, err := b.Usage(context.Background(), "s1"); !errors.Is(err, miner.ErrSandboxNotRunning) {
		t.Fatalf("stopped: %v", err)
	}
	if _, err := b.Usage(context.Background(), "other"); !errors.Is(err, miner.ErrSandboxNotRunning) {
		t.Fatalf("missing: %v", err)
	}
}

func TestUsageLeavesUnreadableMembersNull(t *testing.T) {
	b := usageBackend(t, `{"State":{"Running":true,"Pid":42}}`)
	b.sliceCgroup = "/other.slice" // the process is outside the slice
	u, err := b.Usage(context.Background(), "s1")
	if err != nil {
		t.Fatal(err)
	}
	if u.CPUSeconds != nil || u.MemoryPeakBytes != nil || u.DiskBytes != nil || u.NetworkBytes == nil {
		t.Fatalf("usage %+v", u)
	}
}
