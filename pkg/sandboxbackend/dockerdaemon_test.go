// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package sandboxbackend

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// archiveEngine answers the engine's archive stat from entries (path → mode)
// and records each archive upload.
type archiveEngine struct {
	entries map[string]fs.FileMode
	puts    []archivePut
}

type archivePut struct {
	path  string
	files map[string]string
}

func (e *archiveEngine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasSuffix(r.URL.Path, "/containers/c1/archive") {
		http.NotFound(w, r)
		return
	}
	path := r.URL.Query().Get("path")
	switch r.Method {
	case http.MethodHead:
		mode, ok := e.entries[path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		raw, _ := json.Marshal(map[string]any{"name": filepath.Base(path), "mode": mode})
		w.Header().Set("X-Docker-Container-Path-Stat", base64.StdEncoding.EncodeToString(raw))
	case http.MethodPut:
		put := archivePut{path: path, files: map[string]string{}}
		tr := tar.NewReader(r.Body)
		for {
			h, err := tr.Next()
			if err != nil {
				break
			}
			data, _ := io.ReadAll(tr)
			put.files[h.Name] = string(data)
		}
		e.puts = append(e.puts, put)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func presetWith(t *testing.T, entries map[string]fs.FileMode) (bool, *archiveEngine) {
	t.Helper()
	dir, err := os.MkdirTemp("", "dd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "e.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	fake := &archiveEngine{entries: entries}
	server := &http.Server{Handler: fake}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	b := &GVisor{engine: newEngine(socket)}
	written, err := b.presetDockerDaemon(context.Background(), "c1")
	if err != nil {
		t.Fatal(err)
	}
	return written, fake
}

func TestPresetDockerDaemonWritesPoolsUnderExistingDockerDir(t *testing.T) {
	written, fake := presetWith(t, map[string]fs.FileMode{"/etc": fs.ModeDir | 0o755, "/etc/docker": fs.ModeDir | 0o755})
	if !written || len(fake.puts) != 1 || fake.puts[0].path != "/etc/docker" {
		t.Fatalf("written %v puts %+v", written, fake.puts)
	}
	var config struct {
		Pools []struct {
			Base string `json:"base"`
			Size int    `json:"size"`
		} `json:"default-address-pools"`
	}
	if err := json.Unmarshal([]byte(fake.puts[0].files["daemon.json"]), &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Pools) != 1 || config.Pools[0].Base != "10.200.0.0/14" || config.Pools[0].Size != 24 {
		t.Fatalf("pools %+v", config.Pools)
	}
	if n := 1 << (config.Pools[0].Size - 14); n < 50 {
		t.Fatalf("%d networks", n)
	}
}

func TestPresetDockerDaemonCreatesDockerDirUnderEtc(t *testing.T) {
	written, fake := presetWith(t, map[string]fs.FileMode{"/etc": fs.ModeDir | 0o755})
	if !written || len(fake.puts) != 1 || fake.puts[0].path != "/etc" {
		t.Fatalf("written %v puts %+v", written, fake.puts)
	}
	if _, ok := fake.puts[0].files["docker/"]; !ok || !bytes.Contains([]byte(fake.puts[0].files["docker/daemon.json"]), []byte("default-address-pools")) {
		t.Fatalf("files %v", fake.puts[0].files)
	}
}

func TestPresetDockerDaemonKeepsImageEntries(t *testing.T) {
	for name, entries := range map[string]map[string]fs.FileMode{
		"customer daemon.json": {"/etc": fs.ModeDir, "/etc/docker": fs.ModeDir, "/etc/docker/daemon.json": 0o644},
		"daemon.json symlink":  {"/etc": fs.ModeDir, "/etc/docker": fs.ModeDir, "/etc/docker/daemon.json": fs.ModeSymlink},
		"docker not a dir":     {"/etc": fs.ModeDir, "/etc/docker": 0o644},
		"no /etc":              {},
		"/etc not a dir":       {"/etc": fs.ModeSymlink},
	} {
		t.Run(name, func(t *testing.T) {
			if written, fake := presetWith(t, entries); written || len(fake.puts) != 0 {
				t.Fatalf("written %v puts %+v", written, fake.puts)
			}
		})
	}
}
