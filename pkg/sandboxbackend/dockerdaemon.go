// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package sandboxbackend

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"time"
)

// dockerDaemonConfig is the Docker daemon configuration a docker lease
// starts with when its image has none (docs/sandbox-docker.md). Docker's
// built-in pools give a nested engine about 31 bridge networks; a /14 cut
// into /24s gives 1024, so a compose project with 50 networks starts as is.
// It names nothing else: a directive set both here and as a dockerd flag
// stops dockerd, and the entrypoints in use (the ms dind wrapper, the
// upstream dockerd-entrypoint.sh) set no address pool flag. overlay2 is
// already the engine's default driver on the lease's tmpfs.
const dockerDaemonConfig = `{
  "default-address-pools": [
    {"base": "10.200.0.0/14", "size": 24}
  ]
}
`

// dockerDaemonConfigPath is where dockerd reads its configuration by default.
const dockerDaemonConfigPath = "/etc/docker/daemon.json"

// presetDockerDaemon writes dockerDaemonConfig into a created, never started
// docker lease container at dockerDaemonConfigPath, unless the image holds
// any entry there (a customer's own daemon.json, of any type, is never
// replaced). It writes through the engine's archive API, into the
// container's own writable layer only, and never follows an image symlink
// out of the container root. /etc/docker is created only under an existing
// /etc directory; an image without one, or with a non-directory at
// /etc/docker, is left as is. written reports whether the file was written.
func (b *GVisor) presetDockerDaemon(ctx context.Context, instanceID string) (written bool, err error) {
	archive := "/containers/" + url.PathEscape(instanceID) + "/archive"
	stat := func(path string) (mode fs.FileMode, found bool, err error) {
		resp, err := b.engine.request(ctx, http.MethodHead, archive, url.Values{"path": {path}}, nil)
		if engineStatus(err) == http.StatusNotFound {
			return 0, false, nil
		} else if err != nil {
			return 0, false, err
		}
		resp.Body.Close()
		var st struct {
			Mode fs.FileMode `json:"mode"`
		}
		raw, err := base64.StdEncoding.DecodeString(resp.Header.Get("X-Docker-Container-Path-Stat"))
		if err != nil || json.Unmarshal(raw, &st) != nil {
			return 0, false, fmt.Errorf("archive stat %s: unreadable path stat", path)
		}
		return st.Mode, true, nil
	}
	if _, found, err := stat(dockerDaemonConfigPath); err != nil || found {
		return false, err
	}
	dir, prefix := "/etc/docker", ""
	mode, found, err := stat(dir)
	if err != nil {
		return false, err
	}
	if !found {
		if mode, found, err = stat("/etc"); err != nil || !found || !mode.IsDir() {
			return false, err
		}
		dir, prefix = "/etc", "docker/"
	} else if !mode.IsDir() {
		return false, nil
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	now := time.Unix(0, 0)
	if prefix != "" {
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: prefix, Mode: 0o755, ModTime: now}); err != nil {
			return false, err
		}
	}
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: prefix + "daemon.json", Mode: 0o644, Size: int64(len(dockerDaemonConfig)), ModTime: now}); err != nil {
		return false, err
	}
	if _, err := tw.Write([]byte(dockerDaemonConfig)); err != nil {
		return false, err
	}
	if err := tw.Close(); err != nil {
		return false, err
	}
	err = b.engine.call(ctx, http.MethodPut, archive, url.Values{"path": {dir}, "noOverwriteDirNonDir": {"true"}},
		rawBody{data: buf.Bytes(), contentType: "application/x-tar"}, nil)
	if err != nil {
		return false, fmt.Errorf("sandbox %s docker daemon config: %w", instanceID, err)
	}
	return true, nil
}
