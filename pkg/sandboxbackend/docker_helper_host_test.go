// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package sandboxbackend

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

// dockerDefaultCapabilities is Docker's default capability set
// (moby oci/caps DefaultCapabilities), written out independently of the
// backend so a change to sandboxCapabilities must change this test too.
var dockerDefaultCapabilities = []string{
	"AUDIT_WRITE", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "MKNOD", "NET_BIND_SERVICE",
	"NET_RAW", "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_CHROOT",
}

// TestSandboxCapabilitiesAreDockerDefault: every lease's processes get
// exactly Docker's default set inside the sentry, nothing more.
func TestSandboxCapabilitiesAreDockerDefault(t *testing.T) {
	if !sameSet(sandboxCapabilities, dockerDefaultCapabilities) {
		t.Fatalf("sandbox capabilities %v, want Docker's default set %v", sandboxCapabilities, dockerDefaultCapabilities)
	}
}

// TestDockerCapabilitiesExtendTheSandboxSet: a docker lease keeps every
// capability an ordinary lease has and adds only what a nested engine needs.
func TestDockerCapabilitiesExtendTheSandboxSet(t *testing.T) {
	if len(dockerCapabilities) <= len(sandboxCapabilities) {
		t.Fatalf("docker capabilities %v are not a strict superset of %v", dockerCapabilities, sandboxCapabilities)
	}
	for _, capability := range sandboxCapabilities {
		if !slices.Contains(dockerCapabilities, capability) {
			t.Fatalf("docker leases lack %s, which every lease has", capability)
		}
	}
	for _, capability := range []string{"SYS_ADMIN", "NET_ADMIN"} {
		if !slices.Contains(dockerCapabilities, capability) {
			t.Fatalf("docker leases lack %s", capability)
		}
	}
}

// TestDockerOpsLeaseOnDindHost starts a docker lease with the ops helper
// mount (the backend's docker lease create request plus helperMount, the
// one mount ops mode adds) so the end-to-end job can try, with the lease's
// sentry-virtual SYS_ADMIN, to make the read-only helper writable. The host
// directory MC_SANDBOX_DIND_HELPER_DIR is a read-only bind the job prepares.
func TestDockerOpsLeaseOnDindHost(t *testing.T) {
	env := dindEnv(t, "MC_SANDBOX_DOCKER_HOST", "MC_SANDBOX_DIND_IMAGE", "MC_SANDBOX_DIND_OPS_NAME", "MC_SANDBOX_DIND_RUNTIME", "MC_SANDBOX_DIND_HELPER_DIR")
	body := dockerLeaseCreateBody(t)
	host := body["HostConfig"].(map[string]any)
	body["Image"] = env["MC_SANDBOX_DIND_IMAGE"]
	host["Runtime"] = env["MC_SANDBOX_DIND_RUNTIME"]
	for _, key := range []string{"CgroupParent", "StorageOpt", "LogConfig"} {
		delete(host, key)
	}
	helper := &OpsHelper{Dir: env["MC_SANDBOX_DIND_HELPER_DIR"]}
	want := spec{helper: helper}
	for _, m := range host["Mounts"].([]any) {
		volume := m.(map[string]any)
		want.volumes = append(want.volumes, volume["Target"].(string))
		want.tmpfsBytes = int64(volume["TmpfsOptions"].(map[string]any)["SizeBytes"].(float64))
	}
	host["Mounts"] = append(host["Mounts"].([]any), helperMount(helper))
	e := newEngine(strings.TrimPrefix(env["MC_SANDBOX_DOCKER_HOST"], "unix://"))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	name := env["MC_SANDBOX_DIND_OPS_NAME"]
	if err := e.call(ctx, http.MethodPost, "/containers/create", url.Values{"name": {name}}, body, nil); err != nil {
		t.Fatal(err)
	}
	var created inspectedContainer
	if err := e.call(ctx, http.MethodGet, "/containers/"+name+"/json", nil, nil, &created); err != nil {
		t.Fatal(err)
	}
	if err := verifyVolumeMounts(created, want); err != nil {
		t.Fatalf("helper mount readback: %v", err)
	}
	if err := e.call(ctx, http.MethodPost, "/containers/"+name+"/start", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
}
