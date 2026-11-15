// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package sandboxbackend

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
	"github.com/misscomputer/mscomputer-miner/pkg/sandbox"
	"github.com/misscomputer/mscomputer-miner/pkg/sandboxhost"
)

// The docker lease end-to-end job (.github/workflows/sandbox-dind-e2e.yml)
// drives these against a real dockerd with the runsc docker runtime. They
// skip unless MC_SANDBOX_DIND_IT=1.

func dindEnv(t *testing.T, names ...string) map[string]string {
	t.Helper()
	if os.Getenv("MC_SANDBOX_DIND_IT") != "1" {
		t.Skip("MC_SANDBOX_DIND_IT is not 1")
	}
	values := map[string]string{}
	for _, name := range names {
		value := os.Getenv(name)
		if value == "" {
			t.Fatalf("%s is not set", name)
		}
		values[name] = value
	}
	return values
}

// dockerLeaseCreateBody is the exact create request the backend sends for a
// public docker lease whose image declares /var/lib/docker.
func dockerLeaseCreateBody(t *testing.T) map[string]any {
	h := newBindingHost(t)
	onBridge(h)
	b := h.backend()
	b.observeInstance = func(int, bool) []sandboxhost.Check { return nil }
	lease := testLease(func(l *protocol.SandboxLeaseV1) { dockerLeaseOf(l); publicLease(l) })
	if err := b.Create(context.Background(), instanceOf(lease), lease); err != nil {
		t.Fatal(err)
	}
	h.engine.mu.Lock()
	defer h.engine.mu.Unlock()
	if len(h.engine.created) != 1 {
		t.Fatalf("%d create requests", len(h.engine.created))
	}
	return h.engine.created[0]
}

// TestDockerLeaseOnDindHost sends the backend's docker lease create request
// to a real dockerd, with only the host-specific fields replaced (image, the
// cgroup parent and XFS quota of a provisioned host, the log driver), starts
// it and reads the security settings back from the engine.
func TestDockerLeaseOnDindHost(t *testing.T) {
	env := dindEnv(t, "MC_SANDBOX_DOCKER_HOST", "MC_SANDBOX_DIND_IMAGE", "MC_SANDBOX_DIND_NAME", "MC_SANDBOX_DIND_RUNTIME", "MC_SANDBOX_DIND_SPEC_OUT")
	body := dockerLeaseCreateBody(t)
	host := body["HostConfig"].(map[string]any)
	if host["Runtime"] != "runsc-docker" {
		t.Fatalf("docker lease runtime %v", host["Runtime"])
	}
	body["Image"] = env["MC_SANDBOX_DIND_IMAGE"]
	host["Runtime"] = env["MC_SANDBOX_DIND_RUNTIME"]
	for _, key := range []string{"CgroupParent", "StorageOpt", "LogConfig"} {
		delete(host, key)
	}
	spec := map[string]any{}
	for _, key := range []string{"Runtime", "CapAdd", "CapDrop", "SecurityOpt", "Privileged", "Mounts", "PidsLimit", "Memory", "MemorySwap", "NanoCpus", "NetworkMode", "Init", "ReadonlyRootfs", "IpcMode"} {
		spec[key] = host[key]
	}
	raw, _ := json.MarshalIndent(spec, "", "  ")
	if err := os.WriteFile(env["MC_SANDBOX_DIND_SPEC_OUT"], raw, 0o644); err != nil {
		t.Fatal(err)
	}
	e := newEngine(strings.TrimPrefix(env["MC_SANDBOX_DOCKER_HOST"], "unix://"))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	name := env["MC_SANDBOX_DIND_NAME"]
	if err := e.call(ctx, http.MethodPost, "/containers/create", url.Values{"name": {name}}, body, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.call(ctx, http.MethodPost, "/containers/"+name+"/start", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	var got struct {
		HostConfig struct {
			Runtime     string   `json:"Runtime"`
			CapAdd      []string `json:"CapAdd"`
			CapDrop     []string `json:"CapDrop"`
			SecurityOpt []string `json:"SecurityOpt"`
			Privileged  bool     `json:"Privileged"`
			PidsLimit   int64    `json:"PidsLimit"`
			Memory      int64    `json:"Memory"`
		} `json:"HostConfig"`
		Mounts []struct {
			Type, Destination string
		} `json:"Mounts"`
	}
	if err := e.call(ctx, http.MethodGet, "/containers/"+name+"/json", nil, nil, &got); err != nil {
		t.Fatal(err)
	}
	strs := func(v any) []string {
		var out []string
		for _, s := range v.([]any) {
			out = append(out, s.(string))
		}
		return out
	}
	if got.HostConfig.Runtime != host["Runtime"] || got.HostConfig.Privileged ||
		!slices.Equal(got.HostConfig.CapAdd, strs(host["CapAdd"])) || !slices.Equal(got.HostConfig.CapDrop, strs(host["CapDrop"])) ||
		!slices.Equal(got.HostConfig.SecurityOpt, strs(host["SecurityOpt"])) {
		t.Fatalf("engine applied %+v, backend asked %s", got.HostConfig, raw)
	}
	if !slices.Contains(got.HostConfig.SecurityOpt, "no-new-privileges") || !slices.Equal(got.HostConfig.CapAdd, dockerCapabilities) {
		t.Fatalf("docker lease security options %v caps %v", got.HostConfig.SecurityOpt, got.HostConfig.CapAdd)
	}
	if len(got.Mounts) != 1 || got.Mounts[0].Type != "tmpfs" || got.Mounts[0].Destination != "/var/lib/docker" {
		t.Fatalf("docker lease mounts %+v", got.Mounts)
	}
	t.Logf("backend docker lease spec on the engine: %s", raw)
}

// TestDockerLeaseBindingsOnDindHost loads the port binding table for the
// live sandboxes of a real dockerd with the backend's own resolution (veth
// peer from the sandbox's network namespace, bridge master) and nft load.
func TestDockerLeaseBindingsOnDindHost(t *testing.T) {
	env := dindEnv(t, "MC_SANDBOX_DOCKER_HOST", "MC_SANDBOX_DIND_BRIDGE", "MC_SANDBOX_DIND_SUBNET")
	b := &GVisor{
		config: Config{
			Docker: dockerProfile(),
			Egress: &sandboxhost.ProfileEgress{Bridge: env["MC_SANDBOX_DIND_BRIDGE"], Subnet: env["MC_SANDBOX_DIND_SUBNET"]},
		},
		engine: newEngine(strings.TrimPrefix(env["MC_SANDBOX_DOCKER_HOST"], "unix://")),
	}
	unbound, err := b.syncBindings(context.Background())
	if err != nil || len(unbound) != 0 {
		t.Fatalf("bindings: unbound %v, %v", unbound, err)
	}
}

// TestDockerLeaseDestroyOnDindHost removes the lease through the backend's
// Destroy, which reloads the binding table without it.
func TestDockerLeaseDestroyOnDindHost(t *testing.T) {
	env := dindEnv(t, "MC_SANDBOX_DOCKER_HOST", "MC_SANDBOX_DIND_BRIDGE", "MC_SANDBOX_DIND_SUBNET", "MC_SANDBOX_DIND_NAME")
	b := &GVisor{
		config: Config{
			Docker: dockerProfile(),
			Egress: &sandboxhost.ProfileEgress{Bridge: env["MC_SANDBOX_DIND_BRIDGE"], Subnet: env["MC_SANDBOX_DIND_SUBNET"]},
		},
		engine: newEngine(strings.TrimPrefix(env["MC_SANDBOX_DOCKER_HOST"], "unix://")),
	}
	var loaded [][]sandboxhost.PortBinding
	apply := applyTenantBindings
	t.Cleanup(func() { applyTenantBindings = apply })
	applyTenantBindings = func(e sandboxhost.ProfileEgress, bindings []sandboxhost.PortBinding) error {
		loaded = append(loaded, bindings)
		return apply(e, bindings)
	}
	if err := b.Destroy(context.Background(), env["MC_SANDBOX_DIND_NAME"]); err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 || len(loaded[0]) != 0 {
		t.Fatalf("destroy loaded binding tables %v", loaded)
	}
}

// TestDockerRuntimeRegistrationOnDindHost reads the real daemon's runtime
// registrations: the exact docker runtime is accepted, one without packet
// socket writes is refused, and a backend without the docker member refuses
// docker leases.
func TestDockerRuntimeRegistrationOnDindHost(t *testing.T) {
	env := dindEnv(t, "MC_SANDBOX_DOCKER_HOST", "MC_SANDBOX_RUNSC_PATH", "MC_SANDBOX_DIND_RUNTIME", "MC_SANDBOX_DIND_WEAK_RUNTIME")
	e := newEngine(strings.TrimPrefix(env["MC_SANDBOX_DOCKER_HOST"], "unix://"))
	var info daemonInfo
	if err := e.call(context.Background(), http.MethodGet, "/info", nil, nil, &info); err != nil {
		t.Fatal(err)
	}
	b := &GVisor{config: Config{RunscPath: env["MC_SANDBOX_RUNSC_PATH"], Docker: dockerProfile(), PIDsMax: 4096}}
	b.config.Docker.Runtime = env["MC_SANDBOX_DIND_RUNTIME"]
	if err := b.verifyDockerRuntime(info); err != nil {
		t.Fatalf("exact docker runtime refused: %v", err)
	}
	b.config.Docker.Runtime = env["MC_SANDBOX_DIND_WEAK_RUNTIME"]
	if err := b.verifyDockerRuntime(info); err == nil {
		t.Fatal("a docker runtime without --allow-packet-socket-write was accepted")
	}
	b.config.Docker = nil
	lease := testLease(dockerLeaseOf)
	if code := b.Unsupported(lease); code != sandbox.CapabilityUnsupported {
		t.Fatalf("docker lease without the docker member: %q", code)
	}
}

// standardLeaseCreateBody is the exact create request the backend sends for
// an ordinary (not docker) public lease.
func standardLeaseCreateBody(t *testing.T) map[string]any {
	h := newEgressHost(t)
	b := h.backend()
	b.observeInstance = func(int, bool) []sandboxhost.Check { return nil }
	lease := testLease(publicLease)
	if err := b.Create(context.Background(), instanceOf(lease), lease); err != nil {
		t.Fatal(err)
	}
	h.engine.mu.Lock()
	defer h.engine.mu.Unlock()
	if len(h.engine.created) != 1 {
		t.Fatalf("%d create requests", len(h.engine.created))
	}
	return h.engine.created[0]
}

// TestStandardLeaseOnDindHost sends the backend's ordinary lease create
// request to a real dockerd under runsc, with only host-specific fields
// replaced (image, runtime name, the cgroup parent and XFS quota of a
// provisioned host, and a sleeping command so execs have a live container),
// and runs the backend's own readback (verifyEngine) on what the engine
// applied: CapDrop ALL plus exactly Docker's default set, not privileged.
// The same request with a gVisor flag override annotation is refused by the
// readback. The end-to-end job then execs into the running lease.
func TestStandardLeaseOnDindHost(t *testing.T) {
	env := dindEnv(t, "MC_SANDBOX_DOCKER_HOST", "MC_SANDBOX_STD_IMAGE_ID", "MC_SANDBOX_STD_NAME", "MC_SANDBOX_STD_RUNTIME")
	body := standardLeaseCreateBody(t)
	host := body["HostConfig"].(map[string]any)
	if host["Privileged"] != false || fmt.Sprint(host["CapDrop"]) != "[ALL]" || fmt.Sprint(host["CapAdd"]) != fmt.Sprint(dockerDefaultCapabilities) {
		t.Fatalf("standard lease Privileged %v CapDrop %v CapAdd %v", host["Privileged"], host["CapDrop"], host["CapAdd"])
	}
	imageID := env["MC_SANDBOX_STD_IMAGE_ID"]
	body["Image"] = imageID
	body["Cmd"] = []string{"sleep", "infinity"}
	body["Labels"].(map[string]any)[LabelImageID] = imageID
	host["Runtime"] = env["MC_SANDBOX_STD_RUNTIME"]
	raw, _ := json.Marshal(host)
	var want hostConfig
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	labels := map[string]string{}
	for k, v := range body["Labels"].(map[string]any) {
		labels[k] = v.(string)
	}
	s := spec{labels: labels, host: want}
	for _, key := range []string{"CgroupParent", "StorageOpt"} {
		delete(host, key)
	}
	e := newEngine(strings.TrimPrefix(env["MC_SANDBOX_DOCKER_HOST"], "unix://"))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	readback := func(name string) inspectedContainer {
		var got inspectedContainer
		if err := e.call(ctx, http.MethodGet, "/containers/"+name+"/json", nil, nil, &got); err != nil {
			t.Fatal(err)
		}
		// The two provisioned-host fields this runner cannot apply.
		got.HostConfig.CgroupParent, got.HostConfig.StorageOpt = want.CgroupParent, want.StorageOpt
		return got
	}
	b := newEgressHost(t).backend()

	name := env["MC_SANDBOX_STD_NAME"]
	if err := e.call(ctx, http.MethodPost, "/containers/create", url.Values{"name": {name}}, body, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.call(ctx, http.MethodPost, "/containers/"+name+"/start", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	got := readback(name)
	if err := b.verifyEngine(got, s); err != nil {
		t.Fatalf("backend readback refused the engine's standard lease: %v", err)
	}
	if got.HostConfig.Privileged || !sameSet(got.HostConfig.CapAdd, dockerDefaultCapabilities) || !slices.Equal(got.HostConfig.CapDrop, []string{"ALL"}) ||
		!slices.Contains(got.HostConfig.SecurityOpt, "no-new-privileges") {
		t.Fatalf("engine applied Privileged %v CapAdd %v CapDrop %v SecurityOpt %v", got.HostConfig.Privileged, got.HostConfig.CapAdd, got.HostConfig.CapDrop, got.HostConfig.SecurityOpt)
	}
	t.Logf("engine readback accepted: Privileged=%v CapDrop=%v CapAdd=%v SecurityOpt=%v", got.HostConfig.Privileged, got.HostConfig.CapDrop, got.HostConfig.CapAdd, got.HostConfig.SecurityOpt)

	annotated := name + "-annotated"
	host["Annotations"] = map[string]string{"dev.gvisor.flag.network": "host"}
	if err := e.call(ctx, http.MethodPost, "/containers/create", url.Values{"name": {annotated}}, body, nil); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = e.call(context.Background(), http.MethodDelete, "/containers/"+annotated, url.Values{"force": {"1"}}, nil, nil)
	}()
	bad := readback(annotated)
	if len(bad.HostConfig.Annotations) == 0 {
		t.Fatal("engine dropped the annotation; the refusal is not exercised")
	}
	err := b.verifyEngine(bad, s)
	if err == nil || !strings.Contains(err.Error(), "host settings") {
		t.Fatalf("backend readback of an annotated sandbox: %v, want a host settings refusal", err)
	}
	t.Logf("annotation override refused: %v", err)
}
