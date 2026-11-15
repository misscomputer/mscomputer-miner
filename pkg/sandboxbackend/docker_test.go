// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package sandboxbackend

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
	"github.com/misscomputer/mscomputer-miner/pkg/sandbox"
	"github.com/misscomputer/mscomputer-miner/pkg/sandboxhost"
)

const testImageKey = "docker.io/library/busybox@" + testImageDigest

func dockerProfile() *sandboxhost.ProfileDocker {
	return &sandboxhost.ProfileDocker{Runtime: "runsc-docker", Args: slices.Clone(sandboxhost.DockerRuntimeArgs), VolumeTmpfsMiB: 4096}
}

func dockerLeaseOf(l *protocol.SandboxLeaseV1) { l.Capabilities = []string{sandbox.CapabilityDocker} }

// dockerHost is a scripted host whose profile has docker, whose image
// declares /var/lib/docker, and whose engine applies tmpfs mounts the way
// dockerd reports them.
func dockerHost(t *testing.T) *host {
	h := newHost(t)
	h.config.Docker = dockerProfile()
	image := h.engine.catalog[testImageKey]
	image.Volumes = map[string]any{"/var/lib/docker": map[string]any{}}
	h.engine.catalog[testImageKey] = image
	h.engine.applied = tmpfsAsAsked
	return h
}

func tmpfsAsAsked(c *engineContainer) {
	requested, _ := c.Host["Mounts"].([]any)
	for _, raw := range requested {
		m := raw.(map[string]any)
		if m["Type"] == "tmpfs" {
			c.Mounts = append(c.Mounts, map[string]any{"Type": "tmpfs", "Source": "", "Destination": m["Target"], "RW": true, "Propagation": ""})
		}
	}
}

func TestDockerLeaseRunsUnderTheDockerRuntimeWithTmpfsVolumes(t *testing.T) {
	h := dockerHost(t)
	b := h.backend()
	if !b.DockerEnabled() {
		t.Fatal("backend with a docker profile does not report docker")
	}
	lease := testLease(dockerLeaseOf)
	if err := b.Create(context.Background(), instanceOf(lease), lease); err != nil {
		t.Fatal(err)
	}
	if len(h.engine.created) != 1 {
		t.Fatalf("created %d containers", len(h.engine.created))
	}
	hostConfig := h.engine.created[0]["HostConfig"].(map[string]any)
	if hostConfig["Runtime"] != "runsc-docker" || hostConfig["Privileged"] != false ||
		fmt.Sprint(hostConfig["CapDrop"]) != "[ALL]" || fmt.Sprint(hostConfig["SecurityOpt"]) != "[no-new-privileges]" {
		t.Fatalf("docker host config %v", hostConfig)
	}
	if got := fmt.Sprint(hostConfig["CapAdd"]); got != fmt.Sprint(dockerCapabilities) || len(dockerCapabilities) != 17 {
		t.Fatalf("CapAdd %s", got)
	}
	for _, capability := range dockerCapabilities {
		if capability == "SYS_MODULE" || capability == "SYS_RAWIO" || capability == "SYS_TIME" || capability == "SYS_BOOT" {
			t.Fatalf("docker capability set holds %s", capability)
		}
	}
	mounts := fmt.Sprint(hostConfig["Mounts"])
	if mounts != "[map[ReadOnly:false Target:/var/lib/docker TmpfsOptions:map[SizeBytes:1.073741824e+09] Type:tmpfs]]" {
		t.Fatalf("mounts %s (tmpfs capped at the lease's 1024 MiB)", mounts)
	}
}

// A lease without capabilities on a docker host is byte-for-byte the lease
// of a host without docker.
func TestDockerHostLeavesOtherLeasesUnchanged(t *testing.T) {
	plain, docker := newHost(t), newHost(t)
	docker.config.Docker = dockerProfile()
	lease := testLease(nil)
	for _, h := range []*host{plain, docker} {
		if err := h.backend().Create(context.Background(), instanceOf(lease), lease); err != nil {
			t.Fatal(err)
		}
	}
	a, b := fmt.Sprint(plain.engine.created[0]), fmt.Sprint(docker.engine.created[0])
	if a != b || !strings.Contains(a, "Runtime:runsc ") || strings.Contains(a, "Mounts") {
		t.Fatalf("create bodies differ:\n%s\n%s", a, b)
	}
	// An image volume is still refused for a lease without docker.
	h := dockerHost(t)
	if err := h.backend().Create(context.Background(), instanceOf(lease), lease); refusalCode(err) != "resources_unsupported" {
		t.Fatalf("volume image without docker: %v", err)
	}
}

func TestDockerLeaseRefusedWithoutTheDockerProfile(t *testing.T) {
	h := newHost(t)
	b := h.backend()
	if b.DockerEnabled() {
		t.Fatal("backend without docker reports docker")
	}
	lease := testLease(dockerLeaseOf)
	if code := b.Unsupported(lease); code != sandbox.CapabilityUnsupported {
		t.Fatalf("unsupported %q", code)
	}
	if err := b.Create(context.Background(), instanceOf(lease), lease); refusalCode(err) != sandbox.CapabilityUnsupported || len(h.engine.created) != 0 {
		t.Fatalf("create %v", err)
	}
	if attributed, known := sandbox.ReceiptErrorAttribution[sandbox.CapabilityUnsupported]; !known || attributed {
		t.Fatal("capability_unsupported must be a known non-fault code")
	}
	if code := dockerHostBackend(t).Unsupported(testLease(func(l *protocol.SandboxLeaseV1) { l.Capabilities = []string{"gpu"} })); code != sandbox.CapabilityUnsupported {
		t.Fatalf("unknown capability: %q", code)
	}
}

func dockerHostBackend(t *testing.T) *GVisor { return dockerHost(t).backend() }

func TestDockerLeaseRefusesUncoverableVolumes(t *testing.T) {
	for name, volumes := range map[string]map[string]any{
		"helper target": {"/.mscomputer": nil},
		"proc":          {"/proc/x": nil},
		"etc":           {"/etc": nil},
		"relative":      {"var/lib": nil},
		"unclean":       {"/var/../lib": nil},
		"colon":         {"/a:b": nil},
		"too many": {"/v1": nil, "/v2": nil, "/v3": nil, "/v4": nil, "/v5": nil, "/v6": nil, "/v7": nil, "/v8": nil,
			"/v9": nil},
	} {
		h := dockerHost(t)
		image := h.engine.catalog[testImageKey]
		image.Volumes = volumes
		h.engine.catalog[testImageKey] = image
		lease := testLease(dockerLeaseOf)
		if err := h.backend().Create(context.Background(), instanceOf(lease), lease); refusalCode(err) != "resources_unsupported" || len(h.engine.created) != 0 {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestDockerReadbackRefusesOtherMounts(t *testing.T) {
	for name, applied := range map[string]func(*engineContainer){
		"no tmpfs mounted": func(c *engineContainer) {},
		"engine volume": func(c *engineContainer) {
			c.Mounts = []map[string]any{{"Type": "volume", "Destination": "/var/lib/docker", "RW": true}}
		},
		"extra volume": func(c *engineContainer) {
			tmpfsAsAsked(c)
			c.Mounts = append(c.Mounts, map[string]any{"Type": "volume", "Destination": "/data", "RW": true})
		},
		"unbounded tmpfs": func(c *engineContainer) {
			tmpfsAsAsked(c)
			c.Host["Mounts"] = []any{map[string]any{"Type": "tmpfs", "Target": "/var/lib/docker", "ReadOnly": false}}
		},
		"host bind": func(c *engineContainer) {
			tmpfsAsAsked(c)
			c.Host["Mounts"] = append(c.Host["Mounts"].([]any), map[string]any{"Type": "bind", "Source": "/", "Target": "/host"})
		},
		"base runtime": func(c *engineContainer) { tmpfsAsAsked(c); c.Host["Runtime"] = "runsc" },
		"fewer caps":   func(c *engineContainer) { tmpfsAsAsked(c); c.Host["CapAdd"] = []any{"SYS_ADMIN"} },
		"more caps": func(c *engineContainer) {
			tmpfsAsAsked(c)
			c.Host["CapAdd"] = append(c.Host["CapAdd"].([]any), "SYS_MODULE")
		},
		"privileged": func(c *engineContainer) { tmpfsAsAsked(c); c.Host["Privileged"] = true },
		"tmpfs map":  func(c *engineContainer) { tmpfsAsAsked(c); c.Host["Tmpfs"] = map[string]any{"/x": ""} },
	} {
		h := dockerHost(t)
		h.engine.applied = applied
		lease := testLease(dockerLeaseOf)
		err := h.backend().Create(context.Background(), instanceOf(lease), lease)
		if err == nil || refusalCode(err) != "" || h.engine.starts != 0 {
			t.Errorf("%s: create %v with %d starts, want a readback fault before start", name, err, h.engine.starts)
		}
	}
}

func TestVerifyRuntimeRequiresTheExactDockerRegistration(t *testing.T) {
	h := dockerHost(t)
	b := h.backend()
	base := map[string]struct {
		Path        string            `json:"path"`
		RuntimeArgs []string          `json:"runtimeArgs"`
		Status      map[string]string `json:"status"`
	}{"runsc": {Path: h.config.RunscPath, RuntimeArgs: []string{"--systemd-cgroup", "--overlay2=none"}}}
	info := daemonInfo{}
	info.Runtimes = base
	if err := b.verifyRuntime(info); err == nil || !strings.Contains(err.Error(), "docker runtime") {
		t.Fatalf("missing docker runtime: %v", err)
	}
	for name, entry := range map[string]struct {
		path string
		args []string
		ok   bool
	}{
		"exact":          {h.config.RunscPath, slices.Clone(sandboxhost.DockerRuntimeArgs), true},
		"other binary":   {"/usr/bin/runsc", slices.Clone(sandboxhost.DockerRuntimeArgs), false},
		"host network":   {h.config.RunscPath, append(slices.Clone(sandboxhost.DockerRuntimeArgs), "--network=host"), false},
		"no packet":      {h.config.RunscPath, sandboxhost.DockerRuntimeArgs[:3], false},
		"base args":      {h.config.RunscPath, []string{"--systemd-cgroup", "--overlay2=none"}, false},
		"reordered":      {h.config.RunscPath, []string{"--overlay2=none", "--systemd-cgroup", "--net-raw", "--allow-packet-socket-write"}, false},
		"unsafe nvproxy": {h.config.RunscPath, append(slices.Clone(sandboxhost.DockerRuntimeArgs[:3]), "--nvproxy"), false},
	} {
		runtimes := map[string]struct {
			Path        string            `json:"path"`
			RuntimeArgs []string          `json:"runtimeArgs"`
			Status      map[string]string `json:"status"`
		}{"runsc": base["runsc"]}
		runtimes["runsc-docker"] = struct {
			Path        string            `json:"path"`
			RuntimeArgs []string          `json:"runtimeArgs"`
			Status      map[string]string `json:"status"`
		}{Path: entry.path, RuntimeArgs: entry.args}
		info.Runtimes = runtimes
		if err := b.verifyRuntime(info); (err == nil) != entry.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A host without docker ignores a docker registration it does not use.
	plainHost := newHost(t)
	plain := plainHost.backend()
	entry := base["runsc"]
	entry.Path = plainHost.config.RunscPath
	base["runsc"] = entry
	if err := plain.verifyRuntime(daemonInfo{Runtimes: base}); err != nil {
		t.Fatal(err)
	}
}

// bindingHost is a docker host with egress whose binding hooks record the
// tables loaded.
type bindingHost struct {
	*egressHost
	loads [][]sandboxhost.PortBinding
	fail  error
}

func newBindingHost(t *testing.T) *bindingHost {
	h := &bindingHost{egressHost: newEgressHost(t)}
	h.config.Docker = dockerProfile()
	image := h.engine.catalog[testImageKey]
	image.Volumes = map[string]any{"/var/lib/docker": map[string]any{}}
	h.engine.catalog[testImageKey] = image
	h.engine.applied = tmpfsAsAsked
	apply, veth, master := applyTenantBindings, hostVethOf, bridgeOfPort
	t.Cleanup(func() { applyTenantBindings, hostVethOf, bridgeOfPort = apply, veth, master })
	applyTenantBindings = func(_ sandboxhost.ProfileEgress, bindings []sandboxhost.PortBinding) error {
		h.loads = append(h.loads, bindings)
		return h.fail
	}
	hostVethOf = func(key string) (string, error) {
		if key == "" {
			return "", errors.New("no namespace")
		}
		return "veth" + key[len(key)-4:], nil
	}
	bridgeOfPort = func(string) (string, error) { return "mcsbxeg0", nil }
	return h
}

func TestDockerHostBindsEveryPublicSandboxPort(t *testing.T) {
	h := newBindingHost(t)
	b := h.backend()
	b.observeInstance = func(int, bool) []sandboxhost.Check { return nil }
	lease := testLease(func(l *protocol.SandboxLeaseV1) { dockerLeaseOf(l); publicLease(l) })
	err := b.Create(context.Background(), instanceOf(lease), lease)
	// The fake engine reports no network settings, so the running public
	// sandbox's port cannot be resolved: the table is loaded without it
	// (its port passes nothing) and the create fails as a miner fault.
	if err == nil || refusalCode(err) != "" || !strings.Contains(err.Error(), sandbox.EgressFirewallUnavailable) {
		t.Fatalf("create = %v", err)
	}
	last := h.loads[len(h.loads)-1]
	if len(last) != 0 {
		t.Fatalf("unresolved port was bound: %v", last)
	}
}

func TestPortBindingFromInspection(t *testing.T) {
	h := newBindingHost(t)
	b := h.backend()
	var c inspectedContainer
	c.Name = "/s"
	c.NetworkSettings.SandboxKey = "/run/netns/abcd"
	c.NetworkSettings.Networks = map[string]struct {
		IPAddress  string `json:"IPAddress"`
		MacAddress string `json:"MacAddress"`
	}{"bridge": {IPAddress: "10.231.0.2", MacAddress: "02:42:0A:E7:00:02"}}
	binding, err := b.portBinding(c)
	if err != nil || binding != (sandboxhost.PortBinding{Port: "vethabcd", MAC: "02:42:0a:e7:00:02", IP: netip.MustParseAddr("10.231.0.2")}) {
		t.Fatalf("binding %+v, %v", binding, err)
	}
	bridgeOfPort = func(string) (string, error) { return "docker0", nil }
	if _, err := b.portBinding(c); err == nil {
		t.Fatal("a port of another bridge was bound")
	}
	bridgeOfPort = func(string) (string, error) { return "mcsbxeg0", nil }
	c.NetworkSettings.Networks["other"] = c.NetworkSettings.Networks["bridge"]
	if _, err := b.portBinding(c); err == nil {
		t.Fatal("a sandbox on two networks was bound")
	}
}

// Without docker no binding table is ever loaded.
func TestEgressHostWithoutDockerLoadsNoBindings(t *testing.T) {
	h := newEgressHost(t)
	apply := applyTenantBindings
	t.Cleanup(func() { applyTenantBindings = apply })
	loads := 0
	applyTenantBindings = func(sandboxhost.ProfileEgress, []sandboxhost.PortBinding) error { loads++; return nil }
	b := h.backend()
	lease := testLease(publicLease)
	if err := b.Create(context.Background(), instanceOf(lease), lease); err != nil {
		t.Fatal(err)
	}
	if err := b.Destroy(context.Background(), instanceOf(lease)); err != nil {
		t.Fatal(err)
	}
	if !b.EgressHealthy() || loads != 0 {
		t.Fatalf("binding loads %d", loads)
	}
}

func TestPeerIndexFromRtnetlink(t *testing.T) {
	message := func(name string, link uint32) syscall.NetlinkMessage {
		var data []byte
		data = append(data, make([]byte, syscall.SizeofIfInfomsg)...)
		attr := func(kind uint16, value []byte) {
			length := syscall.SizeofRtAttr + len(value)
			header := syscall.RtAttr{Len: uint16(length), Type: kind}
			data = append(data, (*[syscall.SizeofRtAttr]byte)(unsafe.Pointer(&header))[:]...)
			data = append(data, value...)
			for len(data)%4 != 0 {
				data = append(data, 0)
			}
		}
		attr(syscall.IFLA_IFNAME, append([]byte(name), 0))
		if link != 0 {
			attr(syscall.IFLA_LINK, (*[4]byte)(unsafe.Pointer(&link))[:])
		}
		return syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: syscall.RTM_NEWLINK}, Data: data}
	}
	messages := []syscall.NetlinkMessage{message("lo", 0), message("eth0", 17)}
	if index, err := peerIndexIn(messages, "eth0"); err != nil || index != 17 {
		t.Fatalf("index %d, %v", index, err)
	}
	if _, err := peerIndexIn(messages, "lo"); err == nil {
		t.Fatal("interface without a peer resolved")
	}
	if _, err := peerIndexIn(messages[:1], "eth0"); err == nil {
		t.Fatal("missing eth0 resolved")
	}
	if _, err := hostVeth("relative/path"); err == nil {
		t.Fatal("relative namespace path accepted")
	}
}

// onBridge makes the engine report every started sandbox on the egress
// bridge with a distinct address.
func onBridge(h *bindingHost) {
	h.engine.started = func(c *engineContainer) {
		n := len(c.Name)
		c.Network = map[string]any{
			"SandboxKey": "/run/netns/" + c.Name[n-4:],
			"Networks":   map[string]any{"bridge": map[string]any{"IPAddress": "10.231.0.9", "MacAddress": "02:42:0A:E7:00:09"}},
		}
	}
}

// A public docker sandbox's port is bound before Create returns, the table
// exists before the sandbox starts, and Destroy reloads it without the port.
func TestDockerLeaseBindsItsPortAndDestroyUnbindsIt(t *testing.T) {
	h := newBindingHost(t)
	onBridge(h)
	startsAtLoad := []int{}
	applyTenantBindings = func(_ sandboxhost.ProfileEgress, bindings []sandboxhost.PortBinding) error {
		h.engine.mu.Lock()
		startsAtLoad = append(startsAtLoad, h.engine.starts)
		h.engine.mu.Unlock()
		h.loads = append(h.loads, bindings)
		return nil
	}
	b := h.backend()
	b.observeInstance = func(int, bool) []sandboxhost.Check { return nil }
	lease := testLease(func(l *protocol.SandboxLeaseV1) { dockerLeaseOf(l); publicLease(l) })
	instance := instanceOf(lease)
	if err := b.Create(context.Background(), instance, lease); err != nil {
		t.Fatal(err)
	}
	if len(startsAtLoad) < 2 || startsAtLoad[0] != 0 {
		t.Fatalf("binding table loads at engine starts %v: not loaded before the start", startsAtLoad)
	}
	last := h.loads[len(h.loads)-1]
	want := sandboxhost.PortBinding{Port: "veth" + instance[len(instance)-4:], MAC: "02:42:0a:e7:00:09", IP: netip.MustParseAddr("10.231.0.9")}
	if len(last) != 1 || last[0] != want {
		t.Fatalf("bound %v, want %v", last, want)
	}
	if err := b.Destroy(context.Background(), instance); err != nil {
		t.Fatal(err)
	}
	if last := h.loads[len(h.loads)-1]; len(last) != 0 {
		t.Fatalf("destroyed sandbox still bound: %v", last)
	}
}

// A binding table nft refuses fails the create as a miner fault and fails
// the destroy, so neither path passes silently without the table.
func TestBindingLoadFailureFailsClosed(t *testing.T) {
	h := newBindingHost(t)
	onBridge(h)
	b := h.backend()
	b.observeInstance = func(int, bool) []sandboxhost.Check { return nil }
	lease := testLease(func(l *protocol.SandboxLeaseV1) { dockerLeaseOf(l); publicLease(l) })
	instance := instanceOf(lease)
	h.fail = errors.New("nft refused")
	err := b.Create(context.Background(), instance, lease)
	if err == nil || refusalCode(err) != "" || !strings.Contains(err.Error(), sandbox.EgressFirewallUnavailable) {
		t.Fatalf("create = %v", err)
	}
	h.engine.mu.Lock()
	starts := h.engine.starts
	h.engine.mu.Unlock()
	if starts != 0 {
		t.Fatalf("sandbox started %d times without a binding table", starts)
	}
	h.fail = nil
	if err := b.Create(context.Background(), instance, lease); err != nil {
		t.Fatal(err)
	}
	h.fail = errors.New("nft refused")
	if err := b.Destroy(context.Background(), instance); err == nil || !strings.Contains(err.Error(), "nft refused") {
		t.Fatalf("destroy = %v", err)
	}
}

// A sandbox whose port cannot be resolved stays unbound without failing the
// host's egress health or another sandbox's create.
func TestUnresolvablePortDoesNotFailOtherSandboxes(t *testing.T) {
	h := newBindingHost(t)
	b := h.backend()
	b.observeInstance = func(int, bool) []sandboxhost.Check { return nil }
	other := testLease(func(l *protocol.SandboxLeaseV1) {
		dockerLeaseOf(l)
		publicLease(l)
		l.SandboxID = "sbx-" + strings.Repeat("0", 31) + "2"
	})
	// The engine reports no network for the first sandbox: it cannot be
	// resolved and its own create fails.
	if err := b.Create(context.Background(), instanceOf(other), other); err == nil || !strings.Contains(err.Error(), sandbox.EgressFirewallUnavailable) {
		t.Fatalf("create with an unresolvable port = %v", err)
	}
	h.engine.mu.Lock()
	for _, c := range h.engine.containers {
		c.Status = "running"
	}
	h.engine.mu.Unlock()
	if !b.EgressHealthy() {
		t.Fatal("one unresolvable sandbox port made the host unhealthy")
	}
	onBridge(h)
	lease := testLease(func(l *protocol.SandboxLeaseV1) { dockerLeaseOf(l); publicLease(l) })
	if err := b.Create(context.Background(), instanceOf(lease), lease); err != nil {
		t.Fatalf("create next to an unresolvable sandbox: %v", err)
	}
	if last := h.loads[len(h.loads)-1]; len(last) != 1 {
		t.Fatalf("bound %v", last)
	}
}
