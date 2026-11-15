// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package sandboxbackend

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	goruntime "runtime"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/misscomputer/mscomputer-miner/pkg/miner"
	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
	"github.com/misscomputer/mscomputer-miner/pkg/sandbox"
	"github.com/misscomputer/mscomputer-miner/pkg/sandboxhost"
	"github.com/misscomputer/mscomputer-miner/pkg/sandboxops"
	"golang.org/x/sys/unix"
)

// dockerCapabilities is the capability set of a docker lease's processes
// (docs/sandbox-docker.md). These are capabilities inside the gVisor
// sentry's virtual kernel: the sentry implements them against its own
// emulated objects, and gVisor never grants a host capability to a sandbox
// (the sandbox process itself runs with none of these on the host). A nested
// Docker engine needs them to mount its storage, build bridges and network
// namespaces, and run containers as other users. Every other lease keeps
// sandboxCapabilities (Docker's default set). Privileged stays false and no-new-privileges
// stays set.
var dockerCapabilities = []string{
	"AUDIT_WRITE", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "MKNOD", "NET_ADMIN", "NET_BIND_SERVICE",
	"NET_RAW", "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_ADMIN", "SYS_CHROOT", "SYS_PTRACE",
}

// maxDockerVolumes bounds the image-declared volumes of a docker lease.
const maxDockerVolumes = 8

// The port binding hooks, replaceable in tests.
var (
	applyTenantBindings = sandboxhost.ApplyTenantBindings
	hostVethOf          = hostVeth
	bridgeOfPort        = func(port string) (string, error) {
		master, err := os.Readlink(filepath.Join("/sys/class/net", port, "master"))
		return filepath.Base(master), err
	}
)

// bindingTimeout bounds one resync of the port binding table.
const bindingTimeout = 30 * time.Second

// DockerEnabled reports whether the backend admits leases with capability
// docker: the host profile has the docker member, and Open verified the
// second runtime registration (verifyRuntime), or the backend would not
// have opened.
func (b *GVisor) DockerEnabled() bool { return b.config.Docker != nil }

func dockerLease(lease protocol.SandboxLeaseV1) bool {
	return sandbox.HasCapability(lease.Capabilities, sandbox.CapabilityDocker)
}

func (b *GVisor) capabilitiesSupported(capabilities []string) bool {
	for _, capability := range capabilities {
		if capability != sandbox.CapabilityDocker || b.config.Docker == nil {
			return false
		}
	}
	return true
}

// leaseRuntime is the runtime registration a lease runs under.
func (b *GVisor) leaseRuntime(lease protocol.SandboxLeaseV1) string {
	if dockerLease(lease) && b.config.Docker != nil {
		return b.config.Docker.Runtime
	}
	return b.config.Runtime
}

// leaseCapabilities is the sentry-virtual capability set of a lease.
func (b *GVisor) leaseCapabilities(lease protocol.SandboxLeaseV1) []string {
	if dockerLease(lease) && b.config.Docker != nil {
		return dockerCapabilities
	}
	return sandboxCapabilities
}

// imageVolumePaths returns the sorted volume paths an image declares, or
// false when one is not a path a tmpfs may cover.
func imageVolumePaths(image inspectedImage) ([]string, bool) {
	paths := make([]string, 0, len(image.Config.Volumes))
	for volume := range image.Config.Volumes {
		paths = append(paths, volume)
	}
	sort.Strings(paths)
	if len(paths) > maxDockerVolumes {
		return nil, false
	}
	for _, volume := range paths {
		if !strings.HasPrefix(volume, "/") || path.Clean(volume) != volume || volume == "/" || strings.ContainsAny(volume, ",:\x00") {
			return nil, false
		}
		for _, reserved := range []string{sandboxops.MountTarget, "/proc", "/sys", "/dev", "/etc"} {
			if volume == reserved || strings.HasPrefix(volume, reserved+"/") {
				return nil, false
			}
		}
	}
	return paths, true
}

// dockerVolumesAdmitted reports whether image volumes are admitted for lease:
// only for a docker lease on a docker host, and only when every declared path
// can be covered by a backend-created tmpfs, so no engine volume (host
// storage no quota counts) is ever created.
func (b *GVisor) dockerVolumesAdmitted(image inspectedImage, lease protocol.SandboxLeaseV1) bool {
	if !dockerLease(lease) || b.config.Docker == nil {
		return false
	}
	_, ok := imageVolumePaths(image)
	return ok
}

// setDockerVolumes covers each of the image's volume paths with a tmpfs of
// the profile's size, at most the lease's memory: tmpfs is sentry memory, so
// the lease's memory.max bounds it as well.
func (b *GVisor) setDockerVolumes(s *spec, lease protocol.SandboxLeaseV1, image inspectedImage) {
	paths, ok := imageVolumePaths(image)
	if !ok || b.config.Docker == nil {
		return
	}
	s.volumes = paths
	s.tmpfsBytes = int64(min(b.config.Docker.VolumeTmpfsMiB, lease.Resources.MemoryMiB)) << 20
}

// dockerVolumes sets the volumes of a docker lease's spec from the verified
// image the container was created from.
func (b *GVisor) dockerVolumes(ctx context.Context, s *spec, lease protocol.SandboxLeaseV1) error {
	if !dockerLease(lease) || b.config.Docker == nil {
		return nil
	}
	inspected, err := b.inspectVerified(ctx, s.labels[LabelImageID], lease)
	if err != nil {
		return err
	}
	b.setDockerVolumes(s, lease, inspected)
	return nil
}

// volumeMounts are the tmpfs mounts of a docker lease's spec.
func volumeMounts(s spec) []any {
	mounts := make([]any, 0, len(s.volumes))
	for _, volume := range s.volumes {
		mounts = append(mounts, map[string]any{
			"Type": "tmpfs", "Target": volume, "ReadOnly": false,
			"TmpfsOptions": map[string]any{"SizeBytes": s.tmpfsBytes},
		})
	}
	return mounts
}

// verifyVolumeMounts is the docker lease readback: the requested mounts are
// exactly one size-capped tmpfs per spec volume (plus the ops helper bind,
// verified by verifyHelperMount, when ops are enabled), and the container's
// mounts are exactly those tmpfs (and the helper), so no engine volume or
// other mount exists.
func verifyVolumeMounts(c inspectedContainer, s spec) error {
	requested := map[string]bool{}
	helper := c
	helper.HostConfig.Mounts, helper.Mounts = nil, nil
	for _, m := range c.HostConfig.Mounts {
		switch {
		case m.Type == "tmpfs" && m.Source == "" && !m.ReadOnly && m.BindOptions == nil && m.TmpfsOptions != nil &&
			m.TmpfsOptions.SizeBytes == s.tmpfsBytes && m.TmpfsOptions.Mode == 0 && slices.Contains(s.volumes, m.Target) && !requested[m.Target]:
			requested[m.Target] = true
		case m.Type == "bind" && s.helper != nil:
			helper.HostConfig.Mounts = append(helper.HostConfig.Mounts, m)
		default:
			return fmt.Errorf("sandbox %s requests a mount %s at %s the docker spec does not set", c.Name, m.Type, m.Target)
		}
	}
	if len(requested) != len(s.volumes) {
		return fmt.Errorf("sandbox %s does not request a tmpfs for every image volume", c.Name)
	}
	mounted := map[string]bool{}
	for _, m := range c.Mounts {
		switch {
		case m.Type == "tmpfs" && m.RW && requested[m.Destination] && !mounted[m.Destination]:
			mounted[m.Destination] = true
		case m.Type == "bind" && s.helper != nil:
			helper.Mounts = append(helper.Mounts, m)
		default:
			return fmt.Errorf("sandbox %s carries a mount %s at %s the docker spec does not set", c.Name, m.Type, m.Destination)
		}
	}
	if len(mounted) != len(s.volumes) {
		return fmt.Errorf("sandbox %s does not carry a tmpfs for every image volume", c.Name)
	}
	if s.helper != nil {
		return verifyHelperMount(helper, s.helper)
	}
	return nil
}

// verifyDockerRuntime requires the daemon to register the docker runtime at
// the pinned runsc path with exactly the docker arguments.
func (b *GVisor) verifyDockerRuntime(info daemonInfo) error {
	if b.config.Docker == nil {
		return nil
	}
	runtime, ok := info.Runtimes[b.config.Docker.Runtime]
	if !ok || runtime.Path != b.config.RunscPath {
		return fmt.Errorf("sandbox docker daemon does not register docker runtime %q at %s", b.config.Docker.Runtime, b.config.RunscPath)
	}
	if !slices.Equal(runtime.RuntimeArgs, sandboxhost.DockerRuntimeArgs) || !slices.Equal(b.config.Docker.Args, sandboxhost.DockerRuntimeArgs) {
		return fmt.Errorf("docker runtime %q arguments %v are not exactly %v", b.config.Docker.Runtime, runtime.RuntimeArgs, sandboxhost.DockerRuntimeArgs)
	}
	return nil
}

// bindPorts reloads the port binding table after a public sandbox started
// on a docker host. A table that cannot be loaded, or this sandbox's port
// left unbound, fails the create as a miner fault.
func (b *GVisor) bindPorts(ctx context.Context, instanceID string, lease protocol.SandboxLeaseV1) error {
	if b.config.Docker == nil || b.config.Egress == nil || lease.Network.Mode != sandbox.NetworkPublic {
		return nil
	}
	unbound, err := b.syncBindings(ctx)
	if err == nil {
		err = unbound[instanceID]
	}
	if err != nil {
		return fmt.Errorf("%w: %v", &miner.SandboxFault{Code: sandbox.EgressFirewallUnavailable}, err)
	}
	return nil
}

// unbindPorts reloads the table after a sandbox was removed.
func (b *GVisor) unbindPorts(ctx context.Context) error {
	if b.config.Docker == nil || b.config.Egress == nil {
		return nil
	}
	_, err := b.syncBindings(ctx)
	return err
}

// syncBindings rebuilds the port binding table from the engine's live
// sandboxes in one nft transaction: each running sandbox on the egress
// bridge is bound to the host end of its veth pair, read from its network
// namespace. A sandbox whose port cannot be resolved (one being stopped, for
// example) stays unbound, so its port passes nothing, and is returned by
// name in unbound without failing the others; err is a failure to list the
// sandboxes or to load the table.
func (b *GVisor) syncBindings(ctx context.Context) (unbound map[string]error, err error) {
	b.bindings.Lock()
	defer b.bindings.Unlock()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), bindingTimeout)
	defer cancel()
	filters, _ := json.Marshal(map[string][]string{"label": {LabelSandbox}})
	var containers []listedContainer
	if err := b.engine.call(ctx, http.MethodGet, "/containers/json", url.Values{"all": {"1"}, "filters": {string(filters)}}, nil, &containers); err != nil {
		return nil, fmt.Errorf("list sandboxes for port bindings: %w", err)
	}
	var bindings []sandboxhost.PortBinding
	unbound = map[string]error{}
	for _, listed := range containers {
		var c inspectedContainer
		if err := b.engine.call(ctx, http.MethodGet, "/containers/"+url.PathEscape(listed.ID)+"/json", nil, nil, &c); err != nil {
			if engineStatus(err) != http.StatusNotFound {
				unbound[strings.TrimPrefix(firstName(listed), "/")] = fmt.Errorf("inspect sandbox %s: %w", listed.ID, err)
			}
			continue
		}
		if !c.State.Running || c.HostConfig.NetworkMode != "bridge" {
			continue
		}
		binding, err := b.portBinding(c)
		if err != nil {
			unbound[strings.TrimPrefix(c.Name, "/")] = err
			continue
		}
		bindings = append(bindings, binding)
	}
	for name, err := range unbound {
		slog.Warn("sandbox port left unbound; it passes nothing", "sandbox", name, "error", err)
	}
	if err := applyTenantBindings(*b.config.Egress, bindings); err != nil {
		return unbound, err
	}
	return unbound, nil
}

func firstName(c listedContainer) string {
	if len(c.Names) == 0 {
		return c.ID
	}
	return c.Names[0]
}

func (b *GVisor) portBinding(c inspectedContainer) (sandboxhost.PortBinding, error) {
	network, ok := c.NetworkSettings.Networks["bridge"]
	if !ok || len(c.NetworkSettings.Networks) != 1 {
		return sandboxhost.PortBinding{}, fmt.Errorf("sandbox %s is not on exactly the egress bridge", c.Name)
	}
	ip, err := netip.ParseAddr(network.IPAddress)
	if err != nil {
		return sandboxhost.PortBinding{}, fmt.Errorf("sandbox %s address %q: %w", c.Name, network.IPAddress, err)
	}
	port, err := hostVethOf(c.NetworkSettings.SandboxKey)
	if err != nil {
		return sandboxhost.PortBinding{}, fmt.Errorf("sandbox %s bridge port: %w", c.Name, err)
	}
	if master, err := bridgeOfPort(port); err != nil || master != b.config.Egress.Bridge {
		return sandboxhost.PortBinding{}, fmt.Errorf("sandbox %s port %s is not a port of %s", c.Name, port, b.config.Egress.Bridge)
	}
	binding := sandboxhost.PortBinding{Port: port, MAC: strings.ToLower(network.MacAddress), IP: ip}
	slog.Debug("sandbox port binding", "sandbox", c.Name, "port", port, "mac", binding.MAC, "ip", ip)
	return binding, nil
}

// hostVeth returns the name of the host end of the eth0 veth pair in the
// network namespace at netnsPath: on a locked OS thread it enters the
// namespace, asks rtnetlink for eth0's IFLA_LINK (the peer's ifindex in the
// host namespace), and returns to the thread's own namespace. A thread that
// cannot return is never unlocked, so the Go runtime discards it.
func hostVeth(netnsPath string) (string, error) {
	if !filepath.IsAbs(netnsPath) || filepath.Clean(netnsPath) != netnsPath {
		return "", fmt.Errorf("network namespace path %q is not clean and absolute", netnsPath)
	}
	target, err := unix.Open(netnsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", fmt.Errorf("open network namespace: %w", err)
	}
	defer unix.Close(target)
	type result struct {
		index int
		err   error
	}
	done := make(chan result, 1)
	go func() {
		goruntime.LockOSThread()
		self, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			goruntime.UnlockOSThread()
			done <- result{err: err}
			return
		}
		defer unix.Close(self)
		if err := unix.Setns(target, unix.CLONE_NEWNET); err != nil {
			goruntime.UnlockOSThread()
			done <- result{err: fmt.Errorf("enter network namespace: %w", err)}
			return
		}
		index, lookupErr := linkPeerIndex("eth0")
		if err := unix.Setns(self, unix.CLONE_NEWNET); err != nil {
			done <- result{err: fmt.Errorf("return from network namespace: %w", err)}
			return
		}
		goruntime.UnlockOSThread()
		done <- result{index: index, err: lookupErr}
	}()
	r := <-done
	if r.err != nil {
		return "", r.err
	}
	iface, err := net.InterfaceByIndex(r.index)
	if err != nil {
		return "", fmt.Errorf("host interface %d: %w", r.index, err)
	}
	return iface.Name, nil
}

// linkPeerIndex returns IFLA_LINK of the interface name in the calling
// thread's network namespace.
func linkPeerIndex(name string) (int, error) {
	raw, err := syscall.NetlinkRIB(syscall.RTM_GETLINK, syscall.AF_UNSPEC)
	if err != nil {
		return 0, fmt.Errorf("rtnetlink dump: %w", err)
	}
	messages, err := syscall.ParseNetlinkMessage(raw)
	if err != nil {
		return 0, err
	}
	return peerIndexIn(messages, name)
}

func peerIndexIn(messages []syscall.NetlinkMessage, name string) (int, error) {
	for i := range messages {
		if messages[i].Header.Type != syscall.RTM_NEWLINK {
			continue
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(&messages[i])
		if err != nil {
			return 0, err
		}
		var ifname string
		link := -1
		for _, attr := range attrs {
			switch attr.Attr.Type {
			case syscall.IFLA_IFNAME:
				ifname = strings.TrimRight(string(attr.Value), "\x00")
			case syscall.IFLA_LINK:
				if len(attr.Value) == 4 {
					link = int(binary.NativeEndian.Uint32(attr.Value))
				}
			}
		}
		if ifname == name {
			if link <= 0 {
				return 0, fmt.Errorf("%s has no peer link", name)
			}
			return link, nil
		}
	}
	return 0, fmt.Errorf("no interface %s in the network namespace", name)
}
