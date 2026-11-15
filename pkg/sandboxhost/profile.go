// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package sandboxhost

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/misscomputer/mscomputer-miner/pkg/sandbox"
)

const profileSchema = "ms.computer/mscomputer-subnet/sandbox-host-profile"

// Profile is a sandbox-host-profile.v1 document: values a provisioner
// configured. It tells a backend where its engine is. It is never proof;
// Preflight and the backend's engine checks observe every value.
type Profile struct {
	Schema         string           `json:"schema"`
	SchemaVersion  int              `json:"schema_version"`
	DockerHost     string           `json:"docker_host"`
	Containerd     ProfileContainer `json:"containerd"`
	DataRoot       string           `json:"data_root"`
	DockerDataRoot string           `json:"docker_data_root"`
	RunRoot        string           `json:"run_root"`
	Runtime        ProfileRuntime   `json:"runtime"`
	Engine         ProfileEngine    `json:"engine"`
	CgroupRoot     string           `json:"cgroup_root"`
	LeaseSlice     string           `json:"lease_slice"`
	EngineSlice    string           `json:"engine_slice"`
	Aggregate      ProfileAggregate `json:"aggregate"`
	PerLease       ProfilePerLease  `json:"per_lease"`
	// Egress, when present, enables network mode public (tenant_egress.go).
	Egress *ProfileEgress `json:"egress,omitempty"`
	// Docker, when present, enables lease capability docker (ProfileDocker).
	Docker *ProfileDocker `json:"docker,omitempty"`

	raw map[string]any
}

// ProfileContainer names the dedicated containerd.
type ProfileContainer struct {
	Address          string `json:"address"`
	Namespace        string `json:"namespace"`
	PluginsNamespace string `json:"plugins_namespace"`
}

// ProfileRuntime is the pinned runsc registration.
type ProfileRuntime struct {
	Name         string   `json:"name"`
	Path         string   `json:"path"`
	SHA256       string   `json:"sha256"`
	SentryPath   string   `json:"sentry_path"`
	SentrySHA256 string   `json:"sentry_sha256"`
	Args         []string `json:"args"`
	Release      string   `json:"release"`
}

// DockerRuntimeArgs are the exact runsc flags of the docker runtime: the base
// runtime's flags plus raw and packet sockets, which a nested Docker engine
// needs for its bridge networking (docs/sandbox-docker.md).
var DockerRuntimeArgs = []string{"--systemd-cgroup", "--overlay2=none", "--net-raw", "--allow-packet-socket-write"}

// ProfileDocker is the second runsc registration that docker leases run
// under. It uses the base runtime's pinned binary (runtime.path and
// runtime.sha256); only the name and the flags differ.
type ProfileDocker struct {
	Runtime string   `json:"runtime"`
	Args    []string `json:"args"`
	// VolumeTmpfsMiB caps each backend-created tmpfs that backs an image
	// volume (such as /var/lib/docker) of a docker lease. tmpfs is sentry
	// memory, so the lease memory limit bounds it as well.
	VolumeTmpfsMiB int `json:"volume_tmpfs_mib"`
}

var dockerRuntimeName = regexp.MustCompile(`^runsc-[a-z0-9]{1,16}$`)

// Validate checks the docker member.
func (d ProfileDocker) Validate() error {
	if !dockerRuntimeName.MatchString(d.Runtime) || strings.Join(d.Args, " ") != strings.Join(DockerRuntimeArgs, " ") || len(d.Args) != len(DockerRuntimeArgs) {
		return errors.New("docker must name a runsc-* runtime with exactly " + strings.Join(DockerRuntimeArgs, " "))
	}
	if d.VolumeTmpfsMiB < 64 || d.VolumeTmpfsMiB > sandbox.MaxMemoryMiB {
		return errors.New("docker volume_tmpfs_mib must be 64..65536")
	}
	return nil
}

// ProfileEngine is the reviewed engine pin.
type ProfileEngine struct {
	DockerVersion string `json:"docker_version"`
	EgressTable   string `json:"egress_table"`
}

// ProfileAggregate is the host-wide sizing. DiskMiB is the lane disk budget:
// each lease's writable-layer quota is its disk_mib, and per-sandbox image
// and log bytes, the image reserve and engine overhead are outside it.
type ProfileAggregate struct {
	CPUMillis         int `json:"cpu_millis"`
	MemoryMiB         int `json:"memory_mib"`
	PIDs              int `json:"pids"`
	DataFSMiB         int `json:"data_fs_mib"`
	RunTmpfsMiB       int `json:"run_tmpfs_mib"`
	ImageReserveMiB   int `json:"image_reserve_mib"`
	EngineOverheadMiB int `json:"engine_overhead_mib"`
	ImageMaxMiB       int `json:"image_max_mib"`
	LogMiB            int `json:"log_mib"`
	DiskMiB           int `json:"disk_mib"`
	Sandboxes         int `json:"sandboxes"`
}

// DiskRequiredMiB is the data filesystem size the aggregate needs.
func (a ProfileAggregate) DiskRequiredMiB() int {
	return a.DiskMiB + a.Sandboxes*(a.ImageMaxMiB+a.LogMiB) + a.EngineOverheadMiB + a.ImageReserveMiB
}

// ProfilePerLease is the per-sandbox policy the backend must apply.
type ProfilePerLease struct {
	DefaultWritableMiB int      `json:"default_writable_mib"`
	LogMaxSizeMiB      int      `json:"log_max_size_mib"`
	LogMaxFile         int      `json:"log_max_file"`
	PIDsMax            int      `json:"pids_max"`
	Mounts             string   `json:"mounts"`
	ImageVolumes       string   `json:"image_volumes"`
	NetworkModes       []string `json:"network_modes"`
	Isolation          []string `json:"isolation"`
}

const maxProfileBytes = 64 << 10

// GVisorHostPIDs is the host pids a gVisor sandbox needs beyond its lease's
// pids: the sentry's and gofer's threads and the fd-parking process sit in
// the container cgroup next to the systrap stubs that carry guest tasks, and
// every running exec adds the helper's supervisor and its stubs. The stub
// pool is not reaped, so the cgroup stays at its peak. Measured on runsc
// r20261005: about 40 idle and 139-141 with sandbox.MaxRunningExecs running
// (6.6 per exec); without room for them a 16-exec burst failed to fork and
// execs ended sandbox_resources_exhausted. A lease's pids are its guest's.
const (
	GVisorBasePIDs           = 48
	GVisorPIDsPerRunningExec = 8
	GVisorHostPIDs           = GVisorBasePIDs + GVisorPIDsPerRunningExec*sandbox.MaxRunningExecs
)

// HostPIDs is the container pids.max of a lease asking for leasePIDs.
func HostPIDs(leasePIDs int) int64 { return int64(leasePIDs) + GVisorHostPIDs }

// LoadProfile reads and validates a profile file.
func LoadProfile(name string) (Profile, error) {
	file, err := os.Open(name)
	if err != nil {
		return Profile{}, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxProfileBytes+1))
	if err != nil {
		return Profile{}, err
	}
	if len(raw) > maxProfileBytes {
		return Profile{}, errors.New("sandbox host profile is too large")
	}
	return DecodeProfile(raw)
}

var objectMembers = map[string][]string{
	"":           {"schema", "schema_version", "docker_host", "containerd", "data_root", "docker_data_root", "run_root", "runtime", "engine", "cgroup_root", "lease_slice", "engine_slice", "aggregate", "per_lease"},
	"containerd": {"address", "namespace", "plugins_namespace"},
	"runtime":    {"name", "path", "sha256", "sentry_path", "sentry_sha256", "args", "release"},
	"engine":     {"docker_version", "egress_table"},
	"aggregate":  {"cpu_millis", "memory_mib", "pids", "data_fs_mib", "run_tmpfs_mib", "image_reserve_mib", "engine_overhead_mib", "image_max_mib", "log_mib", "disk_mib", "sandboxes"},
	"docker":     {"runtime", "args", "volume_tmpfs_mib"},
	"egress":     {"bridge", "subnet", "dns", "bandwidth_mbit", "new_conns_per_second", "deny_cidrs"},
	"per_lease":  {"default_writable_mib", "log_max_size_mib", "log_max_file", "pids_max", "mounts", "image_volumes", "network_modes", "isolation"},
}

// optionalMembers are top-level members a profile may omit.
var optionalMembers = []string{"egress", "docker"}

func optionalMember(name string) bool {
	for _, optional := range optionalMembers {
		if optional == name {
			return true
		}
	}
	return false
}

func sameMembers(object map[string]any, want []string) bool {
	if len(object) != len(want) {
		return false
	}
	for _, key := range want {
		if _, ok := object[key]; !ok {
			return false
		}
	}
	return true
}

// DecodeProfile parses a profile strictly: every member present, no unknown
// member, and only values that could be proven.
func DecodeProfile(raw []byte) (Profile, error) {
	var generic map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&generic); err != nil {
		return Profile{}, fmt.Errorf("sandbox host profile: %w", err)
	}
	for member, want := range objectMembers {
		object := generic
		if member == "" {
			want = append([]string(nil), want...)
			for _, optional := range optionalMembers {
				if _, ok := generic[optional]; ok {
					want = append(want, optional)
				}
			}
		} else if _, ok := generic[member]; !ok && optionalMember(member) {
			continue
		}
		if member != "" {
			nested, ok := generic[member].(map[string]any)
			if !ok {
				return Profile{}, fmt.Errorf("sandbox host profile member %s must be an object", member)
			}
			object = nested
		}
		if !sameMembers(object, want) {
			return Profile{}, fmt.Errorf("sandbox host profile %s has unexpected members", strings.TrimSpace("object "+member))
		}
	}
	var profile Profile
	strict := json.NewDecoder(bytes.NewReader(raw))
	strict.DisallowUnknownFields()
	if err := strict.Decode(&profile); err != nil {
		return Profile{}, fmt.Errorf("sandbox host profile: %w", err)
	}
	profile.raw = generic
	if err := profile.Validate(); err != nil {
		return Profile{}, err
	}
	return profile, nil
}

func cleanAbs(value string) bool {
	return strings.HasPrefix(value, "/") && path.Clean(value) == value && value != "/"
}

var (
	hexDigest   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	sliceName   = regexp.MustCompile(`^[a-z0-9]+\.slice$`)
	egressTable = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)
)

// Validate applies the same rules as scripts/sandbox-host/report.py.
func (p Profile) Validate() error {
	if p.Schema != profileSchema || p.SchemaVersion != 1 {
		return errors.New("not a sandbox-host-profile.v1 document")
	}
	socket, ok := strings.CutPrefix(p.DockerHost, "unix://")
	if !ok || !cleanAbs(socket) || socket == "/var/run/docker.sock" || socket == "/run/docker.sock" {
		return errors.New("docker_host must be a dedicated unix socket")
	}
	for name, value := range map[string]string{"data_root": p.DataRoot, "docker_data_root": p.DockerDataRoot, "run_root": p.RunRoot,
		"cgroup_root": p.CgroupRoot, "containerd.address": p.Containerd.Address, "runtime.path": p.Runtime.Path, "runtime.sentry_path": p.Runtime.SentryPath} {
		if !cleanAbs(value) {
			return fmt.Errorf("profile %s must be a clean absolute path", name)
		}
	}
	if !strings.HasPrefix(p.DockerDataRoot, p.DataRoot+"/") {
		return errors.New("docker_data_root must be below data_root")
	}
	c := p.Containerd
	if c.Address == "/run/containerd/containerd.sock" || c.Namespace == "" || c.Namespace == "moby" || c.Namespace == "default" ||
		c.PluginsNamespace == "" || c.PluginsNamespace == "plugins.moby" || c.PluginsNamespace == c.Namespace {
		return errors.New("containerd must name a dedicated address and namespaces")
	}
	r := p.Runtime
	if r.Name != "runsc" || !hexDigest.MatchString(r.SHA256) || !hexDigest.MatchString(r.SentrySHA256) ||
		len(r.Args) != 2 || r.Args[0] != "--systemd-cgroup" || r.Args[1] != "--overlay2=none" {
		return errors.New("runtime must be the pinned runsc with exactly --systemd-cgroup --overlay2=none")
	}
	if p.Engine.DockerVersion == "" || !egressTable.MatchString(p.Engine.EgressTable) {
		return errors.New("engine must name docker_version and an nft egress_table")
	}
	if !sliceName.MatchString(p.LeaseSlice) || !sliceName.MatchString(p.EngineSlice) || p.LeaseSlice == p.EngineSlice {
		return errors.New("lease and engine slices must be distinct top-level slice names without '-'")
	}
	a := p.Aggregate
	for name, value := range map[string]int{"cpu_millis": a.CPUMillis, "memory_mib": a.MemoryMiB, "pids": a.PIDs, "data_fs_mib": a.DataFSMiB,
		"run_tmpfs_mib": a.RunTmpfsMiB, "image_reserve_mib": a.ImageReserveMiB, "engine_overhead_mib": a.EngineOverheadMiB,
		"image_max_mib": a.ImageMaxMiB, "log_mib": a.LogMiB, "disk_mib": a.DiskMiB, "sandboxes": a.Sandboxes} {
		if value <= 0 {
			return fmt.Errorf("profile aggregate.%s must be a positive integer", name)
		}
	}
	if a.DiskRequiredMiB() > a.DataFSMiB {
		return errors.New("data_fs_mib is below disk_mib + sandboxes x (image_max_mib + log_mib) + engine_overhead_mib + image_reserve_mib")
	}
	l := p.PerLease
	if l.DefaultWritableMiB <= 0 || l.LogMaxSizeMiB <= 0 || l.LogMaxFile <= 0 || l.PIDsMax <= 0 {
		return errors.New("per_lease sizes must be positive integers")
	}
	if a.LogMiB != l.LogMaxSizeMiB*l.LogMaxFile {
		return errors.New("aggregate log_mib must equal per_lease log_max_size_mib x log_max_file")
	}
	if int64(a.PIDs) < int64(a.Sandboxes)*HostPIDs(l.PIDsMax) {
		return errors.New("aggregate pids must cover sandboxes x (per_lease pids_max + gVisor host pids)")
	}
	networkModes := []string{"none"}
	if p.Egress != nil {
		if err := p.Egress.Validate(); err != nil {
			return err
		}
		networkModes = append(networkModes, "public")
	}
	if p.Docker != nil {
		if err := p.Docker.Validate(); err != nil {
			return err
		}
		if p.Docker.Runtime == r.Name {
			return errors.New("docker runtime must differ from the base runtime")
		}
	}
	if l.Mounts != "none" || l.ImageVolumes != "refuse" || strings.Join(l.NetworkModes, ",") != strings.Join(networkModes, ",") ||
		len(l.Isolation) != 1 || l.Isolation[0] != "gvisor" {
		return errors.New("per_lease policy must be mounts none, image volumes refused, network none, gvisor only")
	}
	return nil
}

// MinTestnetImageMaxMiB is the smallest tenant image cap a testnet may run
// instead of sandbox.MaxTenantImageMiB: it still holds the default
// sandbox-base image.
const MinTestnetImageMaxMiB = 1024

// StandardMemoryMiB and StandardDiskMiB are the memory and disk of the
// standard sandbox (1 vCPU) under the network-wide image cap: the mainnet
// policy's sandbox_capture_lease (provisional-2026-11-08.1), which the
// validator's capture lease is sized at. A testnet running a smaller
// explicit image cap keeps the lease-class slot (sandbox.MinMemoryMiB,
// sandbox.TenantWorkingSpaceMiB).
const (
	StandardMemoryMiB = 4096
	StandardDiskMiB   = 10240
)

// CapacityFloorCPUMillis, CapacityFloorMemoryMiB and CapacityFloorDiskMiB
// mirror the mainnet policy's sandbox_capacity_floor
// (provisional-2026-11-08.1; Python SANDBOX_CAPACITY_FLOOR): the aggregate a
// sandbox miner must declare, strictly above one standard sandbox so that a
// host declaring exactly one does not qualify.
const (
	CapacityFloorCPUMillis = 2000
	CapacityFloorMemoryMiB = 6144
	CapacityFloorDiskMiB   = 20480
)

// StandardSlot is the standard sandbox (cpu_millis, memory_mib, disk_mib)
// under image cap imageCapMiB: the validator's capture lease.
func StandardSlot(imageCapMiB int) (cpuMillis, memoryMiB, diskMiB int) {
	if imageCapMiB == sandbox.MaxTenantImageMiB {
		return sandbox.MinCPUMillis, StandardMemoryMiB, StandardDiskMiB
	}
	return sandbox.MinCPUMillis, sandbox.MinMemoryMiB, sandbox.TenantWorkingSpaceMiB
}

// CapacityFloor is the aggregate (cpu_millis, memory_mib, disk_mib) a host
// must declare under image cap imageCapMiB: the policy capacity floor under
// the network cap; a testnet cap keeps the lease-class slot.
func CapacityFloor(imageCapMiB int) (cpuMillis, memoryMiB, diskMiB int) {
	if imageCapMiB == sandbox.MaxTenantImageMiB {
		return CapacityFloorCPUMillis, CapacityFloorMemoryMiB, CapacityFloorDiskMiB
	}
	return StandardSlot(imageCapMiB)
}

// DataFSFloorMiB is the smallest data filesystem that holds the declared
// floor's disk (CapacityFloor) beside a capped image of imageCapMiB, its
// logs, the engine overhead and the image reserve. With the network cap
// 10240 and the reference overheads (log 16, engine 512, reserve 512) it is
// 31760 MiB.
func (a ProfileAggregate) DataFSFloorMiB(imageCapMiB int) int {
	_, _, disk := CapacityFloor(imageCapMiB)
	return imageCapMiB + disk + a.LogMiB + a.EngineOverheadMiB + a.ImageReserveMiB
}

// CheckStandard enforces the uniform sandbox standard every sandbox miner
// must meet, beyond Validate, under the network-wide tenant image cap
// imageCapMiB (sandbox.MaxTenantImageMiB; a testnet may pass a smaller
// explicit value):
//   - the profile admits tenant egress (network mode public, advertised as
//     sandbox-egress-v1);
//   - aggregate.image_max_mib restates the cap exactly: the cap is
//     network-wide, so a profile may not choose another value;
//   - the aggregate declares at least the capacity floor (CapacityFloor:
//     2 vCPU, 6144 MiB memory, 20480 MiB disk under the network cap; the
//     lease-class 1 vCPU, 1024 MiB, 5120 MiB under a testnet cap), one sandbox;
//   - data_fs_mib holds that disk beside a capped image (DataFSFloorMiB).
//
// There is no miner opt-out; the agent refuses to start its sandbox lane on
// a profile that fails it.
func (p Profile) CheckStandard(imageCapMiB int) error {
	if p.Egress == nil {
		return errors.New("the sandbox standard requires tenant egress: the host profile has no egress section")
	}
	a := p.Aggregate
	if a.ImageMaxMiB != imageCapMiB {
		return fmt.Errorf("aggregate.image_max_mib is the network-wide tenant image cap %d MiB and cannot be chosen per miner; the profile has %d", imageCapMiB, a.ImageMaxMiB)
	}
	cpu, memory, disk := CapacityFloor(imageCapMiB)
	if a.CPUMillis < cpu || a.MemoryMiB < memory || a.DiskMiB < disk || a.Sandboxes < 1 {
		return fmt.Errorf("the sandbox standard requires aggregate capacity of at least the floor (cpu_millis %d, memory_mib %d, disk_mib %d, sandboxes 1)",
			cpu, memory, disk)
	}
	if floor := a.DataFSFloorMiB(imageCapMiB); a.DataFSMiB < floor {
		return fmt.Errorf("the sandbox standard requires data_fs_mib >= %d (image cap %d + floor disk %d + log, engine overhead and image reserve), the profile has %d",
			floor, imageCapMiB, disk, a.DataFSMiB)
	}
	return nil
}

// testnetImageCapNetworks are the only (network, netuid) pairs a tenant
// image cap below sandbox.MaxTenantImageMiB may run on. Mainnet never.
var testnetImageCapNetworks = map[string]uint{"test": 581}

// CheckImageCap validates the tenant image cap a miner agent runs with: the
// network-wide sandbox.MaxTenantImageMiB, or a smaller explicit value of at
// least MinTestnetImageMaxMiB only on an allowlisted testnet (network "test",
// netuid 581). Any other network name, endpoint URL or netuid is refused.
func CheckImageCap(imageCapMiB int, network string, netuid uint) error {
	if imageCapMiB == sandbox.MaxTenantImageMiB {
		return nil
	}
	if want, ok := testnetImageCapNetworks[network]; !ok || want != netuid {
		return fmt.Errorf("the tenant image cap is %d MiB; %d is only allowed on an allowlisted testnet (network test, netuid 581), not network %q netuid %d",
			sandbox.MaxTenantImageMiB, imageCapMiB, network, netuid)
	}
	if imageCapMiB < MinTestnetImageMaxMiB || imageCapMiB > sandbox.MaxTenantImageMiB {
		return fmt.Errorf("a testnet tenant image cap must be %d..%d MiB, not %d", MinTestnetImageMaxMiB, sandbox.MaxTenantImageMiB, imageCapMiB)
	}
	return nil
}

// DockerSocket is the engine socket path.
func (p Profile) DockerSocket() string { return strings.TrimPrefix(p.DockerHost, "unix://") }

// Digest is sha256 over the canonical JSON of the decoded document, the
// same bytes report.py hashes (sorted keys, no whitespace, UTF-8).
func (p Profile) Digest() (string, error) {
	if p.raw == nil {
		return "", errors.New("profile was not decoded with DecodeProfile")
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, p.raw); err != nil {
		return "", err
	}
	sum := sha256.Sum256(buf.Bytes())
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func writeCanonical(buf *bytes.Buffer, value any) error {
	switch v := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, key); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeCanonical(buf, v[key]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case string:
		encoder := json.NewEncoder(buf)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(v); err != nil {
			return err
		}
		buf.Truncate(buf.Len() - 1) // Encode appends a newline
	case json.Number:
		if strings.ContainsAny(v.String(), ".eE") {
			return errors.New("sandbox host profile numbers must be integers")
		}
		buf.WriteString(v.String())
	case bool:
		fmt.Fprint(buf, v)
	case nil:
		buf.WriteString("null")
	default:
		return fmt.Errorf("unsupported JSON value %T", value)
	}
	return nil
}
