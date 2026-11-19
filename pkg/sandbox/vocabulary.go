// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

// Package sandbox is the shared vocabulary of the sandbox-lease-v1 lane.
// The lane is off by default and independent of
// deployment.v4 and static-site-v1: it adds documents, tables and a
// capability feature, and changes none of theirs.
package sandbox

import (
	"errors"
	"net/netip"
	"regexp"
	"sort"
	"time"

	"github.com/misscomputer/mscomputer-miner/pkg/organic"
)

const (
	// CapabilityFeature is reserved for a miner agent that runs the sandbox
	// lane. No released miner agent advertises it yet.
	CapabilityFeature = "sandbox-lease-v1"
	// ReservationReplayFeature promises the explicit non-creating operation.
	ReservationReplayFeature = "sandbox-reservation-replay-v1"
	// EgressCapabilityFeature promises network mode public: outbound-only
	// internet behind the host firewall, with SMTP ports, private, local and
	// metadata destinations refused and per-sandbox rate limits. A
	// placement asking for public goes only to a miner advertising it.
	EgressCapabilityFeature = "sandbox-egress-v1"
	// AllowlistCapabilityFeature promises network mode allowlist: a public
	// sandbox further confined to its allow entries (hostnames resolved
	// through the profile's resolvers on every sweep, and CIDRs). A
	// placement asking for allowlist goes only to a miner advertising it.
	AllowlistCapabilityFeature = "sandbox-allowlist-v1"
	// FilesCapabilityFeature promises the sandbox files API (write, read,
	// stat, list, remove, mkdir) served through sandbox-ops-v1. It is
	// advertised whenever sandbox-ops-v1 is; there is no opt-out.
	FilesCapabilityFeature = "sandbox-files-v1"
	// DockerCapabilityFeature promises lease capability docker: a nested
	// Docker engine inside the gVisor sandbox (docs/sandbox-docker.md). It is
	// opt-in per host profile; a lease asking for docker goes only to a miner
	// advertising it.
	DockerCapabilityFeature = "sandbox-docker-v1"
	// DirectFilesCapabilityFeature promises direct file transfers: the
	// miner agent serves validator-granted uploads and downloads itself
	// over TLS on DirectFilesPort of its axon host, streamed into the
	// sandbox in one helper run. Required by policy; there is no opt-out.
	DirectFilesCapabilityFeature = "sandbox-direct-files-v1"
	// ImagePrefetchCapabilityFeature promises validator image prefetch: the
	// miner pulls a signed, digest-pinned image into its warm image cache
	// ahead of any lease (POST /v1/sandbox/image-prefetches).
	ImagePrefetchCapabilityFeature = "sandbox-image-prefetch-v1"
	// DirectFilesPort is the public TCP port of the direct-files endpoint
	// on the miner's axon IP.
	DirectFilesPort = 8094
	// DirectFilesPath is the endpoint's transfer route.
	DirectFilesPath = "/v1/direct-files"
	// DirectFileReceiptsPath, followed by the grant's nonce, serves the
	// signed receipt of a completed download once, to the holder of the
	// same grant: reverse proxies may drop the receipt trailer.
	DirectFileReceiptsPath = DirectFilesPath + "/receipts/"
	// DirectFileGrantHeader carries the base64url (no padding) canonical
	// JSON of the grant; DirectFileReceiptHeader carries the receipt the
	// same way (a trailer of a download).
	DirectFileGrantHeader   = "X-Ms-File-Grant"
	DirectFileReceiptHeader = "X-Ms-File-Receipt"
	// WorkloadKind distinguishes sandbox documents from web workloads.
	WorkloadKind = "sandbox"

	// MaxHold bounds how long a reservation may pin capacity uncommitted.
	MaxHold = 2 * time.Minute
	// MaxLeaseWindow bounds one lease or renewal window. A validator that
	// stops renewing frees the miner within MaxLeaseWindow plus Grace.
	MaxLeaseWindow = 15 * time.Minute
	// Grace is the miner-side teardown slack after a lease expires.
	Grace = 30 * time.Second
	// IssueSkew is the tolerated clock skew before issued_at.
	IssueSkew = 30 * time.Second
)

// Resource bounds per sandbox. GPU is not part of v1.
const (
	MinCPUMillis = 1000
	MaxCPUMillis = 16000
	MinMemoryMiB = 1024
	MaxMemoryMiB = 65536
	MinDiskMiB   = 5120
	MaxDiskMiB   = 102400
	MinPIDs      = 64
	MaxPIDs      = 32768
)

// Resources is one sandbox's requested allocation. It is billed and held as
// requested; there is no fixed class.
type Resources struct {
	CPUMillis int `json:"cpu_millis"`
	DiskMiB   int `json:"disk_mib"`
	MemoryMiB int `json:"memory_mib"`
	PIDs      int `json:"pids"`
}

// Validate checks the per-sandbox bounds.
func (r Resources) Validate() error {
	if r.CPUMillis < MinCPUMillis || r.CPUMillis > MaxCPUMillis || r.MemoryMiB < MinMemoryMiB || r.MemoryMiB > MaxMemoryMiB ||
		r.DiskMiB < MinDiskMiB || r.DiskMiB > MaxDiskMiB || r.PIDs < MinPIDs || r.PIDs > MaxPIDs {
		return errors.New("sandbox resources are out of bounds")
	}
	return nil
}

// Capacity is an aggregate over sandboxes: a miner's budget, or the part of
// it that holds or live leases consume.
type Capacity struct {
	CPUMillis int `json:"cpu_millis"`
	DiskMiB   int `json:"disk_mib"`
	MemoryMiB int `json:"memory_mib"`
	Sandboxes int `json:"sandboxes"`
}

// Add returns c plus one sandbox of r.
func (c Capacity) Add(r Resources) Capacity {
	return Capacity{CPUMillis: c.CPUMillis + r.CPUMillis, DiskMiB: c.DiskMiB + r.DiskMiB, MemoryMiB: c.MemoryMiB + r.MemoryMiB, Sandboxes: c.Sandboxes + 1}
}

// Plus returns the component-wise sum.
func (c Capacity) Plus(other Capacity) Capacity {
	return Capacity{CPUMillis: c.CPUMillis + other.CPUMillis, DiskMiB: c.DiskMiB + other.DiskMiB,
		MemoryMiB: c.MemoryMiB + other.MemoryMiB, Sandboxes: c.Sandboxes + other.Sandboxes}
}

// Within reports whether every component of c is non-negative and at most
// the matching component of limit.
func (c Capacity) Within(limit Capacity) bool {
	return c.CPUMillis >= 0 && c.DiskMiB >= 0 && c.MemoryMiB >= 0 && c.Sandboxes >= 0 &&
		c.CPUMillis <= limit.CPUMillis && c.DiskMiB <= limit.DiskMiB && c.MemoryMiB <= limit.MemoryMiB && c.Sandboxes <= limit.Sandboxes
}

// Network modes. Every mode is part of the v1 contract; a miner that cannot
// enforce a mode refuses the reservation with network_policy_unsupported.
const (
	NetworkNone      = "none"
	NetworkPublic    = "public"
	NetworkAllowlist = "allowlist"

	MaxAllowEntries = 64
)

// NetworkPolicy is the egress policy of one sandbox. Inbound is never open
// in v1.
type NetworkPolicy struct {
	Allow []string `json:"allow"`
	Mode  string   `json:"mode"`
}

// A hostname entry names exactly that host. v1 has no wildcard or suffix
// match: "*.example.com" is not a valid entry and "example.com" does not
// admit "api.example.com". A gateway expands a customer wildcard into exact
// hosts or a CIDR, or refuses the request; it never widens it to public.
//
// Validate requires allow to be present (an empty array, never null), empty
// unless mode is allowlist, and otherwise 1..64 sorted unique hostnames or
// canonical CIDR prefixes.
func (p NetworkPolicy) Validate() error {
	if p.Allow == nil {
		return errors.New("network allow must be an array")
	}
	switch p.Mode {
	case NetworkNone, NetworkPublic:
		if len(p.Allow) != 0 {
			return errors.New("network allow is only valid in allowlist mode")
		}
		return nil
	case NetworkAllowlist:
	default:
		return errors.New("network mode is invalid")
	}
	if len(p.Allow) == 0 || len(p.Allow) > MaxAllowEntries || !sortedUnique(p.Allow) {
		return errors.New("network allowlist must hold 1..64 sorted unique entries")
	}
	for _, entry := range p.Allow {
		if !validAllowEntry(entry) {
			return errors.New("network allowlist entry is not a hostname or canonical CIDR")
		}
	}
	return nil
}

func validAllowEntry(entry string) bool {
	if organic.ValidHostname(entry) {
		return true
	}
	prefix, err := netip.ParsePrefix(entry)
	return err == nil && prefix.Masked() == prefix && prefix.String() == entry
}

// Isolation classes. Each is a kernel boundary stronger than plain runc
// namespaces; a lease names exactly one.
const (
	IsolationGVisor      = "gvisor"
	IsolationKata        = "kata"
	IsolationFirecracker = "firecracker"
)

// ValidIsolation reports whether value is a v1 isolation class.
func ValidIsolation(value string) bool {
	switch value {
	case IsolationGVisor, IsolationKata, IsolationFirecracker:
		return true
	}
	return false
}

// Lease capabilities. A capability widens what the sandbox may do inside its
// isolation boundary; it never widens the boundary. A miner that cannot
// provide a requested capability refuses the lease with
// capability_unsupported.
const (
	// CapabilityDocker runs the sandbox under the host's docker runtime
	// profile so the guest can run its own Docker engine.
	CapabilityDocker = "docker"

	// CapabilityUnsupported refuses a lease asking for a capability the
	// miner does not provide.
	CapabilityUnsupported = "capability_unsupported"
)

// ValidateCapabilities accepts a nil or empty list, or sorted unique known
// capabilities.
func ValidateCapabilities(capabilities []string) error {
	if !sortedUnique(capabilities) {
		return errors.New("sandbox capabilities must be sorted and unique")
	}
	for _, capability := range capabilities {
		if capability != CapabilityDocker {
			return errors.New("sandbox capability is unknown")
		}
	}
	return nil
}

// HasCapability reports whether capabilities names capability.
func HasCapability(capabilities []string, capability string) bool {
	for _, value := range capabilities {
		if value == capability {
			return true
		}
	}
	return false
}

// MaxSecretNames bounds the declared environment of one sandbox. Every
// customer environment variable is declared in secret_env, so this is the
// whole customer environment, not only the variables a customer marks secret.
const MaxSecretNames = 128

var (
	envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	imagePattern   = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?/)?[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*@(sha256:[0-9a-f]{64})$`)
)

// ValidEnvName reports whether value is a portable environment name.
func ValidEnvName(value string) bool { return envNamePattern.MatchString(value) }

// ValidateEnv requires the signed env member to be an empty object (never
// null). Signed documents are persisted and may be logged by validator and
// miner, and a customer may pass a secret in any variable, so no environment
// value travels in a signed document: the gateway declares every customer
// variable in secret_env.
func ValidateEnv(env map[string]string) error {
	if env == nil {
		return errors.New("env must be an object")
	}
	if len(env) != 0 {
		return errors.New("env must be empty: customer environment is declared in secret_env")
	}
	return nil
}

// Secret delivery schemes. A signed document never carries an environment
// value. sealed-bundle-v1 names the variables and binds the digest of a
// bundle that is delivered separately. Its delivery path is not implemented
// yet, so a miner refuses every sealed-bundle-v1 lease with
// secret_delivery_unsupported; a sandbox with customer environment cannot
// start until that path exists.
const (
	SecretDeliveryNone         = "none"
	SecretDeliverySealedBundle = "sealed-bundle-v1"
)

// SecretEnv declares secret environment variables without their values.
type SecretEnv struct {
	BundleDigest *string  `json:"bundle_digest"`
	Delivery     string   `json:"delivery"`
	Names        []string `json:"names"`
}

// Validate checks the declaration shape.
func (s SecretEnv) Validate() error {
	if s.Names == nil {
		return errors.New("secret_env names must be an array")
	}
	switch s.Delivery {
	case SecretDeliveryNone:
		if len(s.Names) != 0 || s.BundleDigest != nil {
			return errors.New("secret_env without delivery carries names or a bundle")
		}
		return nil
	case SecretDeliverySealedBundle:
	default:
		return errors.New("secret_env delivery is invalid")
	}
	if s.BundleDigest == nil || !organic.ValidDigest(*s.BundleDigest) {
		return errors.New("secret_env bundle_digest is invalid")
	}
	if len(s.Names) == 0 || len(s.Names) > MaxSecretNames || !sortedUnique(s.Names) {
		return errors.New("secret_env names must be 1..128 sorted unique names")
	}
	for _, name := range s.Names {
		if !ValidEnvName(name) {
			return errors.New("secret_env name is invalid")
		}
	}
	return nil
}

// ImageDigest returns the digest pinned by an OCI reference of the form
// [registry[:port]/]repository@sha256:<hex>. Tags are not admitted: the
// validator resolves a tag before signing.
func ImageDigest(reference string) (string, bool) {
	if len(reference) > 512 {
		return "", false
	}
	match := imagePattern.FindStringSubmatch(reference)
	if match == nil {
		return "", false
	}
	return match[1], true
}

// Release reasons.
const (
	ReleaseCustomerDelete   = "customer_delete"
	ReleaseTTLExpired       = "ttl_expired"
	ReleasePlacementAborted = "placement_aborted"
	ReleaseHoldUnused       = "hold_unused"
	ReleaseHealthLost       = "liveness_lost"
	ReleaseOperator         = "operator_takedown"
)

// ValidReleaseReason reports whether value is a v1 release reason.
func ValidReleaseReason(value string) bool {
	switch value {
	case ReleaseCustomerDelete, ReleaseTTLExpired, ReleasePlacementAborted, ReleaseHoldUnused, ReleaseHealthLost, ReleaseOperator:
		return true
	}
	return false
}

// Receipt stages: held and refused answer a reservation; the rest answer a
// lease, a renewal or a release.
const (
	StageHeld     = "held"
	StageRefused  = "refused"
	StageAccepted = "accepted"
	StageReady    = "ready"
	StageFailed   = "failed"
	StageReleased = "released"
	StageExpired  = "expired"
)

// ReceiptErrorAttribution maps every receipt error code to whether it is
// attributed to the miner. Unsupported features and customer or validator
// decisions are not miner faults.
var ReceiptErrorAttribution = map[string]bool{
	"capacity_exhausted":          false,
	"resources_unsupported":       false,
	"network_policy_unsupported":  false,
	"isolation_unsupported":       false,
	"secret_delivery_unsupported": false,
	"sandbox_disabled":            false,
	"released_before_use":         false,
	"hold_expired":                false,
	"lease_expired":               false,
	"image_unavailable":           false,
	ImageTooLarge:                 false,
	"runtime_start_failed":        true,
	"miner_restart":               true,
	CapabilityUnsupported:         false,
	EgressFirewallUnavailable:     true,
}

// EgressFirewallUnavailable fails a public sandbox on a host whose profile
// promises egress but whose tenant egress firewall cannot be restored. It is
// a miner fault: sandbox-egress-v1 stays advertised.
const EgressFirewallUnavailable = "egress_firewall_unavailable"

func sortedUnique(values []string) bool {
	if !sort.StringsAreSorted(values) {
		return false
	}
	for index := 1; index < len(values); index++ {
		if values[index] == values[index-1] {
			return false
		}
	}
	return true
}
