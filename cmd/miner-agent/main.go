// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/misscomputer/mscomputer-miner/pkg/artifact"
	"github.com/misscomputer/mscomputer-miner/pkg/bridge"
	"github.com/misscomputer/mscomputer-miner/pkg/durable"
	"github.com/misscomputer/mscomputer-miner/pkg/miner"
	"github.com/misscomputer/mscomputer-miner/pkg/neuron"
	"github.com/misscomputer/mscomputer-miner/pkg/organic"
	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
	"github.com/misscomputer/mscomputer-miner/pkg/qualification"
	"github.com/misscomputer/mscomputer-miner/pkg/registrylogin"
	deployruntime "github.com/misscomputer/mscomputer-miner/pkg/runtime"
	"github.com/misscomputer/mscomputer-miner/pkg/sandbox"
	"github.com/misscomputer/mscomputer-miner/pkg/service"
)

type api struct {
	agent   *miner.Agent
	store   *durable.Store
	network string
	netuid  uint16
	hotkey  string
	uid     *uint16
	public  ed25519.PublicKey
	// sandbox is the sandbox-lease-v1 lane; nil (the default) leaves its
	// routes and capability absent.
	sandbox                  *miner.SandboxLane
	sandboxReservationReplay bool
	// qualification runs miner qualification jobs; nil (the default)
	// answers qualification_disabled.
	qualification *qualification.Runner
	// plots keeps the disk plot; nil (the default) answers
	// qualification_plot_disabled.
	plots *qualification.PlotRunner
}

func main() {
	if err := run(); err != nil {
		slog.Error("miner agent stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		bind                  = flag.String("bind", "127.0.0.1:9101", "authenticated Python-to-Go bridge address")
		allowNonLoopback      = flag.Bool("allow-non-loopback", false, "allow bridge binding beyond loopback (unsafe unless separately isolated)")
		network               = flag.String("network", "local", "Bittensor network name or endpoint identity")
		netuid                = flag.Uint("netuid", 0, "Bittensor subnet netuid")
		hotkey                = flag.String("hotkey", "", "registered miner hotkey SS58")
		uid                   = flag.Int("uid", -1, "current miner UID, or -1 when unknown")
		secretFile            = flag.String("bridge-secret-file", "", "file containing the loopback HMAC secret")
		secretEnv             = flag.String("bridge-secret-env", "MS_BRIDGE_SECRET", "environment variable fallback for the HMAC secret")
		keyFile               = flag.String("service-key-file", "", "persistent Ed25519 Go service key file")
		stateDB               = flag.String("state-db", "", "SQLite state path")
		artifactBackend       = flag.String("artifact-backend", "file", "artifact backend: pull (operator pull gateway; no storage credentials) or file (local tests)")
		artifactPullSuffix    = flag.String("artifact-pull-redirect-suffix", "", "optional: only follow pull gateway redirects to hosts ending in this suffix")
		registryLoginURL      = flag.String("image-registry-login-url", "", "image mirror login route, e.g. https://mirror.ms.computer/v1/mirror-login: sandbox pulls from that host carry a short-lived credential signed for with the service key")
		artifactPullURL       = flag.String("artifact-pull-url", "", "pull gateway route for --artifact-backend pull, e.g. https://api.ms.computer/v1/miner-artifacts")
		artifactDir           = flag.String("artifact-dir", "", "local artifact store root")
		runtimeKind           = flag.String("runtime", "docker", "runtime backend: docker (organic OCI)")
		dockerState           = flag.String("docker-state-dir", "", "per-instance organic OCI state directory")
		organicNetwork        = flag.String("organic-network", deployruntime.DefaultOrganicNetwork, "internal Docker network for organic containers")
		organicBridge         = flag.String("organic-bridge", deployruntime.DefaultOrganicBridge, "fixed host bridge interface name of the organic network")
		hostIsolation         = flag.String("host-isolation", "enforce", "host firewall rule for the organic bridge: enforce (install if missing) or verify")
		minerTransport        = flag.String("miner-transport", "https", "advertised miner transport: https, or explicit mock http")
		tlsCertificateSHA256  = flag.String("tls-certificate-sha256", "", "SHA-256 fingerprint of the configured public TLS leaf certificate")
		allowInsecureMockHTTP = flag.Bool("allow-insecure-mock-http", false, "allow pinless HTTP tickets only on an explicit local/mock network")
		staticSites           = flag.String("static-sites", "off", "static-site-v1 workload: off (default) or on")
		responseReceipts      = flag.String("response-receipts", "off", "response-receipts-v2: off (default) or on; signs one Merkle batch of per-response receipts per second with the service key and serves them to the edge")
		staticCacheDir        = flag.String("static-cache-dir", "", "private directory for verified static site files (required with --static-sites on)")
		staticCacheMaxBytes   = flag.Int64("static-cache-max-bytes", 8<<30, "byte quota of pinned static site files")
		staticFetchTimeout    = flag.Duration("static-fetch-timeout", miner.DefaultStaticFetchTimeout, "bound on fetching and verifying one static site")
		staticConcurrency     = flag.Int("static-request-concurrency", miner.DefaultStaticRequestConcurrency, "in-flight requests per static endpoint")
		sandboxReplay         = flag.String("sandbox-reservation-replay", "off", "existing-hold-only replay: off (default) or on; requires --sandbox-leases on")
		sandboxLeases         = flag.String("sandbox-leases", "off", "sandbox-lease-v1 workload: off (default) or on (gVisor on a dedicated Docker daemon; the host preflight report must pass)")
		sandboxHostProfile    = flag.String("sandbox-host-profile", "", "sandbox-host-profile.v1 document of this host (required with --sandbox-leases on)")
		sandboxDeployment     = flag.String("sandbox-deployment-cgroup", "", "cgroup v2 path deployment.v4 replicas run in, kept disjoint from sandboxes (required with --sandbox-leases on)")
		sandboxDaemonConfig   = flag.String("sandbox-daemon-config", "", "configuration file of the dedicated sandbox Docker daemon (required with --sandbox-leases on)")
		sandboxOpsMode        = flag.String("sandbox-ops", "off", "sandbox-ops-v1 exec and file operations: off (default) or on; requires --sandbox-leases on and --sandbox-ops-config")
		sandboxImageCap       = flag.Int("sandbox-max-tenant-image-mib", 0, "tenant image cap in MiB: 0 (default) is the network-wide 10240; a smaller explicit value (1024..10240) only with --network test --netuid 581")
		sandboxPinnedImages   = flag.String("sandbox-pinned-images", "", "comma-separated image digests (sha256:...) the sandbox image cache never evicts, e.g. sandbox-base; requires --sandbox-leases on")
		sandboxOpsConfig      = flag.String("sandbox-ops-config", "", "sandbox-ops-v1 helper pin and parameters (required with --sandbox-ops on)")
		directFilesBind       = flag.String("direct-files-bind", "", "TLS listen address of the direct file transfer endpoint (sandbox-direct-files-v1; public port "+strconv.Itoa(sandbox.DirectFilesPort)+" on the axon IP); requires --sandbox-ops on")
		directFilesCert       = flag.String("direct-files-tls-cert", "", "TLS certificate file of the direct-files endpoint: the axon's own (its leaf must equal --tls-certificate-sha256)")
		directFilesKey        = flag.String("direct-files-tls-key", "", "TLS private key file of the direct-files endpoint: the axon's own")
		directFilesPerSandbox = flag.Int("direct-files-per-sandbox", 0, "direct transfers in flight per sandbox (0: default 4)")
		directFilesGlobal     = flag.Int("direct-files-global", 0, "direct transfers in flight per miner (0: default 8)")
		qualificationMode     = flag.String("qualification", "off", "PROVISIONAL miner qualification jobs: off (default) or on")
		qualificationFillMiB  = flag.Int("qualification-max-fill-mib", 0, "largest qualification fill accepted in MiB (0: PROVISIONAL default 16384)")
		qualificationWindow   = flag.Duration("qualification-max-window", 0, "longest qualification challenge window accepted (0: default 5m)")
		qualificationJobs     = flag.Int("qualification-jobs-per-hour", 0, "qualification jobs accepted per validator per hour (0: PROVISIONAL default 4)")
		qualificationPlotDir  = flag.String("qualification-plot-dir", "", "private directory (mode 0700, under the agent data directory) for the PROVISIONAL disk plot; empty (default) disables the plot routes")
		qualificationWorkers  = flag.Int("qualification-plot-workers", 0, "plot chunks built at once, each held in memory until written (0: PROVISIONAL default 1)")
		qualificationPlotMiB  = flag.Int("qualification-plot-max-mib", 0, "largest disk plot accepted in MiB (0: PROVISIONAL default 262144)")
		qualificationPlotIdle = flag.Duration("qualification-plot-idle", 0, "a complete plot not spot-checked by its validator for this long may be replaced by another validator (0: PROVISIONAL default 36h)")
		qualificationRehash   = flag.Bool("qualification-plot-rehash-on-resume", false, "re-hash every stored plot block on startup (reads the whole plot)")
		systemReserveMiB      = flag.Int("system-reserve-mib", miner.DefaultSystemReserveMiB, "host memory in MiB kept for the system")
		sandboxReserveMiB     = flag.Int("sandbox-reserve-mib", miner.DefaultSandboxReserveMiB, "host memory in MiB guaranteed to each sandbox reserve")
		appBudgetMiB          = flag.Int("app-budget-mib", miner.DefaultAppBudgetMiB, "app site (deployment.v4) memory budget in MiB of a 16 GiB host, scaled by host memory; 0 disables admission accounting (the app slice still applies). The hard limit is the app slice MemoryMax, installed from --app-budget-print")
		appCopyMiB            = flag.Int("app-copy-mib", miner.DefaultAppCopyMiB, "MiB each app replica counts against the app budget")
		appCPUWeight          = flag.Int("app-cpu-weight", miner.DefaultAppCPUWeight, "CPUWeight the app slice should have (below the sandbox and health-check slices)")
		appCgroupParentFlag   = flag.String("app-cgroup-parent", "", "systemd slice app replicas run in (empty: the --sandbox-deployment-cgroup slice; none: Docker's default)")
		hostMemoryMiBFlag     = flag.Int("host-memory-mib", 0, "host memory in MiB for the app budget plan (0: MemTotal rounded up to a GiB)")
		hostVCPUsFlag         = flag.Int("host-vcpus", 0, "host vCPUs for the app budget plan (0: auto)")
		appBudgetPrint        = flag.Bool("app-budget-print", false, "print this host's app budget plan and app slice drop-in, then exit")
	)
	flag.Parse()
	appOptions := appBudgetOptions{
		Config: miner.AppBudgetConfig{
			SystemReserveMiB: *systemReserveMiB, SandboxReserveMiB: *sandboxReserveMiB, AppBudgetMiB: *appBudgetMiB, AppCopyMiB: *appCopyMiB,
		},
		CPUWeight: *appCPUWeight, HostMemoryMiB: *hostMemoryMiBFlag, HostVCPUs: *hostVCPUsFlag,
	}
	appPlan, err := planHostAppBudget(appOptions)
	if err != nil {
		return fmt.Errorf("app budget: %w", err)
	}
	if appOptions.CgroupParent, err = appCgroupParent(*appCgroupParentFlag, *sandboxDeployment); err != nil {
		return err
	}
	if *appBudgetPrint {
		encoded, err := json.MarshalIndent(appPlan, "", "  ")
		if err != nil {
			return err
		}
		fmt.Printf("%s\n# %s drop-in\n%s", encoded, appOptions.CgroupParent, appSliceDropIn(appPlan, *appCPUWeight))
		return nil
	}
	if *sandboxReplay != "off" && *sandboxReplay != "on" {
		return errors.New("unsupported --sandbox-reservation-replay mode")
	}
	if *sandboxReplay == "on" && *sandboxLeases != "on" {
		return errors.New("--sandbox-reservation-replay on requires --sandbox-leases on")
	}
	opsSettings, err := loadSandboxOps(*sandboxOpsMode, *sandboxOpsConfig, *sandboxLeases)
	if err != nil {
		return err
	}
	directSettings, err := loadDirectFiles(*directFilesBind, *directFilesCert, *directFilesKey, *tlsCertificateSHA256, opsSettings != nil,
		*directFilesPerSandbox, *directFilesGlobal)
	if err != nil {
		return err
	}
	if *qualificationMode != "off" && *qualificationMode != "on" {
		return errors.New("unsupported --qualification mode")
	}
	plotSettings := plotPolicy{
		Dir: *qualificationPlotDir, Workers: *qualificationWorkers, MaxMiB: *qualificationPlotMiB, Idle: *qualificationPlotIdle,
		Rehash: *qualificationRehash,
	}
	if err := validatePlotPolicy(*qualificationMode, plotSettings); err != nil {
		return err
	}
	if err := service.ValidateBind(*bind, *allowNonLoopback); err != nil {
		return err
	}
	if strings.TrimSpace(*network) == "" || *hotkey == "" || *keyFile == "" || *stateDB == "" {
		return errors.New("network, hotkey, service-key-file, and state-db are required")
	}
	if *netuid > 65535 || *uid < -1 || *uid > 65535 {
		return errors.New("netuid or UID exceeds uint16")
	}
	if *minerTransport == neuron.TransportHTTPS {
		if !neuron.CanonicalSHA256(*tlsCertificateSHA256) {
			return errors.New("HTTPS miner transport requires a canonical lowercase TLS certificate SHA-256")
		}
	} else if *minerTransport != neuron.TransportHTTP || *tlsCertificateSHA256 != "" || !*allowInsecureMockHTTP || !localMockNetwork(*network) {
		return errors.New("pinless HTTP miner transport requires --allow-insecure-mock-http on an explicit local/mock network")
	}
	secret, err := bridge.LoadSecret(*secretFile, *secretEnv)
	if err != nil {
		return err
	}
	privateKey, err := service.LoadOrCreateSigningKey(*keyFile)
	if err != nil {
		return err
	}
	store, err := durable.Open(*stateDB)
	if err != nil {
		return err
	}
	defer store.Close()
	artifacts, err := openArtifacts(artifactConfig{
		Backend: *artifactBackend, Dir: *artifactDir, PullURL: *artifactPullURL, PullRedirectSuffix: *artifactPullSuffix,
		Network: *network, NetUID: uint16(*netuid), Hotkey: *hotkey, ServiceKey: privateKey,
	})
	if err != nil {
		return err
	}
	if *runtimeKind != "docker" {
		return fmt.Errorf("unsupported runtime %q", *runtimeKind)
	}
	organicRuntime, err := openOrganicRuntime(artifacts, *dockerState, *organicNetwork, *organicBridge, *hostIsolation, appOptions.CgroupParent)
	if err != nil {
		return err
	}
	registry := miner.NewEndpointRoutes()
	agent := miner.NewAgent(*hotkey, nil, privateKey, artifacts, organicRuntime, registry)
	if *appBudgetMiB > 0 {
		copies := sliceAppCopies("/sys/fs/cgroup", appOptions.CgroupParent, appPlan, *appCPUWeight)
		agent.EnableAppBudget(copies)
		slog.Info("app budget", "host_memory_mib", appPlan.HostMemoryMiB, "host_vcpus", appPlan.HostVCPUs, "sandboxes", appPlan.Sandboxes,
			"app_budget_mib", appPlan.AppBudgetMiB, "app_copy_mib", appPlan.AppCopyMiB, "app_copies", copies, "app_slice", appOptions.CgroupParent)
	}
	agent.State = store
	agent.MinerTransport = *minerTransport
	agent.MinerTLSCertificateSHA256 = *tlsCertificateSHA256
	if agent.Static, err = openStaticSites(*staticSites, *staticCacheDir, *staticCacheMaxBytes, *staticFetchTimeout, *staticConcurrency); err != nil {
		return err
	}
	switch *responseReceipts {
	case "off":
	case "on":
		if agent.Receipts, err = miner.NewReceiptRecorder(privateKey, miner.DefaultReceiptRecorderConfig()); err != nil {
			return err
		}
	default:
		return errors.New("--response-receipts must be off or on")
	}
	if agent.Receipts != nil {
		// Run until after the server has flushed, then flush every
		// pending leaf: a planned restart owes the edge no receipts.
		receiptsCtx, receiptsStop := context.WithCancel(context.Background())
		receiptsDone := make(chan struct{})
		go func() { agent.Receipts.Run(receiptsCtx); close(receiptsDone) }()
		defer func() { receiptsStop(); <-receiptsDone }()
	}
	sandboxCtx, sandboxCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	options := sandboxOptions{
		Mode: *sandboxLeases, HostProfile: *sandboxHostProfile, DeploymentCgroup: *sandboxDeployment, DaemonConfig: *sandboxDaemonConfig,
		ImageCapMiB: *sandboxImageCap, PinnedImages: *sandboxPinnedImages, Network: *network, NetUID: *netuid,
	}
	if *registryLoginURL != "" {
		login := &registrylogin.Client{URL: *registryLoginURL, Network: *network, NetUID: uint16(*netuid), Hotkey: *hotkey, ServiceKey: privateKey}
		if err := login.Validate(); err != nil {
			sandboxCancel()
			return fmt.Errorf("--image-registry-login-url: %w", err)
		}
		options.RegistryLogin = login
	}
	if opsSettings != nil {
		options.OpsHelper = &opsSettings.helper
		options.NetworkStateDir = filepath.Join(filepath.Dir(*stateDB), "sandbox-network")
	}
	sandboxLane, err := openSandboxLeases(sandboxCtx, options, agent, store)
	sandboxCancel()
	if err != nil {
		return err
	}
	recoveryCtx, recoveryCancel := context.WithTimeout(context.Background(), 30*time.Second)
	if err := agent.RecoverCleanup(recoveryCtx); err != nil {
		recoveryCancel()
		return fmt.Errorf("restart cleanup: %w", err)
	}
	recoveryCancel()
	if sandboxLane != nil {
		// Its own budget: recovery may remove every sandbox left running.
		sandboxRecovery, sandboxRecoveryCancel := context.WithTimeout(context.Background(), sandboxRecoveryTimeout)
		err := sandboxLane.Recover(sandboxRecovery)
		sandboxRecoveryCancel()
		if err != nil {
			return fmt.Errorf("sandbox restart cleanup: %w", err)
		}
		if opsSettings != nil {
			// After both startup Recover steps, before serving.
			opsCtx, opsCancel := context.WithTimeout(context.Background(), 30*time.Second)
			err := enableSandboxOps(opsCtx, sandboxLane, store, opsSettings)
			opsCancel()
			if err != nil {
				return fmt.Errorf("sandbox ops: %w", err)
			}
			if directSettings != nil {
				if err := sandboxLane.EnableDirectFiles(directSettings.config); err != nil {
					return fmt.Errorf("direct files: %w", err)
				}
			}
		}
	}
	var minerUID *uint16
	if *uid >= 0 {
		value := uint16(*uid)
		minerUID = &value
	}
	qualificationRunner, err := openQualification(*qualificationMode, qualificationPolicy{MaxFillMiB: *qualificationFillMiB, MaxWindow: *qualificationWindow, JobsPerHour: *qualificationJobs})
	if err != nil {
		return err
	}
	if qualificationRunner != nil {
		qualificationRunner.Key, qualificationRunner.Network, qualificationRunner.NetUID = agent.SigningKey, *network, uint16(*netuid)
		qualificationRunner.Hotkey, qualificationRunner.UID = *hotkey, minerUID
	}
	var plotRunner *qualification.PlotRunner
	if plotSettings.Dir != "" {
		plotRunner, err = qualification.OpenPlots(qualification.PlotConfig{
			Dir: plotSettings.Dir, Key: agent.SigningKey, Network: *network, NetUID: uint16(*netuid), Hotkey: *hotkey, UID: minerUID,
			Workers: plotSettings.Workers, MaxPlotMiB: plotSettings.MaxMiB, IdleTimeout: plotSettings.Idle,
			RehashOnResume: plotSettings.Rehash,
		})
		if err != nil {
			return fmt.Errorf("qualification plots: %w", err)
		}
		defer plotRunner.Close()
	}
	serviceAPI := &api{
		agent: agent, store: store, network: *network, netuid: uint16(*netuid), hotkey: *hotkey, uid: minerUID,
		public: privateKey.Public().(ed25519.PublicKey), sandbox: sandboxLane, sandboxReservationReplay: *sandboxReplay == "on",
		qualification: qualificationRunner, plots: plotRunner,
	}
	protected := serviceAPI.routes()
	authenticator := bridge.Authenticator{Secret: secret, Store: store}
	root := http.NewServeMux()
	root.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	root.Handle("/v1/", authenticator.Middleware(protected))
	server := &http.Server{
		Addr: *bind, Handler: bridgeHandler(root, authenticator.Middleware(agent.RuntimeIngressHandler(runtimePrefix))),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second,
		WriteTimeout: 2 * time.Minute, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10,
	}
	shutdownCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if sandboxLane != nil {
		go sweepSandboxes(shutdownCtx, sandboxLane)
	}
	errorsChannel := make(chan error, 2)
	if directSettings != nil && sandboxLane != nil && sandboxLane.DirectFilesEnabled() {
		directServer := newDirectFilesServer(directSettings, sandboxLane)
		go func() {
			slog.Info("direct files endpoint ready", "bind", directSettings.bind)
			if err := serveDirectFiles(shutdownCtx, directServer); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errorsChannel <- fmt.Errorf("direct files endpoint: %w", err)
			}
		}()
	}
	go func() {
		slog.Info("miner agent ready", "bind", *bind, "network", *network, "netuid", *netuid, "hotkey", *hotkey)
		errorsChannel <- server.ListenAndServe()
	}()
	var serveErr error
	select {
	case err := <-errorsChannel:
		if !errors.Is(err, http.ErrServerClosed) {
			serveErr = err
		}
	case <-shutdownCtx.Done():
	}
	var lane sandboxStopper
	if sandboxLane != nil {
		lane = sandboxLane
	}
	if err := stopAgent(server, agent.RecoverCleanup, lane, agentStopBudgets); serveErr == nil {
		serveErr = err
	}
	return serveErr
}

// stopBudgets bound the phases of the agent's shutdown. Their sum is the
// longest the agent takes to stop; a service manager's stop timeout must
// exceed it (docs/miner-quickstart.md).
type stopBudgets struct {
	// serve bounds server.Shutdown and the sandbox lane's Close together:
	// both start at the signal and share one deadline.
	serve time.Duration
	// cleanup bounds the agent's own replica cleanup.
	cleanup time.Duration
	// sandbox bounds the sandbox lane's shutdown Recover, which runs after
	// the cleanup on a budget of its own.
	sandbox time.Duration
}

var agentStopBudgets = stopBudgets{serve: 15 * time.Second, cleanup: 30 * time.Second, sandbox: 60 * time.Second}

type shutdowner interface {
	Shutdown(ctx context.Context) error
}

// sandboxStopper is the part of the sandbox lane the shutdown drives.
type sandboxStopper interface {
	Close(ctx context.Context) error
	Recover(ctx context.Context) error
}

// stopAgent runs the shutdown after the signal. The sandbox lane closes
// while the server flushes, on the same deadline, so neither adds to the
// other's time; then the agent cleans up its replicas, and then the lane's
// Recover destroys every sandbox once nothing else holds a lease lock. A
// phase that fails or runs out of time does not stop the later ones.
func stopAgent(server shutdowner, cleanup func(context.Context) error, lane sandboxStopper, budgets stopBudgets) error {
	var errs []error
	serveCtx, cancelServe := context.WithTimeout(context.Background(), budgets.serve)
	closed := make(chan error, 1)
	if lane != nil {
		go func() { closed <- lane.Close(serveCtx) }()
	} else {
		closed <- nil
	}
	if err := server.Shutdown(serveCtx); err != nil {
		errs = append(errs, err)
	}
	if err := <-closed; err != nil {
		errs = append(errs, err)
	}
	cancelServe()
	cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), budgets.cleanup)
	if err := cleanup(cleanupCtx); err != nil {
		errs = append(errs, fmt.Errorf("shutdown cleanup: %w", err))
	}
	cancelCleanup()
	if lane != nil {
		recoverCtx, cancelRecover := context.WithTimeout(context.Background(), budgets.sandbox)
		if err := lane.Recover(recoverCtx); err != nil {
			errs = append(errs, fmt.Errorf("sandbox shutdown cleanup: %w", err))
		}
		cancelRecover()
	}
	return errors.Join(errs...)
}

// routes is the authenticated bridge API. Sandbox routes exist only with an
// enabled sandbox lane.
func (a *api) routes() *http.ServeMux {
	protected := http.NewServeMux()
	protected.HandleFunc("GET /v1/capabilities", a.capabilities)
	protected.HandleFunc("POST /v1/assignments", a.assign)
	protected.HandleFunc("POST /v1/status", a.status)
	protected.HandleFunc("POST /v1/deactivate", a.deactivate)
	protected.HandleFunc("POST /v1/static/assignments", a.assignStatic)
	protected.HandleFunc("POST /v1/static/status", a.staticStatus)
	protected.HandleFunc("POST /v1/qualification/jobs", a.qualificationJob)
	protected.HandleFunc("POST /v1/qualification/openings", a.qualificationOpenings)
	protected.HandleFunc("POST /v1/qualification/plots", a.qualificationPlot)
	protected.HandleFunc("POST /v1/qualification/plots/status", a.qualificationPlotStatus)
	protected.HandleFunc("POST /v1/qualification/plot-spots", a.qualificationPlotSpot)
	protected.HandleFunc("POST /v1/qualification/plot-seals", a.qualificationPlotSeal)
	if a.sandbox != nil {
		a.registerSandboxRoutes(protected)
	}
	return protected
}

// openOrganicRuntime configures Docker for organic OCI replicas and proves
// the isolation prerequisites before the miner may advertise organic-oci-v1.
func openOrganicRuntime(artifacts artifact.Store, stateDir, network, bridgeName, hostIsolation, cgroupParent string) (deployruntime.OCIRuntime, error) {
	if _, ok := artifacts.(artifact.BlobOpener); !ok {
		return nil, errors.New("organic runtime requires a streaming artifact store")
	}
	if hostIsolation != "enforce" && hostIsolation != "verify" {
		return nil, fmt.Errorf("unsupported host isolation mode %q", hostIsolation)
	}
	runtime := deployruntime.NewDockerOCIRuntime("docker", stateDir, network, bridgeName)
	runtime.CgroupParent = cgroupParent
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := runtime.VerifyCgroupParent(ctx); err != nil {
		return nil, fmt.Errorf("%w (set --app-cgroup-parent none to keep Docker's default parent)", err)
	}
	if err := runtime.EnsureNetwork(ctx); err != nil {
		return nil, err
	}
	if err := runtime.EnsureHostIsolation(ctx, hostIsolation == "enforce"); err != nil {
		return nil, err
	}
	return runtime, nil
}

// runtimePrefix is the bridge path of the runtime proxy. The Python axon
// forwards /runtime/<endpoint_id>/<path>?<query> here byte-exact.
const runtimePrefix = "/v1/runtime/"

// bridgeHandler routes the runtime proxy around ServeMux, whose path cleaning
// would redirect application paths such as "//" or "/./" instead of
// forwarding them exactly, and serves every other bridge route through mux.
// Runtime requests pass the same bridge HMAC before edge authorization.
func bridgeHandler(mux http.Handler, runtime http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if strings.HasPrefix(req.URL.EscapedPath(), runtimePrefix) {
			runtime.ServeHTTP(w, req)
			return
		}
		mux.ServeHTTP(w, req)
	})
}

func localMockNetwork(network string) bool {
	normalized := strings.ToLower(strings.TrimSpace(network))
	return normalized == "local" || normalized == "mock" || strings.HasPrefix(normalized, "mock-")
}

func (a *api) capabilities(w http.ResponseWriter, req *http.Request) {
	var certificatePin *string
	if a.agent.MinerTLSCertificateSHA256 != "" {
		pin := a.agent.MinerTLSCertificateSHA256
		certificatePin = &pin
	}
	writeJSON(w, http.StatusOK, neuron.LocalCapabilities{
		Protocol: neuron.SynapseVersion, Network: a.network, NetUID: a.netuid, MinerHotkey: a.hotkey, MinerUID: a.uid,
		ServicePublicKey: hex.EncodeToString(a.public), Transport: a.agent.MinerTransport, TransportCertificateSHA256: certificatePin,
		Features: a.features(), MaxBodyBytes: bridge.MaxBodyBytes, CachedImages: a.cachedImages(req),
	})
}

// cachedImagesTimeout bounds the inventory read of one capability request.
const cachedImagesTimeout = 2 * time.Second

// cachedImagesQuery is the query a neuron sends to ask for cached_images. A
// neuron that predates the member refuses it, so it is reported only on
// request.
const cachedImagesQuery = "cached_images"

// cachedImages is the sandbox image inventory the capability response
// reports, most recently used first. It is optional: unless the request asks
// for it, without a sandbox lane, or when the inventory cannot be read in
// time, the member is omitted.
func (a *api) cachedImages(req *http.Request) []string {
	if a.sandbox == nil || req.URL.Query().Get(cachedImagesQuery) != "1" {
		return nil
	}
	ctx, cancel := context.WithTimeout(req.Context(), cachedImagesTimeout)
	defer cancel()
	digests, err := a.sandbox.CachedImages(ctx)
	if err != nil {
		slog.Warn("sandbox image inventory unavailable; capability response omits cached_images", "err", err)
		return nil
	}
	return digests
}

// features advertises organic-oci-v1 only when an OCI runtime whose network
// and host isolation were verified at startup is configured; validators
// treat its absence as ineligibility.
func (a *api) features() []string {
	features := []string{"deploy", "status", "deactivate", "runtime-proxy"}
	if a.agent.OCI != nil {
		features = append(features, neuron.FeatureOrganicOCIV1)
		if copies, enforced := a.agent.AppCopies(); enforced {
			features = append(features, miner.AppCopiesFeature(copies))
		}
	}
	if a.agent.Static != nil {
		features = append(features, neuron.FeatureOrganicStaticV1)
	}
	if a.agent.Receipts != nil {
		features = append(features, organic.ResponseReceiptsCapability)
	}
	if a.sandbox != nil {
		features = append(features, sandbox.CapabilityFeature)
		if a.sandboxReservationReplay {
			features = append(features, sandbox.ReservationReplayFeature)
		}
		if a.sandbox.OpsEnabled() {
			features = append(features, sandbox.OpsCapabilityFeature, sandbox.FilesCapabilityFeature)
		}
		if a.sandbox.DirectFilesEnabled() {
			features = append(features, sandbox.DirectFilesCapabilityFeature)
		}
		if a.sandbox.EgressEnabled() {
			features = append(features, sandbox.EgressCapabilityFeature, sandbox.AllowlistCapabilityFeature)
		}
		if a.sandbox.DockerEnabled() {
			features = append(features, sandbox.DockerCapabilityFeature)
		}
		if a.sandbox.ImagePrefetchEnabled() {
			features = append(features, sandbox.ImagePrefetchCapabilityFeature)
		}
	}
	return features
}

// assign accepts only the organic envelope. Synthetic lab assignments are
// retired and must not reach identity or runtime work.
func (a *api) assign(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(io.LimitReader(req.Body, bridge.MaxBodyBytes+1))
	if err != nil || len(body) > bridge.MaxBodyBytes {
		bridge.WriteError(w, http.StatusBadRequest, "invalid_request", "assignment body is unreadable or too large", false)
		return
	}
	var envelope struct {
		Protocol string `json:"protocol"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		bridge.WriteError(w, http.StatusBadRequest, "invalid_request", err.Error(), false)
		return
	}
	if envelope.Protocol != neuron.OrganicSynapseVersion {
		bridge.WriteError(w, http.StatusBadRequest, "version_mismatch", "only subnet-synapse.v3 organic assignments are accepted", false)
		return
	}
	a.assignOrganic(w, req, body)
}

// assignOrganic is the network organic path. The strict TicketV4 decode
// rejects every deployment.v1-v3 ticket and every synthetic challenge field
// before any identity or runtime work. A signed failed receipt is answered
// as a result so the scheduler can attribute its error_code.
func (a *api) assignOrganic(w http.ResponseWriter, req *http.Request, body []byte) {
	var input neuron.LocalAssignRequestV3
	if err := decodeJSON(bytes.NewReader(body), &input); err != nil {
		bridge.WriteError(w, http.StatusBadRequest, "invalid_request", err.Error(), false)
		return
	}
	if !input.BindingVerified {
		bridge.WriteError(w, http.StatusForbidden, "binding_unverified", "validator hotkey service binding was not verified", false)
		return
	}
	if err := input.Validate(); err != nil {
		bridge.WriteError(w, http.StatusBadRequest, "invalid_request", err.Error(), false)
		return
	}
	result, err := a.assignBound(req, input.RequestID, input.CurrentBlock, input.CallerHotkey, input.ValidatorBinding, protocol.TicketFromV4(input.Ticket))
	if err != nil && (result.Receipt.Stage != protocol.StageFailed || result.Receipt.Signature == "") {
		status, code, retryable := assignmentError(err)
		bridge.WriteError(w, status, code, err.Error(), retryable)
		return
	}
	minerResult, convertErr := neuron.MinerResultFromV4(result.Receipt)
	if convertErr != nil {
		bridge.WriteError(w, http.StatusInternalServerError, "assignment_failed", convertErr.Error(), false)
		return
	}
	writeJSON(w, http.StatusOK, neuron.DeployResponseV3{
		Protocol: neuron.OrganicSynapseVersion, RequestID: input.RequestID, Result: minerResult, Idempotent: result.Idempotent,
	})
}

// bridgeError carries an exact bridge status for assignBound's callers.
type bridgeError struct {
	status int
	code   string
	err    error
}

func (e *bridgeError) Error() string { return e.err.Error() }

func (a *api) assignBound(req *http.Request, requestID string, currentBlock uint64, callerHotkey string, binding neuron.ServiceKeyBinding, ticket protocol.Ticket) (miner.Result, error) {
	if ticket.Version != protocol.OrganicVersion {
		return miner.Result{}, &bridgeError{http.StatusBadRequest, "version_mismatch", errors.New("only deployment.v4 tickets are accepted")}
	}
	if requestID == "" {
		return miner.Result{}, &bridgeError{http.StatusForbidden, "binding_unverified", errors.New("request_id is required")}
	}
	key, err := a.acceptValidatorBinding(req, currentBlock, callerHotkey, binding)
	if err != nil {
		return miner.Result{}, err
	}
	v4, err := ticket.V4()
	if err != nil {
		return miner.Result{}, err
	}
	result, err := a.agent.AssignBoundV4(req.Context(), v4, key, currentBlock, a.network, a.netuid, callerHotkey, a.hotkey, a.uid)
	return miner.Result{Receipt: protocol.ReceiptFromV4(result.Receipt), EndpointID: result.EndpointID, Idempotent: result.Idempotent}, err
}

func (a *api) status(w http.ResponseWriter, req *http.Request) {
	var input neuron.StatusSynapse
	if err := decodeJSON(req.Body, &input); err != nil {
		bridge.WriteError(w, http.StatusBadRequest, "invalid_request", err.Error(), false)
		return
	}
	if input.Protocol != neuron.SynapseVersion || input.RequestID == "" {
		bridge.WriteError(w, http.StatusBadRequest, "version_mismatch", "unsupported status contract", false)
		return
	}
	if _, static, err := a.agent.StaticRecord(req.Context(), input.EndpointID); err != nil {
		bridge.WriteError(w, http.StatusInternalServerError, "state_error", err.Error(), true)
		return
	} else if static {
		bridge.WriteError(w, http.StatusConflict, "static_endpoint", "static endpoints answer only subnet-static-synapse.v1 status", false)
		return
	}
	ticket, status, exists, err := a.store.AssignmentTicket(req.Context(), input.EndpointID)
	if err != nil {
		bridge.WriteError(w, http.StatusInternalServerError, "state_error", err.Error(), true)
		return
	}
	if !exists {
		writeJSON(w, http.StatusOK, neuron.StatusResponseV3{Protocol: neuron.OrganicSynapseVersion, RequestID: input.RequestID, Status: "absent"})
		return
	}
	if ticket.Subnet == nil || ticket.Subnet.ValidatorHotkey != input.CallerHotkey {
		bridge.WriteError(w, http.StatusForbidden, "identity_mismatch", "assignment belongs to another validator", false)
		return
	}
	if err := a.agent.ValidateSubnetTransport(ticket); err != nil {
		bridge.WriteError(w, http.StatusForbidden, "identity_mismatch", err.Error(), false)
		return
	}
	receipt, found, err := a.store.CachedResult(req.Context(), input.EndpointID)
	if err != nil {
		bridge.WriteError(w, http.StatusInternalServerError, "state_error", err.Error(), true)
		return
	}
	// Status is answered only in its subnet-synapse.v3 form.
	response := neuron.StatusResponseV3{Protocol: neuron.OrganicSynapseVersion, RequestID: input.RequestID, Status: status}
	if found {
		v4, err := receipt.V4()
		if err != nil {
			bridge.WriteError(w, http.StatusInternalServerError, "state_error", err.Error(), false)
			return
		}
		response.Receipt = &v4
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *api) deactivate(w http.ResponseWriter, req *http.Request) {
	var input neuron.DeactivateSynapse
	if err := decodeJSON(req.Body, &input); err != nil {
		bridge.WriteError(w, http.StatusBadRequest, "invalid_request", err.Error(), false)
		return
	}
	if input.Protocol != neuron.SynapseVersion || input.RequestID == "" {
		bridge.WriteError(w, http.StatusBadRequest, "version_mismatch", "unsupported deactivation contract", false)
		return
	}
	if handled := a.deactivateStatic(w, req, input); handled {
		return
	}
	ticket, _, exists, err := a.store.AssignmentTicket(req.Context(), input.EndpointID)
	if err != nil {
		bridge.WriteError(w, http.StatusInternalServerError, "state_error", err.Error(), true)
		return
	}
	if !exists {
		if err := a.agent.FenceDeactivation(req.Context(), input.EndpointID, input.DeploymentID, input.CallerHotkey); err != nil {
			bridge.WriteError(w, http.StatusConflict, "cleanup_failed", err.Error(), false)
			return
		}
		writeJSON(w, http.StatusOK, neuron.DeactivateResponse{Protocol: neuron.SynapseVersion, RequestID: input.RequestID, Status: "deactivated"})
		return
	}
	if ticket.DeploymentID != input.DeploymentID || ticket.Subnet == nil || ticket.Subnet.ValidatorHotkey != input.CallerHotkey {
		bridge.WriteError(w, http.StatusForbidden, "identity_mismatch", "deactivation does not own this endpoint", false)
		return
	}
	if err := a.agent.ValidateSubnetTransport(ticket); err != nil {
		bridge.WriteError(w, http.StatusForbidden, "identity_mismatch", err.Error(), false)
		return
	}
	if err := a.agent.Deactivate(req.Context(), input.EndpointID); err != nil {
		bridge.WriteError(w, http.StatusBadGateway, "cleanup_failed", err.Error(), true)
		return
	}
	writeJSON(w, http.StatusOK, neuron.DeactivateResponse{Protocol: neuron.SynapseVersion, RequestID: input.RequestID, Status: "deactivated"})
}

func optionalString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func assignmentError(err error) (int, string, bool) {
	var exact *bridgeError
	if errors.As(err, &exact) {
		return exact.status, exact.code, false
	}
	if errors.Is(err, miner.ErrAppBudgetExhausted) {
		return http.StatusServiceUnavailable, "app_budget_exhausted", true
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "replayed") || strings.Contains(message, "already"):
		return http.StatusConflict, "replayed_assignment", false
	case strings.Contains(message, "expired") || strings.Contains(message, "not valid"):
		return http.StatusGone, "expired_assignment", false
	case strings.Contains(message, "hotkey") || strings.Contains(message, "signature") || strings.Contains(message, "subnet") || strings.Contains(message, "uid") ||
		strings.Contains(message, "service key") || strings.Contains(message, "transport") || strings.Contains(message, "certificate pin"):
		return http.StatusForbidden, "identity_mismatch", false
	default:
		return http.StatusUnprocessableEntity, "assignment_failed", false
	}
}

func decodeJSON(reader io.Reader, output any) error {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request must contain one JSON value")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
