// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package qualification

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/misscomputer/mscomputer-miner/pkg/organic"
)

// Plot refusals. Each is one stable bridge code.
var (
	ErrPlotSlotsFull       = errors.New("qualification_plot_slots_full")
	ErrPlotWriteFailed     = errors.New("qualification_plot_write_failed")
	ErrPlotReadFailed      = errors.New("qualification_plot_read_failed")
	ErrPlotAbsent          = errors.New("qualification_plot_absent")
	ErrPlotBuilding        = errors.New("qualification_plot_building")
	ErrPlotDeadline        = errors.New("qualification_plot_deadline_exceeded")
	ErrPlotRequestMismatch = errors.New("qualification_plot_request_mismatch")
	// ErrPlotSealPending is retryable: the agent is recomputing the chunk's
	// lower layers for a seal request; send the same request again later.
	ErrPlotSealPending = errors.New("qualification_plot_seal_pending")
	// ErrPlotChunkSealed refuses a seal request for a chunk the agent has
	// already recomputed for another request of this plot: each chunk is
	// recomputed for a seal at most once per plot.
	ErrPlotChunkSealed = errors.New("qualification_plot_chunk_sealed")
)

// Plot policy (PROVISIONAL). An operator may lower the sizes and counts.
const (
	// MaxPlots is the number of plots one agent keeps, across validators.
	MaxPlots = 1
	// DefaultMaxPlotMiB is 256 GiB.
	DefaultMaxPlotMiB = 256 << 10
	// DefaultPlotsPerValidator new plots per DefaultPlotsWindow, per validator.
	DefaultPlotsPerValidator = 4
	DefaultPlotsWindow       = 24 * time.Hour
	// DefaultPlotWorkers chunks are built at once, each holding its chunk
	// (1 GiB in production) in memory until it is written.
	DefaultPlotWorkers = 1
	MaxPlotWorkers     = 64
	// DefaultPlotIdle frees the slot: a complete plot its validator has not
	// spot-checked for this long (the evaluator's maximum evidence age) may
	// be replaced by another validator's challenge.
	DefaultPlotIdle = 36 * time.Hour
)

// Plot states answered by Status.
const (
	PlotBuilding = "building"
	PlotComplete = "complete"
)

const (
	plotDirPrefix  = "plot-"
	plotMetaFile   = "challenge.json"
	plotCommitFile = "commitment.json"
	plotTempPrefix = "tmp-"
	treeMagic      = "mcqtree3"
)

// PlotStatus is the build state of one plot.
type PlotStatus struct {
	State      string
	ChunksDone int
	Commitment *PlotCommitment
}

// PlotRunner keeps at most MaxPlots validator-seeded plots in a private
// directory, builds them in the background, resumes them after a restart,
// and answers spot reads from disk. Every file it writes or deletes is one
// it names itself, inside its own plot directory, through directory file
// descriptors and O_NOFOLLOW; it never deletes recursively.
type PlotRunner struct {
	key     ed25519.PrivateKey
	network string
	netuid  uint16
	hotkey  string
	uid     *uint16
	workers int
	maxMiB  int
	perVal  int
	window  time.Duration
	idle    time.Duration
	rehash  bool
	now     func() time.Time
	memMiB  func() (int64, error)

	mu      sync.Mutex
	seal    *sealWork
	dirFD   int
	plot    *plotState
	retired map[string]int64
	starts  map[string][]time.Time
}

// PlotConfig configures OpenPlots. Zero values select the defaults; Now and
// MemAvailableMiB default to the host's clock and /proc/meminfo.
type PlotConfig struct {
	Dir               string
	Key               ed25519.PrivateKey
	Network           string
	NetUID            uint16
	Hotkey            string
	UID               *uint16
	Workers           int
	MaxPlotMiB        int
	PlotsPerValidator int
	PlotsWindow       time.Duration
	// IdleTimeout is DefaultPlotIdle when zero.
	IdleTimeout time.Duration
	// RehashOnResume re-hashes every stored block against its tree on
	// startup (slow: it reads the whole plot); otherwise only the trees are
	// checked.
	RehashOnResume  bool
	Now             func() time.Time
	MemAvailableMiB func() (int64, error)
}

type plotMeta struct {
	Challenge       PlotChallenge `json:"challenge"`
	StartedAtUnixMS int64         `json:"started_at_unix_ms"`
}

type plotState struct {
	meta   plotMeta
	digest string
	name   string
	dirFD  int

	mu         sync.Mutex
	lower      [][32]byte
	top        [][32]byte
	done       []bool
	lastActive time.Time
	chunksDone int
	levels     [][][32]byte
	commitment *PlotCommitment
	err        error
	cancel     context.CancelFunc
	finished   chan struct{}
}

// ChunkMiB is the size of one chunk in MiB, rounded down.
func (c PlotChallenge) ChunkMiB() int64 { return int64(c.BlocksPerChunk()) * BlockSize >> 20 }

func chunkBytes(c PlotChallenge) int64 { return int64(c.BlocksPerChunk()) * BlockSize }

func chunkName(chunk int, suffix string) string { return fmt.Sprintf("chunk-%05d.%s", chunk, suffix) }

// OpenPlots opens the private plot directory (an existing directory owned
// by this user, not a symlink, with no group or other permission) and loads
// the plot it holds, resuming its build while its window is open.
func OpenPlots(config PlotConfig) (*PlotRunner, error) {
	if !filepath.IsAbs(config.Dir) || len(config.Key) != ed25519.PrivateKeySize {
		return nil, errors.New("plot directory must be an absolute path and the service key set")
	}
	if config.Workers < 0 || config.Workers > MaxPlotWorkers || config.MaxPlotMiB < 0 || config.PlotsPerValidator < 0 {
		return nil, errors.New("plot workers, size or rate is out of range")
	}
	fd, err := unix.Open(config.Dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open plot directory: %w", err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&0o077 != 0 {
		unix.Close(fd)
		return nil, errors.New("plot directory must be owned by this user with mode 0700")
	}
	r := &PlotRunner{
		key: config.Key, network: config.Network, netuid: config.NetUID, hotkey: config.Hotkey, uid: config.UID,
		workers: orDefault(config.Workers, DefaultPlotWorkers), maxMiB: orDefault(config.MaxPlotMiB, DefaultMaxPlotMiB),
		perVal: orDefault(config.PlotsPerValidator, DefaultPlotsPerValidator), window: orDefault(config.PlotsWindow, DefaultPlotsWindow),
		idle: orDefault(config.IdleTimeout, DefaultPlotIdle), rehash: config.RehashOnResume,
		now: config.Now, memMiB: config.MemAvailableMiB, dirFD: fd,
		retired: map[string]int64{}, starts: map[string][]time.Time{},
	}
	if r.now == nil {
		r.now = time.Now
	}
	if r.memMiB == nil {
		r.memMiB = func() (int64, error) { return readMemAvailable("/proc/meminfo") }
	}
	r.load()
	return r, nil
}

// Close stops a running build and releases the directories.
func (r *PlotRunner) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p := r.plot; p != nil {
		r.stop(p)
		r.cancelSeal()
		unix.Close(p.dirFD)
		r.plot = nil
	}
	unix.Close(r.dirFD)
	r.dirFD = -1
}

// load adopts the first well-formed plot directory for this miner. A plot
// it cannot read is left in place and not served.
func (r *PlotRunner) load() {
	dup, err := unix.Dup(r.dirFD)
	if err != nil {
		return
	}
	dir := os.NewFile(uintptr(dup), "plots")
	entries, err := dir.ReadDir(-1)
	dir.Close()
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, plotDirPrefix) || !hex64.MatchString(strings.TrimPrefix(name, plotDirPrefix)) {
			continue
		}
		if p := r.loadPlot(name); p != nil {
			r.plot = p
			if p.commitment == nil && p.err == nil {
				r.build(p)
			}
			return
		}
	}
}

func (r *PlotRunner) loadPlot(name string) *plotState {
	fd, err := unix.Openat(r.dirFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil
	}
	raw, err := readFileAt(fd, plotMetaFile, 64<<10)
	var meta plotMeta
	if err != nil || strictDecode(raw, &meta) != nil || meta.Challenge.Validate() != nil || !r.mine(meta.Challenge) ||
		plotDirPrefix+meta.Challenge.PlotID != name {
		unix.Close(fd)
		return nil
	}
	p := newPlotState(meta, name, fd)
	for chunk := range meta.Challenge.Chunks {
		if lower, top, ok := loadChunk(fd, meta.Challenge, chunk, r.rehash); ok {
			p.lower[chunk], p.top[chunk], p.done[chunk] = lower, top, true
			p.chunksDone++
		}
	}
	if raw, err := readFileAt(fd, plotCommitFile, 64<<10); err == nil {
		commitment, err := DecodePlotCommitment(raw)
		if err == nil && p.chunksDone == meta.Challenge.Chunks &&
			VerifyPlotCommitment(commitment, meta.Challenge, signerKey(r.key)) == nil {
			p.levels = PlotLevels(p.leaves())
			if hexString(p.levels[len(p.levels)-1][0]) == commitment.Root {
				p.commitment, p.lastActive = &commitment, r.now()
				return p
			}
		}
	}
	if !r.now().Before(time.Unix(meta.Challenge.BuildExpiresAtUnix, 0)) {
		p.err = ErrPlotDeadline
	}
	return p
}

func newPlotState(meta plotMeta, name string, fd int) *plotState {
	digest, _ := PlotChallengeSHA256(meta.Challenge)
	return &plotState{
		meta: meta, digest: digest, name: name, dirFD: fd,
		lower: make([][32]byte, meta.Challenge.Chunks), top: make([][32]byte, meta.Challenge.Chunks),
		done: make([]bool, meta.Challenge.Chunks),
	}
}

// leaves are the plot-tree leaves. Caller holds p.mu or owns p.
func (p *plotState) leaves() [][32]byte {
	out := make([][32]byte, len(p.lower))
	for i := range out {
		out[i] = ChunkLeaf(p.lower[i], p.top[i])
	}
	return out
}

// replaceable reports whether another validator may take p's slot: p
// failed, or p is complete and its validator has not spot-checked it for
// the idle timeout.
func (r *PlotRunner) replaceable(p *plotState, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err != nil || (p.commitment != nil && now.Sub(p.lastActive) > r.idle)
}

// mine reports whether c names this miner.
func (r *PlotRunner) mine(c PlotChallenge) bool {
	return r.uid != nil && c.MinerHotkey == r.hotkey && c.MinerUID == *r.uid && c.Network == r.network && c.NetUID == r.netuid
}

func (p *plotState) status() (PlotStatus, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return PlotStatus{}, p.err
	}
	if p.commitment != nil {
		commitment := *p.commitment
		return PlotStatus{State: PlotComplete, ChunksDone: p.chunksDone, Commitment: &commitment}, nil
	}
	return PlotStatus{State: PlotBuilding, ChunksDone: p.chunksDone}, nil
}

// Start starts or resumes the build of c for callerHotkey (the btauth-
// verified validator). The same validator's new plot replaces its old one;
// another validator's plot is replaced only when it failed or sat idle.
func (r *PlotRunner) Start(c PlotChallenge, callerHotkey string) (PlotStatus, error) {
	if err := c.Validate(); err != nil {
		return PlotStatus{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if c.ValidatorHotkey != callerHotkey || !r.mine(c) {
		return PlotStatus{}, ErrIdentity
	}
	now := r.now()
	if now.Before(time.Unix(c.IssuedAtUnix, 0).Add(-issueSkew)) || !now.Before(time.Unix(c.BuildExpiresAtUnix, 0)) {
		return PlotStatus{}, ErrExpired
	}
	digest, err := PlotChallengeSHA256(c)
	if err != nil {
		return PlotStatus{}, err
	}
	if p := r.plot; p != nil && p.meta.Challenge.PlotID == c.PlotID {
		if p.digest != digest {
			return PlotStatus{}, ErrReplayed
		}
		p.mu.Lock()
		restart := p.commitment == nil && (p.err != nil || p.cancel == nil)
		if restart {
			p.err = nil
		}
		p.mu.Unlock()
		if restart {
			r.build(p)
		}
		return p.status()
	}
	if p := r.plot; p != nil && p.meta.Challenge.ValidatorHotkey != c.ValidatorHotkey && !r.replaceable(p, now) {
		return PlotStatus{}, ErrPlotSlotsFull
	}
	for id, expires := range r.retired {
		if expires < now.Unix() {
			delete(r.retired, id)
		}
	}
	if _, replayed := r.retired[c.PlotID]; replayed {
		return PlotStatus{}, ErrReplayed
	}
	if int64(c.Chunks)*c.ChunkMiB() > int64(r.maxMiB) {
		return PlotStatus{}, ErrPolicy
	}
	if available, err := r.memMiB(); err != nil || 2*c.ChunkMiB()+fillOverheadMiB > available {
		return PlotStatus{}, ErrMemory
	}
	if r.rateLimited(c.ValidatorHotkey, now) {
		return PlotStatus{}, ErrRateLimited
	}
	if old := r.plot; old != nil {
		r.stop(old)
		r.cancelSeal()
		r.retired[old.meta.Challenge.PlotID] = old.meta.Challenge.BuildExpiresAtUnix
		r.remove(old)
		r.plot = nil
	}
	p, err := r.create(plotMeta{Challenge: c, StartedAtUnixMS: now.UnixMilli()})
	if err != nil {
		return PlotStatus{}, err
	}
	r.retired[c.PlotID] = c.BuildExpiresAtUnix
	r.plot = p
	r.build(p)
	return p.status()
}

func (r *PlotRunner) rateLimited(validator string, now time.Time) bool {
	recent := r.starts[validator][:0]
	for _, at := range r.starts[validator] {
		if now.Sub(at) < r.window {
			recent = append(recent, at)
		}
	}
	if len(recent) >= r.perVal {
		r.starts[validator] = recent
		return true
	}
	r.starts[validator] = append(recent, now)
	return false
}

func (r *PlotRunner) create(meta plotMeta) (*plotState, error) {
	name := plotDirPrefix + meta.Challenge.PlotID
	if err := unix.Mkdirat(r.dirFD, name, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, ErrPlotWriteFailed
	}
	fd, err := unix.Openat(r.dirFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrPlotWriteFailed
	}
	raw, err := organic.Canonical(meta)
	if err != nil || writeFileAt(fd, plotMetaFile, raw) != nil {
		unix.Close(fd)
		return nil, ErrPlotWriteFailed
	}
	return newPlotState(meta, name, fd), nil
}

// remove deletes the files this runner names in p's directory, then the
// directory if it is empty. unlinkat never follows a symlink and refuses a
// directory, so nothing outside p's directory is touched.
func (r *PlotRunner) remove(p *plotState) {
	names := []string{plotMetaFile, plotCommitFile}
	for chunk := range p.meta.Challenge.Chunks {
		names = append(names, chunkName(chunk, "bin"), chunkName(chunk, "tree"), chunkName(chunk, "sealreq"), chunkName(chunk, "seal"))
	}
	for _, name := range names {
		_ = unix.Unlinkat(p.dirFD, name, 0)
		_ = unix.Unlinkat(p.dirFD, plotTempPrefix+name, 0)
	}
	unix.Close(p.dirFD)
	_ = unix.Unlinkat(r.dirFD, p.name, unix.AT_REMOVEDIR)
}

// stop cancels p's build and waits for it. Caller holds r.mu.
func (r *PlotRunner) stop(p *plotState) {
	p.mu.Lock()
	cancel, finished := p.cancel, p.finished
	p.mu.Unlock()
	if cancel != nil {
		cancel()
		<-finished
	}
}

// build runs p's missing chunks in the background. Caller holds r.mu.
func (r *PlotRunner) build(p *plotState) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Unix(p.meta.Challenge.BuildExpiresAtUnix, 0))
	finished := make(chan struct{})
	p.mu.Lock()
	p.cancel, p.finished = cancel, finished
	p.mu.Unlock()
	workers := r.workers
	if available, err := r.memMiB(); err == nil {
		workers = int(min(int64(workers), max((available-fillOverheadMiB)/max(2*p.meta.Challenge.ChunkMiB(), 1), 1)))
	}
	go func() {
		defer close(finished)
		defer cancel()
		err := r.runBuild(ctx, p, workers)
		p.mu.Lock()
		defer p.mu.Unlock()
		p.cancel = nil
		if err != nil && !errors.Is(err, context.Canceled) {
			p.err = err
		}
	}()
}

func (r *PlotRunner) runBuild(ctx context.Context, p *plotState, workers int) error {
	c := p.meta.Challenge
	seed, _ := hex.DecodeString(c.Seed)
	next := make(chan int)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for chunk := range next {
				lower, top, err := buildChunk(ctx, p.dirFD, c, seed, chunk)
				if err != nil {
					errs <- err
					return
				}
				p.mu.Lock()
				p.lower[chunk], p.top[chunk], p.done[chunk] = lower, top, true
				p.chunksDone++
				p.mu.Unlock()
			}
		}()
	}
	var failed error
feed:
	for chunk := range c.Chunks {
		p.mu.Lock()
		done := p.done[chunk]
		p.mu.Unlock()
		if done {
			continue
		}
		select {
		case next <- chunk:
		case failed = <-errs:
			break feed
		case <-ctx.Done():
			break feed
		}
	}
	close(next)
	wg.Wait()
	go debug.FreeOSMemory()
	if failed == nil {
		select {
		case failed = <-errs:
		default:
		}
	}
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return ErrPlotDeadline
		}
		return err
	}
	if failed != nil {
		return failed
	}
	levels := PlotLevels(p.leaves())
	commitment := PlotCommitment{
		Schema: PlotCommitmentSchema, PlotChallengeSHA256: p.digest, PlotID: c.PlotID, Network: c.Network, NetUID: c.NetUID,
		ValidatorHotkey: c.ValidatorHotkey, MinerHotkey: c.MinerHotkey, ServicePublicKey: signerKey(r.key),
		Root: hexString(levels[len(levels)-1][0]), Chunks: c.Chunks, BlocksPerChunk: c.BlocksPerChunk(),
		BuildElapsedMS: min(max(r.now().UnixMilli()-p.meta.StartedAtUnixMS, 0), maxPlotElapsedMS),
	}
	if err := SignPlotCommitment(&commitment, r.key); err != nil {
		return err
	}
	raw, err := organic.Canonical(commitment)
	if err != nil || writeFileAt(p.dirFD, plotCommitFile, raw) != nil {
		return ErrPlotWriteFailed
	}
	p.mu.Lock()
	p.levels, p.commitment, p.lastActive = levels, &commitment, r.now()
	p.mu.Unlock()
	return nil
}

// buildChunk computes every layer of chunk, writes the stored top layer and
// then its tree sidecar (each through a temp file, fsync and rename) and
// returns the lower digest and the top root. The lower layers are
// discarded. A chunk counts as done on resume only when its sidecar is in
// place.
func buildChunk(ctx context.Context, dirFD int, c PlotChallenge, seed []byte, chunk int) ([32]byte, [32]byte, error) {
	computed, err := ComputePlotChunk(ctx, PlotChunkNonce(seed, chunk), c.ChunkBlocksPerSlice, nil)
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	if err := writeFileAt(dirFD, chunkName(chunk, "bin"), computed.top); err != nil {
		return [32]byte{}, [32]byte{}, ErrPlotWriteFailed
	}
	if err := writeFileAt(dirFD, chunkName(chunk, "tree"), encodeTree(computed.LowerDigest(), computed.topLevels)); err != nil {
		return [32]byte{}, [32]byte{}, ErrPlotWriteFailed
	}
	return computed.LowerDigest(), computed.TopRoot(), nil
}

// The tree sidecar is "mcqtree3", the lower digest, every level of the top
// layer's tree (leaves first), then the SHA-256 of everything before it,
// which guards the lower digest that resume cannot recompute.
func encodeTree(lower [32]byte, levels [][][32]byte) []byte {
	out := append([]byte(treeMagic), lower[:]...)
	for _, level := range levels {
		for _, node := range level {
			out = append(out, node[:]...)
		}
	}
	sum := sha256.Sum256(out)
	return append(out, sum[:]...)
}

const treeHeader = len(treeMagic) + 32

func levelSizes(n int) []int {
	sizes := []int{n}
	for n > 1 {
		n = (n + 1) / 2
		sizes = append(sizes, n)
	}
	return sizes
}

func treeBytes(n int) int64 {
	total := int64(treeHeader + sha256.Size)
	for _, size := range levelSizes(n) {
		total += 32 * int64(size)
	}
	return total
}

// loadChunk accepts a written chunk on resume by verifying its sidecar: the
// block file has exactly the chunk's size, and every node of the stored
// top-layer tree is recomputed from the stored leaves. With rehash it also
// re-hashes every stored block against its leaf. Without it a damaged block
// only fails the spot checks that read it.
func loadChunk(dirFD int, c PlotChallenge, chunk int, rehash bool) ([32]byte, [32]byte, bool) {
	var none [32]byte
	n := c.BlocksPerChunk()
	fd, err := unix.Openat(dirFD, chunkName(chunk, "bin"), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return none, none, false
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size != chunkBytes(c) {
		return none, none, false
	}
	raw, err := readFileAt(dirFD, chunkName(chunk, "tree"), treeBytes(n))
	if err != nil || int64(len(raw)) != treeBytes(n) || string(raw[:len(treeMagic)]) != treeMagic {
		return none, none, false
	}
	lower := [32]byte(raw[len(treeMagic):treeHeader])
	leaves := make([][32]byte, n)
	for i := range leaves {
		copy(leaves[i][:], raw[treeHeader+32*i:])
	}
	levels := MerkleLevels(leaves)
	if !bytes.Equal(encodeTree(lower, levels), raw) {
		return none, none, false
	}
	if rehash {
		block := make([]byte, BlockSize)
		for i, leaf := range leaves {
			if read, err := unix.Pread(fd, block, int64(i)*BlockSize); err != nil || read != BlockSize || LeafHash(block) != leaf {
				return none, none, false
			}
		}
	}
	return lower, levels[len(levels)-1][0], true
}

// Status answers the build state of c for its validator.
func (r *PlotRunner) Status(c PlotChallenge, callerHotkey string) (PlotStatus, error) {
	if err := c.Validate(); err != nil {
		return PlotStatus{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if c.ValidatorHotkey != callerHotkey || !r.mine(c) {
		return PlotStatus{}, ErrIdentity
	}
	p := r.plot
	digest, err := PlotChallengeSHA256(c)
	if err != nil {
		return PlotStatus{}, err
	}
	if p == nil || p.digest != digest {
		return PlotStatus{}, ErrPlotAbsent
	}
	return p.status()
}

// Spot answers one spot read of the complete plot from disk: each picked
// block and its path by pread, the chunk paths from memory. A spot by the
// plot's validator keeps the slot from going idle.
func (r *PlotRunner) Spot(request PlotSpotRequest, callerHotkey string) (PlotSpot, error) {
	if err := request.Validate(); err != nil {
		return PlotSpot{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	p, commitment, err := r.complete(request.PlotID, request.PlotChallengeSHA256, request.Root, callerHotkey)
	if err != nil {
		return PlotSpot{}, err
	}
	c := p.meta.Challenge
	for _, pick := range request.Picks {
		if pick.Chunk >= c.Chunks || pick.Index >= c.BlocksPerChunk() {
			return PlotSpot{}, ErrPlotRequestMismatch
		}
	}
	spot := PlotSpot{Schema: PlotSpotSchema, PlotID: c.PlotID, ServicePublicKey: signerKey(r.key), Root: commitment.Root}
	p.mu.Lock()
	lower, top, levels := p.lower, p.top, p.levels
	p.mu.Unlock()
	for _, pick := range request.Picks {
		block, path, err := readStored(p.dirFD, c, pick.Chunk, pick.Index)
		if err != nil {
			return PlotSpot{}, ErrPlotReadFailed
		}
		spot.Items = append(spot.Items, PlotSpotItem{
			Chunk: pick.Chunk, LowerDigest: hexString(lower[pick.Chunk]), TopRoot: hexString(top[pick.Chunk]),
			ChunkPath: MerklePath(levels, pick.Chunk), Index: pick.Index, Block: encodeBlock(block), Path: path,
		})
	}
	if spot.RequestSHA256, err = PlotRequestSHA256(request); err != nil {
		return PlotSpot{}, err
	}
	if err := SignPlotSpot(&spot, r.key); err != nil {
		return PlotSpot{}, err
	}
	p.mu.Lock()
	p.lastActive = r.now()
	p.mu.Unlock()
	return spot, nil
}

// complete returns the complete plot a seal or spot request names, for its
// validator only. Caller holds r.mu.
func (r *PlotRunner) complete(plotID, digest, root, caller string) (*plotState, PlotCommitment, error) {
	p := r.plot
	if p == nil || p.meta.Challenge.PlotID != plotID {
		return nil, PlotCommitment{}, ErrPlotAbsent
	}
	if p.meta.Challenge.ValidatorHotkey != caller {
		return nil, PlotCommitment{}, ErrIdentity
	}
	p.mu.Lock()
	commitment, err := p.commitment, p.err
	p.mu.Unlock()
	if err != nil {
		return nil, PlotCommitment{}, err
	}
	if commitment == nil {
		return nil, PlotCommitment{}, ErrPlotBuilding
	}
	if digest != p.digest || root != commitment.Root {
		return nil, PlotCommitment{}, ErrPlotRequestMismatch
	}
	return p, *commitment, nil
}

// readStored reads stored block index of chunk and its top-layer path.
func readStored(dirFD int, c PlotChallenge, chunk, index int) ([]byte, []string, error) {
	data, err := unix.Openat(dirFD, chunkName(chunk, "bin"), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	defer unix.Close(data)
	tree, err := unix.Openat(dirFD, chunkName(chunk, "tree"), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	defer unix.Close(tree)
	block := make([]byte, BlockSize)
	if n, err := unix.Pread(data, block, int64(index)*BlockSize); err != nil || n != BlockSize {
		return nil, nil, errors.New("short block read")
	}
	path := []string{}
	offset := int64(treeHeader)
	sizes := levelSizes(c.BlocksPerChunk())
	for _, size := range sizes[:len(sizes)-1] {
		if sibling := index ^ 1; sibling < size {
			var node [32]byte
			if n, err := unix.Pread(tree, node[:], offset+32*int64(sibling)); err != nil || n != 32 {
				return nil, nil, errors.New("short tree read")
			}
			path = append(path, hexString(node))
		}
		offset += 32 * int64(size)
		index /= 2
	}
	return block, path, nil
}

// sealWork is the one chunk recomputed for a seal answer.
type sealWork struct {
	plotID string
	chunk  int
	digest string
	cancel context.CancelFunc
	done   chan struct{}
	result *PlotChunk
	err    error
}

// Seal answers one seal request. The lower layers are not stored, so the
// first request for a chunk records its digest (chunk-NNNNN.sealreq), then
// recomputes the chunk in the background and answers ErrPlotSealPending;
// the same request sent again once that finished is answered after the
// recomputed top root and lower digest matched the stored ones, and the
// signed answer is kept (chunk-NNNNN.seal) and served again for the same
// request. A different request for a chunk that already has a recorded
// request is refused with ErrPlotChunkSealed, so one plot costs at most
// one recomputation per chunk. One chunk is recomputed at a time.
func (r *PlotRunner) Seal(request PlotSealRequest, callerHotkey string) (PlotSeal, error) {
	if err := request.Validate(); err != nil {
		return PlotSeal{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	p, commitment, err := r.complete(request.PlotID, request.PlotChallengeSHA256, request.Root, callerHotkey)
	if err != nil {
		return PlotSeal{}, err
	}
	c := p.meta.Challenge
	n := c.BlocksPerChunk()
	if request.Chunk >= c.Chunks {
		return PlotSeal{}, ErrPlotRequestMismatch
	}
	for _, point := range request.Openings {
		if point.Index >= n {
			return PlotSeal{}, ErrPlotRequestMismatch
		}
	}
	digest, err := PlotRequestSHA256(request)
	if err != nil {
		return PlotSeal{}, err
	}
	work := r.seal
	if work == nil || work.plotID != c.PlotID || work.chunk != request.Chunk {
		recorded, err := readFileAt(p.dirFD, chunkName(request.Chunk, "sealreq"), 64)
		switch {
		case err == nil && string(recorded) != digest:
			return PlotSeal{}, ErrPlotChunkSealed
		case err == nil:
			return cachedSeal(p.dirFD, request.Chunk, digest)
		case !errors.Is(err, unix.ENOENT):
			return PlotSeal{}, ErrPlotReadFailed
		}
		select {
		case <-r.sealDone():
		default:
			return PlotSeal{}, ErrBusy
		}
		if available, err := r.memMiB(); err != nil || 2*c.ChunkMiB()+fillOverheadMiB > available {
			return PlotSeal{}, ErrMemory
		}
		if err := writeFileAt(p.dirFD, chunkName(request.Chunk, "sealreq"), []byte(digest)); err != nil {
			return PlotSeal{}, ErrPlotWriteFailed
		}
		ctx, cancel := context.WithCancel(context.Background())
		work = &sealWork{plotID: c.PlotID, chunk: request.Chunk, digest: digest, cancel: cancel, done: make(chan struct{})}
		r.seal = work
		seed, _ := hex.DecodeString(c.Seed)
		points := append([]PlotSealPoint(nil), request.Openings...)
		go func() {
			defer close(work.done)
			defer cancel()
			work.result, work.err = ComputePlotChunk(ctx, PlotChunkNonce(seed, request.Chunk), c.ChunkBlocksPerSlice, points)
		}()
	}
	if work.digest != digest {
		return PlotSeal{}, ErrPlotChunkSealed
	}
	select {
	case <-work.done:
	default:
		return PlotSeal{}, ErrPlotSealPending
	}
	// Answered or failed, the recomputed chunk (2 GiB in production) is freed.
	r.seal = nil
	go debug.FreeOSMemory()
	p.mu.Lock()
	lower, top, levels := p.lower[request.Chunk], p.top[request.Chunk], p.levels
	p.mu.Unlock()
	if work.err != nil || work.result.LowerDigest() != lower || work.result.TopRoot() != top {
		return PlotSeal{}, ErrPlotReadFailed
	}
	seal := PlotSeal{
		Schema: PlotSealSchema, RequestSHA256: digest, PlotID: c.PlotID, ServicePublicKey: signerKey(r.key), Root: commitment.Root,
		Chunk: request.Chunk, ChunkPath: MerklePath(levels, request.Chunk), Openings: work.result.Openings(),
	}
	for _, root := range work.result.Roots() {
		seal.LayerRoots = append(seal.LayerRoots, hexString(root))
	}
	if err := SignPlotSeal(&seal, r.key); err != nil {
		return PlotSeal{}, err
	}
	raw, err := organic.Canonical(seal)
	if err != nil || writeFileAt(p.dirFD, chunkName(request.Chunk, "seal"), raw) != nil {
		return PlotSeal{}, ErrPlotWriteFailed
	}
	return seal, nil
}

// cachedSeal answers a repeated seal request from its kept answer. A
// recorded request without a kept answer (its recomputation failed or was
// interrupted) is not recomputed again.
func cachedSeal(dirFD, chunk int, digest string) (PlotSeal, error) {
	raw, err := readFileAt(dirFD, chunkName(chunk, "seal"), MaxPlotSealBytes)
	if err != nil {
		return PlotSeal{}, ErrPlotChunkSealed
	}
	seal, err := DecodePlotSeal(raw)
	if err != nil || seal.RequestSHA256 != digest {
		return PlotSeal{}, ErrPlotReadFailed
	}
	return seal, nil
}

// cancelSeal stops a running seal recomputation. Caller holds r.mu.
func (r *PlotRunner) cancelSeal() {
	if r.seal != nil {
		r.seal.cancel()
		r.seal = nil
	}
}

// sealDone is closed when no seal recomputation is running. Caller holds r.mu.
func (r *PlotRunner) sealDone() <-chan struct{} {
	if r.seal == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return r.seal.done
}

// writeFileAt writes name in dirFD through a temp file it names itself:
// exclusive create without following links, write, fsync, rename, then
// fsync of the directory.
func writeFileAt(dirFD int, name string, data []byte) error {
	temp := plotTempPrefix + name
	_ = unix.Unlinkat(dirFD, temp, 0)
	fd, err := unix.Openat(dirFD, temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	for written := 0; written < len(data); {
		n, err := unix.Write(fd, data[written:])
		if err != nil {
			unix.Close(fd)
			_ = unix.Unlinkat(dirFD, temp, 0)
			return err
		}
		written += n
	}
	if err := unix.Fsync(fd); err != nil {
		unix.Close(fd)
		_ = unix.Unlinkat(dirFD, temp, 0)
		return err
	}
	if err := unix.Close(fd); err != nil {
		return err
	}
	if err := unix.Renameat(dirFD, temp, dirFD, name); err != nil {
		_ = unix.Unlinkat(dirFD, temp, 0)
		return err
	}
	return unix.Fsync(dirFD)
}

// readFileAt reads a regular file of at most limit bytes without following
// links and without blocking on a FIFO.
func readFileAt(dirFD int, name string, limit int64) ([]byte, error) {
	fd, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size > limit {
		return nil, errors.New("not a bounded regular file")
	}
	out := make([]byte, st.Size)
	for read := 0; read < len(out); {
		n, err := unix.Pread(fd, out[read:], int64(read))
		if err != nil || n == 0 {
			return nil, errors.New("short read")
		}
		read += n
	}
	return out, nil
}
