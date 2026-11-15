// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package qualification

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Runner refusals. Each is one stable bridge code.
var (
	ErrBusy              = errors.New("qualification_busy")
	ErrIdentity          = errors.New("qualification_identity_mismatch")
	ErrExpired           = errors.New("qualification_challenge_expired")
	ErrReplayed          = errors.New("qualification_challenge_replayed")
	ErrDeadline          = errors.New("qualification_deadline_exceeded")
	ErrMemory            = errors.New("qualification_memory_unavailable")
	ErrFillAbsent        = errors.New("qualification_fill_absent")
	ErrRequestMismatch   = errors.New("qualification_openings_request_mismatch")
	ErrOpeningsExhausted = errors.New("qualification_openings_exhausted")
	ErrOpeningsServed    = errors.New("qualification_openings_served_exhausted")
	ErrPolicy            = errors.New("qualification_policy_refused")
	ErrRateLimited       = errors.New("qualification_rate_limited")
)

// issueSkew is how far in the future a challenge's issued_at may be.
const issueSkew = 30 * time.Second

// DefaultMaxDuration keeps the fill inside the agent's bridge write timeout.
const DefaultMaxDuration = 100 * time.Second

// openingsServedSlack is how many openings beyond the challenge's budget a
// fill serves in total, re-requests included, for retries: one full request.
const openingsServedSlack = MaxOpeningsPerRequest

// MaxOpeningsServed bounds the openings, repeats included, that one fill
// answers, so re-requesting served indices cannot loop. Validators may open
// one index per call; the bound counts openings, not calls.
func MaxOpeningsServed(openings int) int { return openings + openingsServedSlack }

// Server-side policy defaults (PROVISIONAL). An operator may lower them.
const (
	// DefaultMaxFillBlocks is 16 GiB of 16 KiB blocks.
	DefaultMaxFillBlocks = 1 << 20
	// DefaultMaxWindow is the longest challenge window accepted.
	DefaultMaxWindow = MaxWindowSeconds * time.Second
	// DefaultJobsPerValidator jobs per DefaultJobsWindow, per validator.
	DefaultJobsPerValidator = 4
	DefaultJobsWindow       = time.Hour
	// DefaultFirstOpenTimeout frees a committed fill whose validator sends
	// no round-two call in time, so one validator cannot hold the single
	// fill slot for the whole window.
	DefaultFirstOpenTimeout = 30 * time.Second
)

// fillOverheadMiB is reserved beyond the blocks for the tree and the
// process itself when comparing against MemAvailable.
const fillOverheadMiB = 256

// Runner computes one fill at a time, holds it until its challenge expires
// or every opening it allows was served, and signs both rounds.
type Runner struct {
	Key     ed25519.PrivateKey
	Network string
	NetUID  uint16
	Hotkey  string
	// UID is the miner's configured UID; nil refuses every challenge.
	UID *uint16
	// MaxDuration caps the fill below the challenge expiry; zero means
	// DefaultMaxDuration.
	MaxDuration time.Duration
	// Now and MemAvailableMiB are the clock and /proc/meminfo
	// MemAvailable; nil uses the host's.
	Now             func() time.Time
	MemAvailableMiB func() (int64, error)
	// MaxFillBlocks, MaxWindow and JobsPerValidator (per JobsWindow) are
	// the operator's policy; zero means the PROVISIONAL default.
	MaxFillBlocks    int
	MaxWindow        time.Duration
	JobsPerValidator int
	JobsWindow       time.Duration
	// FirstOpenTimeout is how long a committed fill waits for its first
	// round-two call; zero means DefaultFirstOpenTimeout.
	FirstOpenTimeout time.Duration

	mu   sync.Mutex
	busy bool
	held *heldFill
	seen map[string]int64
	jobs map[string][]time.Time
}

func orDefault[T int | time.Duration](value, fallback T) T {
	if value <= 0 {
		return fallback
	}
	return value
}

// rateLimited records one job of validator at now and reports whether it
// exceeds JobsPerValidator in the trailing JobsWindow. Caller holds mu.
func (r *Runner) rateLimited(validator string, now time.Time) bool {
	if r.jobs == nil {
		r.jobs = map[string][]time.Time{}
	}
	window := orDefault(r.JobsWindow, DefaultJobsWindow)
	recent := r.jobs[validator][:0]
	for _, at := range r.jobs[validator] {
		if now.Sub(at) < window {
			recent = append(recent, at)
		}
	}
	if len(recent) >= orDefault(r.JobsPerValidator, DefaultJobsPerValidator) {
		r.jobs[validator] = recent
		return true
	}
	r.jobs[validator] = append(recent, now)
	return false
}

type heldFill struct {
	challenge Challenge
	digest    string
	root      string
	filled    *Filled
	served    map[int]bool
	opened    int
	calls     int
	timer     *time.Timer
	idle      *time.Timer
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Runner) memAvailable() (int64, error) {
	if r.MemAvailableMiB != nil {
		return r.MemAvailableMiB()
	}
	return readMemAvailable("/proc/meminfo")
}

// Commit runs round one for callerHotkey (the btauth-verified validator):
// it fills, commits and holds the fill. While a fill runs or is held, every
// other challenge is refused with ErrBusy, never queued.
func (r *Runner) Commit(ctx context.Context, c Challenge, callerHotkey string) (Commitment, error) {
	started, err := r.admit(c, callerHotkey)
	if err != nil {
		return Commitment{}, err
	}
	defer func() {
		r.mu.Lock()
		r.busy = false
		r.mu.Unlock()
	}()
	digest, err := ChallengeSHA256(c)
	if err != nil {
		return Commitment{}, err
	}
	nonce, _ := hex.DecodeString(c.Nonce)
	limit := r.MaxDuration
	if limit <= 0 {
		limit = DefaultMaxDuration
	}
	deadline := time.Unix(c.ExpiresAtUnix, 0)
	if capped := started.Add(limit); capped.Before(deadline) {
		deadline = capped
	}
	fillCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	filled, err := ComputeFill(fillCtx, nonce, c.Fill)
	if err != nil {
		// Return the abandoned buffers now, or the next admission could see
		// a low MemAvailable and refuse.
		go debug.FreeOSMemory()
		return Commitment{}, ErrDeadline
	}
	root := filled.Root()
	commitment := Commitment{
		Schema: CommitmentSchema, ChallengeSHA256: digest, ChallengeID: c.ChallengeID, Network: c.Network, NetUID: c.NetUID,
		ValidatorHotkey: c.ValidatorHotkey, MinerHotkey: c.MinerHotkey, ServicePublicKey: signerKey(r.Key),
		Root: hexString(root), Blocks: c.Fill.Blocks(),
		FillElapsedMS: min(max(r.now().Sub(started).Milliseconds(), 0), maxElapsedMS),
	}
	if err := SignCommitment(&commitment, r.Key); err != nil {
		return Commitment{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	held := &heldFill{challenge: c, digest: digest, root: commitment.Root, filled: filled, served: map[int]bool{}}
	held.timer = time.AfterFunc(time.Until(time.Unix(c.ExpiresAtUnix, 0)), func() { r.release(held) })
	held.idle = time.AfterFunc(orDefault(r.FirstOpenTimeout, DefaultFirstOpenTimeout), func() { r.releaseUnopened(held) })
	r.held = held
	return commitment, nil
}

// admit takes the single fill slot after every refusal that needs no work.
func (r *Runner) admit(c Challenge, callerHotkey string) (time.Time, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.busy || r.held != nil {
		return time.Time{}, ErrBusy
	}
	if err := c.Validate(); err != nil {
		return time.Time{}, err
	}
	if r.UID == nil || c.ValidatorHotkey != callerHotkey || c.MinerHotkey != r.Hotkey || c.MinerUID != *r.UID ||
		c.Network != r.Network || c.NetUID != r.NetUID {
		return time.Time{}, ErrIdentity
	}
	started := r.now()
	if started.Before(time.Unix(c.IssuedAtUnix, 0).Add(-issueSkew)) || !started.Before(time.Unix(c.ExpiresAtUnix, 0)) {
		return time.Time{}, ErrExpired
	}
	if r.seen == nil {
		r.seen = map[string]int64{}
	}
	for id, expires := range r.seen {
		if expires < started.Unix() {
			delete(r.seen, id)
		}
	}
	if _, replayed := r.seen[c.ChallengeID]; replayed {
		return time.Time{}, ErrReplayed
	}
	if c.Fill.Blocks() > orDefault(r.MaxFillBlocks, DefaultMaxFillBlocks) ||
		time.Duration(c.ExpiresAtUnix-c.IssuedAtUnix)*time.Second > orDefault(r.MaxWindow, DefaultMaxWindow) {
		return time.Time{}, ErrPolicy
	}
	needMiB := (int64(c.Fill.Blocks())*BlockSize+(1<<20)-1)>>20 + fillOverheadMiB
	if available, err := r.memAvailable(); err != nil || needMiB > available {
		return time.Time{}, ErrMemory
	}
	if r.rateLimited(c.ValidatorHotkey, started) {
		return time.Time{}, ErrRateLimited
	}
	r.seen[c.ChallengeID] = c.ExpiresAtUnix
	r.busy = true
	return started, nil
}

// release frees held if it is still the held fill.
func (r *Runner) release(held *heldFill) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.releaseLocked(held)
}

// releaseUnopened frees held if no round-two call reached it.
func (r *Runner) releaseUnopened(held *heldFill) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if held.calls == 0 {
		r.releaseLocked(held)
	}
}

func (r *Runner) releaseLocked(held *heldFill) {
	if r.held != held || held == nil {
		return
	}
	held.timer.Stop()
	held.idle.Stop()
	held.filled = nil
	r.held = nil
	go debug.FreeOSMemory()
}

// Held reports whether a fill is held for challengeID.
func (r *Runner) Held(challengeID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.held != nil && r.held.challenge.ChallengeID == challengeID
}

// Open runs round two: the openings of the requested indices of the held
// fill, for its validator only, until the challenge expires. Indices count
// against the challenge's openings budget once each; the fill is freed
// when the budget is spent.
func (r *Runner) Open(request OpeningsRequest, callerHotkey string) (Openings, error) {
	if err := request.Validate(); err != nil {
		return Openings{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	held := r.held
	if held == nil || held.challenge.ChallengeID != request.ChallengeID {
		return Openings{}, ErrFillAbsent
	}
	if held.challenge.ValidatorHotkey != callerHotkey {
		return Openings{}, ErrIdentity
	}
	held.calls++
	if !r.now().Before(time.Unix(held.challenge.ExpiresAtUnix, 0)) {
		r.releaseLocked(held)
		return Openings{}, ErrFillAbsent
	}
	if held.opened+len(request.Indices) > MaxOpeningsServed(held.challenge.Openings) {
		return Openings{}, ErrOpeningsServed
	}
	held.opened += len(request.Indices)
	if request.ChallengeSHA256 != held.digest || request.Root != held.root {
		return Openings{}, ErrRequestMismatch
	}
	fresh := 0
	for _, index := range request.Indices {
		if index >= held.challenge.Fill.Blocks() {
			return Openings{}, ErrRequestMismatch
		}
		if !held.served[index] {
			fresh++
		}
	}
	if len(held.served)+fresh > held.challenge.Openings {
		return Openings{}, ErrOpeningsExhausted
	}
	requestDigest, err := RequestSHA256(request)
	if err != nil {
		return Openings{}, err
	}
	answer := Openings{
		Schema: OpeningsSchema, ChallengeSHA256: held.digest, ChallengeID: held.challenge.ChallengeID,
		ServicePublicKey: signerKey(r.Key), Root: held.root, RequestSHA256: requestDigest,
	}
	for _, index := range request.Indices {
		answer.Openings = append(answer.Openings, held.filled.Open(index))
	}
	if err := SignOpenings(&answer, r.Key); err != nil {
		return Openings{}, err
	}
	for _, index := range request.Indices {
		held.served[index] = true
	}
	if len(held.served) == held.challenge.Openings {
		r.releaseLocked(held)
	}
	return answer, nil
}

func readMemAvailable(name string) (int64, error) {
	file, err := os.Open(name)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 3 && fields[0] == "MemAvailable:" && fields[2] == "kB" {
			value, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				return 0, err
			}
			return value / 1024, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, errors.New("meminfo lacks MemAvailable")
}
