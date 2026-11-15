// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package sandboxbackend

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/misscomputer/mscomputer-miner/pkg/miner"
	"github.com/misscomputer/mscomputer-miner/pkg/sandboxops"
)

// The sandbox-ops-v1 mode of the backend: every sandbox created while it
// is enabled
// carries one read-only directory mount of the pinned helper at
// /.mscomputer, and RunHelper runs that helper with docker exec. With ops
// disabled (the default) the create body and its readback are byte-identical
// to a backend without this file. EnableOps refuses while the helper mount
// cannot carry every property the contract requires of
// it.

// OpsHelper pins the helper delivery directory: a root-owned 0555 directory
// holding exactly sandboxops.HelperName, a root-owned 0555 regular file whose
// SHA-256 is SHA256.
type OpsHelper struct {
	Dir    string
	SHA256 string
	// Keepalive runs the helper as each sandbox's PID 1 in keepalive mode,
	// with the image's own command as its child, so a sandbox whose image
	// command exits (python:3.12-slim and its python3) keeps running for
	// ops. It needs a helper built with that mode.
	Keepalive bool
}

// maxHelperStderrBytes bounds what the backend reads of the helper's stderr;
// the helper writes none, and anything a guest writes there is dropped.
const maxHelperStderrBytes = 64 << 10

// pingTimeout bounds the independent daemon health check.
const pingTimeout = 5 * time.Second

// dockerd records an attached exec's end shortly after its stream closes, so
// an inspect right after EOF can still report it running; it is re-read at
// most exitSettleTries times, exitSettlePoll apart.
const (
	exitSettleTries = 20
	exitSettlePoll  = 25 * time.Millisecond
)

var _ miner.SandboxOpsBackend = (*GVisor)(nil)

// helperMountRequired are the mount properties the contract's delivery
// requires of the helper mount inside the sandbox. helperMountProven are
// the ones this backend both
// requests of the engine and reads back (helperMount, verifyHelperMount):
// an Engine API v1.47 bind mount carries ReadOnly and BindOptions.Propagation,
// and its readback shows RW and Propagation. A readback that does not name a
// property proves nothing about it.
//
// The required set is read-only and rprivate,
// adopted conditionally: the pinned engine can neither request nor report
// nosuid or nodev on a bind, dockerd hands runsc only rbind, ro and the
// propagation, and the pinned runsc ignores nodev. A1 replaces the two flags
// with properties this backend enforces or reads back, none of which this
// file may weaken. On every create: the pinned directory holds only a
// root-owned 0555 regular helper, neither carries an extended attribute,
// both are on a read-only host mount, and every ancestor is root-owned and
// not group- or other-writable (verifyHelper, also at enable); the readback
// shows exactly this one bind, read-only and rprivate (verifyHelperMount),
// every capability dropped with none added and no-new-privileges
// (verifyEngine). When the backend is opened and when ops are enabled: the
// runtime is registered with only reviewed arguments, none of which enables
// set-ID execution, flag overrides or device or host-file passthrough
// (verifyRuntime). When ops are enabled: the runtime's cached OCI features
// are shown and list no rro mount option (verifyOpsRuntime). A guest
// observation on the pinned Docker and runsc must pass and be
// reviewed independently before this change merges, and again on every
// re-pin.
var (
	helperMountRequired = []string{"ro", "rprivate"}
	helperMountProven   = map[string]bool{"ro": true, "rprivate": true}
)

// opsInfoTimeout bounds EnableOps's read of the daemon's runtime
// registration.
const opsInfoTimeout = 10 * time.Second

// ociRuntimeFeaturesKey is the runtime status member in which dockerd
// reports the OCI features it cached for a runtime (daemon/info_unix.go of
// moby v28.0.4, read as source at the tag).
const ociRuntimeFeaturesKey = "org.opencontainers.runtime-spec.features"

// EnableOps turns on the ops mode with the pinned helper. It must run before
// any Create. It fails closed while a property the contract requires of the
// helper mount is not requested and read back, before
// it asks the daemon anything. It then checks the daemon's runtime
// registration (verifyOpsRuntime) and verifies the helper pin, which is
// verified again before every create. No flag, configuration member or lab
// profile bypasses any of these checks.
func (b *GVisor) EnableOps(helper OpsHelper) error {
	if !filepath.IsAbs(helper.Dir) || filepath.Clean(helper.Dir) != helper.Dir || helper.Dir == "/" || !sha256Pattern.MatchString(helper.SHA256) {
		return errors.New("ops helper directory must be a clean absolute path pinned by a lowercase SHA-256")
	}
	var unproven []string
	for _, property := range helperMountRequired {
		if !helperMountProven[property] {
			unproven = append(unproven, property)
		}
	}
	if len(unproven) != 0 {
		return fmt.Errorf("sandbox ops stay off: the contract requires a %s helper mount, which the engine can neither request nor read back",
			strings.Join(unproven, ", "))
	}
	if err := b.verifyOpsRuntime(); err != nil {
		return fmt.Errorf("sandbox ops stay off: %w", err)
	}
	if err := verifyHelper(helper); err != nil {
		return err
	}
	b.opsHelper = &helper
	return nil
}

// verifyOpsRuntime checks one fresh /info answer of the daemon. The runtime
// must still be registered as verifyRuntime requires, with only the
// reviewed arguments, so none that enables set-ID execution, flag
// overrides, or device or host-file passthrough. The OCI features dockerd
// cached for it must be shown, decode, and list no rro mount
// option.
//
// dockerd turns a read-only bind into rro, not ro, only when those cached
// features list rro (daemon/oci_linux.go and supportsRecursivelyReadOnly in
// daemon/daemon_linux.go of moby v28.0.4, the pinned daemon's tag; source
// at the tag, the binary is assumed to correspond, P6). The reviewed runsc
// parser applies ro and ignores options it does not know, so a runtime that
// listed rro could be handed a helper bind it does not make read-only. A
// runtime whose features dockerd does not report refuses as well: the
// options it would be handed are then not shown here. That is deliberately
// stricter than dockerd 28.0.4, which hands such a runtime ro. The features
// are what the runtime claims to parse; they are never proof of what a
// guest sees. The check holds when ops are enabled; a daemon
// reloaded with another runtime afterwards is not seen until the next
// start.
func (b *GVisor) verifyOpsRuntime() error {
	ctx, cancel := context.WithTimeout(context.Background(), opsInfoTimeout)
	defer cancel()
	var info daemonInfo
	if err := b.engine.call(ctx, http.MethodGet, "/info", nil, nil, &info); err != nil {
		return fmt.Errorf("sandbox docker daemon info: %w", err)
	}
	if err := b.verifyRuntime(info); err != nil {
		return err
	}
	raw, ok := info.Runtimes[b.config.Runtime].Status[ociRuntimeFeaturesKey]
	if !ok {
		return fmt.Errorf("the daemon reports no OCI features for runtime %q, so the helper bind's read-only option is not shown", b.config.Runtime)
	}
	var features struct {
		MountOptions []string `json:"mountOptions"`
	}
	if err := json.Unmarshal([]byte(raw), &features); err != nil {
		return fmt.Errorf("cannot decode the OCI features of runtime %q: %w", b.config.Runtime, err)
	}
	if slices.Contains(features.MountOptions, "rro") {
		return fmt.Errorf("runtime %q lists the rro mount option, which dockerd would request for the helper bind and the reviewed runsc does not apply", b.config.Runtime)
	}
	return nil
}

// verifyHelper is the host-side helper pin: the directory and every ancestor
// are root-owned and not group- or other-writable, the directory holds only
// the helper, and the helper, opened without following a symlink, is a
// root-owned regular file of mode exactly 0555 with the pinned digest.
// The directory is opened first, without following a symlink, and the
// checks of the directory, its entries and the helper are made on that
// descriptor and on the helper opened from it. Neither the opened directory
// nor the opened helper may carry an extended attribute, such as a file
// capability or an access ACL, and a descriptor whose attributes cannot be
// listed fails the pin. Both must be on a read-only host mount
// too: the helper is checked as well as the directory, since a file
// mounted over the helper can come from another mount. The pin holds at the
// moment it is checked; it does not stop a privileged host process from
// changing the files or the mounts afterwards, and it says nothing about
// what a guest observes.
func verifyHelper(helper OpsHelper) error {
	dirFD, err := unix.Open(helper.Dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("ops helper directory %s: %w", helper.Dir, err)
	}
	dir := os.NewFile(uintptr(dirFD), helper.Dir)
	defer dir.Close()
	var opened unix.Stat_t
	if err := unix.Fstat(dirFD, &opened); err != nil {
		return fmt.Errorf("ops helper directory %s: %w", helper.Dir, err)
	}
	for path := helper.Dir; ; path = filepath.Dir(path) {
		var st unix.Stat_t
		if err := unix.Lstat(path, &st); err != nil {
			return fmt.Errorf("ops helper directory %s: %w", path, err)
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0o022 != 0 {
			return fmt.Errorf("ops helper ancestor %s must be a root-owned directory that is not group- or other-writable", path)
		}
		if path == helper.Dir && (st.Dev != opened.Dev || st.Ino != opened.Ino) {
			return fmt.Errorf("ops helper directory %s changed while it was checked", path)
		}
		if path == "/" {
			break
		}
	}
	if opened.Mode&unix.S_IFMT != unix.S_IFDIR || opened.Uid != 0 || opened.Mode&0o7777 != 0o555 {
		return fmt.Errorf("ops helper directory %s must have mode 0555", helper.Dir)
	}
	if err := noExtendedAttributes(dirFD); err != nil {
		return fmt.Errorf("ops helper directory %s: %w", helper.Dir, err)
	}
	if err := readOnlyMount(dirFD); err != nil {
		return fmt.Errorf("ops helper directory %s: %w", helper.Dir, err)
	}
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return fmt.Errorf("ops helper directory: %w", err)
	}
	if len(names) != 1 || names[0] != sandboxops.HelperName {
		return fmt.Errorf("ops helper directory %s must hold only %s", helper.Dir, sandboxops.HelperName)
	}
	path := filepath.Join(helper.Dir, sandboxops.HelperName)
	fd, err := unix.Openat(dirFD, sandboxops.HelperName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open ops helper: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Mode&0o7777 != 0o555 {
		return errors.New("ops helper must be a root-owned regular file with mode exactly 0555")
	}
	if err := noExtendedAttributes(fd); err != nil {
		return fmt.Errorf("ops helper %s: %w", path, err)
	}
	if err := readOnlyMount(fd); err != nil {
		return fmt.Errorf("ops helper %s: %w", path, err)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != helper.SHA256 {
		return errors.New("ops helper does not match its pinned SHA-256")
	}
	return nil
}

// noExtendedAttributes requires the extended-attribute list of the open file
// fd to be empty: one listxattr call that answers a size of zero. Any other
// answer fails, including a filesystem that cannot list attributes, since
// then their absence is not shown. The list holds every namespace the
// caller may see (security, system and user; trusted only with
// CAP_SYS_ADMIN), so a host whose security module labels files through
// extended attributes cannot hold a pinned helper.
func noExtendedAttributes(fd int) error {
	size, err := unix.Flistxattr(fd, nil)
	if err != nil {
		return fmt.Errorf("cannot show it has no extended attributes: %w", err)
	}
	if size != 0 {
		return errors.New("has extended attributes; the pin allows none")
	}
	return nil
}

// readOnlyMount requires the open file fd to be on a read-only mount: one
// fstatfs call on the descriptor, so no path is resolved again, whose mount
// flags include ST_RDONLY. The flag is set for a read-only mount and for a
// read-only filesystem alike.
func readOnlyMount(fd int) error {
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return fmt.Errorf("cannot show it is on a read-only mount: %w", err)
	}
	if fs.Flags&unix.ST_RDONLY == 0 {
		return errors.New("is on a writable mount; the pin requires a read-only host mount (statfs ST_RDONLY)")
	}
	return nil
}

// imageCheckSuffix names the image check container after the sandbox it is
// made for, so a check whose create went unanswered can still be removed by
// name, and one left behind is found by the next check's create. The check
// carries the sandbox labels and the lease label. The lane's orphan sweep
// recognises it by that name and label, and destroys it only while no Create
// of its lease holds the lease lock (miner.SandboxImageCheckSuffix).
const imageCheckSuffix = miner.SandboxImageCheckSuffix

// imageConflict is the ops-mode check, before the sandbox is created, that
// the verified image holds nothing at the helper's mount
// target. The engine follows a symlink there when it
// mounts the helper, and an image entry can be re-pointed by the guest once
// it is not a mount point, so the mount is made only over a path the image
// does not hold. It creates, and never starts, a container of imageID from
// the create body of s without the helper mount, and asks the engine's
// archive stat for sandboxops.MountTarget. The archive stat does not follow
// a final symlink, and with no mount in the check it sees the image's own
// layers. The check is then removed with its anonymous volumes, under
// removalTimeout even if ctx was cancelled.
//
// It returns nil only when the stat answered 404 and a fresh inspection
// shows the same check still exists and never started: a 404 also answers a
// container that is gone. Any entry, whatever its type, is a
// *miner.SandboxRefusal image_unavailable: the customer chose the image,
// and it is refused on every honest miner alike. So is a stat the engine
// answered with another error, once the check is shown never started; the
// engine may fail to stat an image whose layers it cannot mount, which
// would also have failed the start. Everything else is
// returned as the miner's fault, as the sandbox create's own failures are:
// a call the engine did not answer, a check that vanished or started, a
// check create the engine refused, and any check that could not be
// removed, even after a conflict was found. missing reports that the engine
// no longer has imageID; the caller pulls it again.
func (b *GVisor) imageConflict(ctx context.Context, instanceID, imageID string, s spec) (missing bool, err error) {
	s.helper = nil
	name := instanceID + imageCheckSuffix
	create := func() (string, error) {
		var created struct {
			ID string `json:"Id"`
		}
		err := b.engine.call(ctx, http.MethodPost, "/containers/create", url.Values{"name": {name}, "platform": {"linux/amd64"}}, b.createBody(s, imageID), &created)
		return created.ID, err
	}
	id, err := create()
	if engineStatus(err) == http.StatusConflict {
		// An earlier check of this sandbox was left behind.
		if err := b.removeImageCheck(ctx, name); err != nil {
			return false, fmt.Errorf("sandbox %s image check %s left behind: %w", instanceID, name, err)
		}
		id, err = create()
	}
	switch {
	case engineStatus(err) == http.StatusNotFound:
		return true, nil
	case err != nil:
		return false, errors.Join(fmt.Errorf("sandbox %s image check: %w", instanceID, err), b.removeImageCheck(ctx, name))
	case id == "":
		return false, errors.Join(fmt.Errorf("sandbox %s image check was created without an ID", instanceID), b.removeImageCheck(ctx, name))
	}
	verdict := b.imageCheckVerdict(ctx, id)
	if err := b.removeImageCheck(ctx, id); err != nil {
		return false, fmt.Errorf("sandbox %s image check %s (%s) not removed after %v: %w", instanceID, name, id, verdictText(verdict), err)
	}
	slog.Info("sandbox image check", "sandbox", instanceID, "check_id", id, "target", sandboxops.MountTarget, "decision", verdictText(verdict))
	return false, verdict
}

// imageCheckVerdict asks the engine's archive stat for the helper target in the
// check container id and decides as imageConflict describes, before the
// check is removed.
func (b *GVisor) imageCheckVerdict(ctx context.Context, id string) error {
	statErr := b.engine.call(ctx, http.MethodHead, "/containers/"+url.PathEscape(id)+"/archive", url.Values{"path": {sandboxops.MountTarget}}, nil, nil)
	status := engineStatus(statErr)
	switch {
	case statErr == nil:
		return &miner.SandboxRefusal{Code: "image_unavailable"}
	case status == 0:
		return fmt.Errorf("image check %s archive stat: %w", id, statErr)
	}
	again, found, err := b.inspect(ctx, id)
	switch {
	case err != nil:
		return fmt.Errorf("image check %s after its archive stat: %w", id, err)
	case !found || again.ID != id:
		return fmt.Errorf("image check %s vanished during its archive stat", id)
	case !neverStarted(again):
		return fmt.Errorf("image check %s was started", id)
	case status == http.StatusNotFound:
		return nil
	}
	return &miner.SandboxRefusal{Code: "image_unavailable"}
}

// verdictText is how a check verdict is logged.
func verdictText(verdict error) string {
	var refusal *miner.SandboxRefusal
	switch {
	case verdict == nil:
		return "absent"
	case errors.As(verdict, &refusal):
		return "refused: " + refusal.Code
	}
	return "fault: " + verdict.Error()
}

// removeImageCheck removes the check container (an ID or the check's name) and its
// anonymous volumes, and waits until the engine no longer reports it. It
// runs even when ctx was cancelled, bounded by removalTimeout.
func (b *GVisor) removeImageCheck(ctx context.Context, container string) error {
	return b.removeContainer(context.WithoutCancel(ctx), container)
}

// helperMount is the one mount an ops-mode sandbox has.
func helperMount(helper *OpsHelper) map[string]any {
	return map[string]any{
		"Type": "bind", "Source": helper.Dir, "Target": sandboxops.MountTarget, "ReadOnly": true,
		"BindOptions": map[string]any{"Propagation": "rprivate"},
	}
}

// verifyHelperMount is the ops-mode readback: exactly the requested mount in
// the host configuration and exactly one read-only rprivate bind of the
// pinned directory at /.mscomputer among the container's mounts.
func verifyHelperMount(c inspectedContainer, helper *OpsHelper) error {
	h := c.HostConfig
	if len(h.Mounts) != 1 || len(c.Mounts) != 1 {
		return fmt.Errorf("sandbox %s does not carry exactly the ops helper mount", c.Name)
	}
	requested, mounted := h.Mounts[0], c.Mounts[0]
	if requested.Type != "bind" || requested.Source != helper.Dir || requested.Target != sandboxops.MountTarget || !requested.ReadOnly ||
		requested.BindOptions == nil || requested.BindOptions.Propagation != "rprivate" {
		return fmt.Errorf("sandbox %s ops helper mount request differs from the pinned mount", c.Name)
	}
	if mounted.Type != "bind" || mounted.Source != helper.Dir || mounted.Destination != sandboxops.MountTarget || mounted.RW ||
		mounted.Propagation != "rprivate" {
		return fmt.Errorf("sandbox %s ops helper mount is not the pinned read-only directory", c.Name)
	}
	return nil
}

// RunHelper runs the helper once in instanceID: docker exec of the fixed
// helper path as the image's default user, not privileged, with no added
// environment and no TTY, with request as its only stdin. Its stdout is read
// bounded by sandboxops.MaxResponseBytes; stderr is flushed and dropped.
func (b *GVisor) RunHelper(ctx context.Context, instanceID string, request []byte) ([]byte, error) {
	if b.opsHelper == nil {
		return nil, errors.New("sandbox ops are not enabled on this backend")
	}
	if len(request) > sandboxops.MaxRequestBytes {
		return nil, errors.New("ops helper request exceeds its bound")
	}
	id, err := b.createHelperExec(ctx, instanceID)
	if err != nil {
		return nil, err
	}
	stdout, err := b.engine.hijackExec(ctx, id, request)
	if err != nil {
		return nil, b.unanswered(ctx, err)
	}
	if err := b.helperExited(ctx, id); err != nil {
		return nil, err
	}
	return stdout, nil
}

// Running reports the engine's record of instanceID (GET
// /containers/{id}/json). It starts no exec, so nothing enters the guest. An
// unknown container is not running.
func (b *GVisor) Running(ctx context.Context, instanceID string) (bool, error) {
	if b.opsHelper == nil {
		return false, errors.New("sandbox ops are not enabled on this backend")
	}
	container, found, err := b.inspect(ctx, instanceID)
	if err != nil {
		return false, err
	}
	return found && container.State.Running, nil
}

// createHelperExec creates the helper exec of RunHelper and StreamHelper.
func (b *GVisor) createHelperExec(ctx context.Context, instanceID string) (string, error) {
	var created struct {
		ID string `json:"Id"`
	}
	err := b.engine.call(ctx, http.MethodPost, "/containers/"+url.PathEscape(instanceID)+"/exec", nil, map[string]any{
		"AttachStdin": true, "AttachStdout": true, "AttachStderr": true, "Tty": false, "Privileged": false,
		"User": "", "Env": []string{}, "Cmd": []string{sandboxops.HelperPath},
	}, &created)
	switch status := engineStatus(err); {
	case status == http.StatusNotFound || status == http.StatusConflict:
		// No such container, or it is not running.
		return "", miner.ErrSandboxNotRunning
	case err != nil:
		return "", b.unanswered(ctx, err)
	case created.ID == "":
		return "", errors.New("docker engine created an exec without an ID")
	}
	return created.ID, nil
}

// helperExited waits for the helper exec to be seen ended and requires a
// zero exit status.
func (b *GVisor) helperExited(ctx context.Context, id string) error {
	var inspected struct {
		Running  bool `json:"Running"`
		ExitCode int  `json:"ExitCode"`
	}
	for try := 0; ; try++ {
		if err := b.engine.call(ctx, http.MethodGet, "/exec/"+url.PathEscape(id)+"/json", nil, nil, &inspected); err != nil {
			return b.unanswered(ctx, err)
		}
		if !inspected.Running || try == exitSettleTries {
			break
		}
		timer := time.NewTimer(exitSettlePoll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return b.unanswered(ctx, ctx.Err())
		case <-timer.C:
		}
	}
	if inspected.Running || inspected.ExitCode != 0 {
		// The helper ended abnormally or was replaced: sandbox_op_failed.
		return fmt.Errorf("ops helper exited with status %d", inspected.ExitCode)
	}
	return nil
}

// StreamHelper runs one streamed helper transfer (a direct file transfer)
// in instanceID, with the same exec as RunHelper. stdin is request, a
// newline, and then body when body is not nil; the helper's first stdout
// line (bounded by MaxResponseBytes) is returned, and every stdout byte
// after it is copied to sink, which may be nil only when none may follow.
// A sink with a HelperAnswer([]byte) error method sees the line before the
// first byte after it.
// It returns the response line and the number of bytes copied to sink.
func (b *GVisor) StreamHelper(ctx context.Context, instanceID string, request []byte, body io.Reader, sink io.Writer) ([]byte, int64, error) {
	if b.opsHelper == nil {
		return nil, 0, errors.New("sandbox ops are not enabled on this backend")
	}
	if len(request) > sandboxops.MaxRequestBytes || bytes.IndexByte(request, '\n') >= 0 {
		return nil, 0, errors.New("ops helper stream request is not one bounded line")
	}
	id, err := b.createHelperExec(ctx, instanceID)
	if err != nil {
		return nil, 0, err
	}
	line, copied, err := b.engine.streamExec(ctx, id, append(append([]byte{}, request...), '\n'), body, sink)
	if err != nil {
		return nil, copied, b.unanswered(ctx, err)
	}
	if err := b.helperExited(ctx, id); err != nil {
		return nil, copied, err
	}
	return line, copied, nil
}

// unanswered classifies a failed engine call. An engine-answered
// error is never a miner fault (the allowlist is empty until lab evidence).
// A call without an answer is a miner fault only when an independent
// health check of the same daemon fails as well.
func (b *GVisor) unanswered(ctx context.Context, err error) error {
	if engineStatus(err) != 0 || ctx.Err() != nil {
		return err
	}
	ping, cancel := context.WithTimeout(context.WithoutCancel(ctx), pingTimeout)
	defer cancel()
	if pingErr := b.engine.call(ping, http.MethodGet, "/_ping", nil, nil, nil); pingErr != nil {
		return &miner.SandboxEngineUnavailable{Err: errors.Join(err, pingErr)}
	}
	return err
}

// hijackExec starts exec id attached, writes stdin, half-closes it, and
// demultiplexes the raw stream until the helper exits.
func (e *engine) hijackExec(ctx context.Context, id string, stdin []byte) ([]byte, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", e.socket)
	if err != nil {
		return nil, fmt.Errorf("docker engine exec start: %w", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	body, _ := json.Marshal(map[string]any{"Detach": false, "Tty": false})
	var request bytes.Buffer
	fmt.Fprintf(&request, "POST /%s/exec/%s/start HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: %d\r\n\r\n",
		engineAPIVersion, url.PathEscape(id), len(body))
	request.Write(body)
	if _, err := conn.Write(request.Bytes()); err != nil {
		return nil, fmt.Errorf("docker engine exec start: %w", err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		return nil, fmt.Errorf("docker engine exec start: %w", err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols && response.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(response.Body, maxEngineErrorBytes))
		response.Body.Close()
		return nil, &engineError{Status: response.StatusCode, Message: bounded(string(raw))}
	}
	if _, err := conn.Write(stdin); err != nil {
		return nil, fmt.Errorf("write ops helper request: %w", err)
	}
	if closer, ok := conn.(interface{ CloseWrite() error }); ok {
		if err := closer.CloseWrite(); err != nil {
			return nil, err
		}
	}
	return demux(reader, sandboxops.MaxResponseBytes)
}

// demux reads Docker's multiplexed raw stream: an 8-byte header (stream,
// three zero bytes, big-endian length) per frame. It keeps at most limit
// bytes of stdout and fails beyond them, and drops stderr after counting it
// against its own bound.
func demux(reader io.Reader, limit int) ([]byte, error) {
	var stdout bytes.Buffer
	stderr := 0
	var header [8]byte
	for {
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return stdout.Bytes(), nil
			}
			return nil, fmt.Errorf("ops helper stream: %w", err)
		}
		size := int64(binary.BigEndian.Uint32(header[4:]))
		switch header[0] {
		case 1:
			if int64(stdout.Len())+size > int64(limit) {
				return nil, errors.New("ops helper stdout exceeds its bound")
			}
			if _, err := io.CopyN(&stdout, reader, size); err != nil {
				return nil, fmt.Errorf("ops helper stream: %w", err)
			}
		case 2:
			if stderr += int(size); stderr > maxHelperStderrBytes {
				return nil, errors.New("ops helper stderr exceeds its bound")
			}
			if _, err := io.CopyN(io.Discard, reader, size); err != nil {
				return nil, fmt.Errorf("ops helper stream: %w", err)
			}
		default:
			return nil, errors.New("ops helper stream has an unknown frame")
		}
	}
}

// streamExec is hijackExec for a streamed transfer: it writes head and then
// body to the exec's stdin while it reads the demultiplexed stdout, returns
// the first stdout line and copies the rest to sink. When the helper answers
// before it took the whole body (a refusal), the body copy is abandoned.
func (e *engine) streamExec(ctx context.Context, id string, head []byte, body io.Reader, sink io.Writer) ([]byte, int64, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", e.socket)
	if err != nil {
		return nil, 0, fmt.Errorf("docker engine exec start: %w", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	start, _ := json.Marshal(map[string]any{"Detach": false, "Tty": false})
	var request bytes.Buffer
	fmt.Fprintf(&request, "POST /%s/exec/%s/start HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: %d\r\n\r\n",
		engineAPIVersion, url.PathEscape(id), len(start))
	request.Write(start)
	if _, err := conn.Write(request.Bytes()); err != nil {
		return nil, 0, fmt.Errorf("docker engine exec start: %w", err)
	}
	reader := bufio.NewReaderSize(conn, 1<<20)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("docker engine exec start: %w", err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols && response.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(response.Body, maxEngineErrorBytes))
		response.Body.Close()
		return nil, 0, &engineError{Status: response.StatusCode, Message: bounded(string(raw))}
	}
	written := make(chan error, 1)
	go func() {
		if _, err := conn.Write(head); err != nil {
			written <- fmt.Errorf("write ops helper request: %w", err)
			return
		}
		var copyErr error
		if body != nil {
			if _, err := io.CopyBuffer(conn, body, make([]byte, 1<<20)); err != nil {
				copyErr = fmt.Errorf("write ops helper stream: %w", err)
			}
		}
		// Half-close even after a failed body: the helper then sees a short
		// stream, refuses it and exits instead of waiting for more.
		closer, ok := conn.(interface{ CloseWrite() error })
		if !ok {
			written <- errors.Join(copyErr, errors.New("ops helper stream cannot half-close"))
			return
		}
		written <- errors.Join(copyErr, closer.CloseWrite())
	}()
	stdout := bufio.NewReaderSize(&stdoutFrames{reader: reader}, 1<<20)
	line, err := readHelperLine(stdout)
	if err != nil {
		return nil, 0, err
	}
	if head, ok := sink.(interface{ HelperAnswer([]byte) error }); ok {
		if err := head.HelperAnswer(line); err != nil {
			return nil, 0, err
		}
	}
	var copied int64
	if sink != nil {
		copied, err = io.CopyBuffer(sink, stdout, make([]byte, 1<<20))
	} else {
		var extra [1]byte
		if n, _ := stdout.Read(extra[:]); n > 0 {
			err = errors.New("ops helper wrote after its answer")
		}
	}
	if err != nil {
		return nil, copied, err
	}
	// stdout ended: the helper is done. A body it did not consume (it
	// refused the transfer) is abandoned rather than awaited.
	select {
	case werr := <-written:
		if werr != nil && body == nil {
			return nil, copied, werr
		}
	default:
		_ = conn.SetWriteDeadline(time.Unix(1, 0))
		<-written
	}
	return line, copied, nil
}

func readHelperLine(reader *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, err := reader.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > sandboxops.MaxResponseBytes {
			return nil, errors.New("ops helper stdout exceeds its bound")
		}
		switch {
		case err == nil:
			return line, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			if len(line) == 0 {
				return nil, errors.New("ops helper answered nothing")
			}
			return line, nil
		default:
			return nil, fmt.Errorf("ops helper stream: %w", err)
		}
	}
}

// stdoutFrames reads the stdout payload of Docker's multiplexed raw stream,
// dropping stderr frames after counting them against their bound.
type stdoutFrames struct {
	reader    io.Reader
	remaining int64
	stderr    int
}

func (f *stdoutFrames) Read(p []byte) (int, error) {
	for f.remaining == 0 {
		var header [8]byte
		if _, err := io.ReadFull(f.reader, header[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return 0, io.EOF
			}
			return 0, fmt.Errorf("ops helper stream: %w", err)
		}
		size := int64(binary.BigEndian.Uint32(header[4:]))
		switch header[0] {
		case 1:
			f.remaining = size
		case 2:
			if f.stderr += int(size); f.stderr > maxHelperStderrBytes {
				return 0, errors.New("ops helper stderr exceeds its bound")
			}
			if _, err := io.CopyN(io.Discard, f.reader, size); err != nil {
				return 0, fmt.Errorf("ops helper stream: %w", err)
			}
		default:
			return 0, errors.New("ops helper stream has an unknown frame")
		}
	}
	n, err := f.reader.Read(p[:min(int64(len(p)), f.remaining)])
	f.remaining -= int64(n)
	if errors.Is(err, io.EOF) && f.remaining > 0 {
		err = io.ErrUnexpectedEOF
	}
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return n, err
}
