// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package sandboxbackend

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/misscomputer/mscomputer-miner/pkg/protocol"
	"github.com/misscomputer/mscomputer-miner/pkg/sandboxops"
)

// These tests cover the ops-mode defences that run before a sandbox is
// created: the helper pin's extended-attribute rule and the image
// check for an entry at the helper's mount target. The engine is an
// in-process http.RoundTripper, so no socket or listener exists. They prove
// what the backend asks the engine and how it decides on each answer; they
// do not prove how Docker answers. That, and whether a guest sees the host
// pin's attributes, is lab evidence.

// engineCall is one request the backend made to the scripted engine.
type engineCall struct {
	Method, Path string
	Query        url.Values
	Body         map[string]any
	// Cancelled is whether the request's context was already done.
	Cancelled bool
}

func (c engineCall) String() string {
	if len(c.Query) == 0 {
		return c.Method + " " + c.Path
	}
	return c.Method + " " + c.Path + "?" + c.Query.Encode()
}

// scriptedEngine is the backend's Engine API transport. answer returns the
// status, JSON body and headers of each call; a negative status drops the
// call without an answer.
type scriptedEngine struct {
	mu     sync.Mutex
	calls  []engineCall
	answer func(engineCall) (int, any, http.Header)
}

func (e *scriptedEngine) RoundTrip(r *http.Request) (*http.Response, error) {
	call := engineCall{Method: r.Method, Path: strings.TrimPrefix(r.URL.Path, "/"+engineAPIVersion), Query: r.URL.Query(), Cancelled: r.Context().Err() != nil}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&call.Body)
		_ = r.Body.Close()
	}
	e.mu.Lock()
	e.calls = append(e.calls, call)
	answer := e.answer
	e.mu.Unlock()
	status, body, header := answer(call)
	if status < 0 {
		return nil, errors.New("connection closed before the engine answered")
	}
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{StatusCode: status, Status: http.StatusText(status), Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: header, Body: io.NopCloser(bytes.NewReader(raw)), ContentLength: int64(len(raw)), Request: r}, nil
}

func (e *scriptedEngine) log() []engineCall {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.calls)
}

// scriptedBackend is a backend whose engine is e, with a public registry
// address and a data root with room for a pull.
func scriptedBackend(t *testing.T, e *scriptedEngine) *GVisor {
	client := &http.Client{Transport: e}
	return &GVisor{
		config: Config{Runtime: "runsc", DataRoot: t.TempDir(), Slice: testSlice, DiskMiB: 1024, Sandboxes: 2, ImageMaxMiB: 64, LogMiB: 4, PIDsMax: 4096},
		engine: &engine{client: client, pullClient: client, base: "http://docker/" + engineAPIVersion}, sliceCgroup: "/mc.slice/" + testSlice,
		lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("151.101.0.1")}, nil
		},
		hostAddresses: func() ([]netip.Addr, error) { return nil, nil },
	}
}

// pathStat is the X-Docker-Container-Path-Stat header dockerd sends with an
// archive stat that found an entry; mode is a Go fs.FileMode.
func pathStat(mode uint32, target string) http.Header {
	raw, _ := json.Marshal(map[string]any{"name": ".mscomputer", "size": 0, "mode": mode, "mtime": "2026-10-19T00:00:00Z", "linkTarget": target})
	return http.Header{"X-Docker-Container-Path-Stat": {base64.StdEncoding.EncodeToString(raw)}}
}

// Entries an image can hold at /.mscomputer. Each is refused, the
// directory included: only an engine 404 shows that the path is absent.
var helperTargetEntries = map[string]http.Header{
	"symlink into the root": pathStat(1<<27|0o777, "/usr/bin"),
	"directory":             pathStat(1<<31|0o755, ""),
	"regular file":          pathStat(0o644, ""),
	"fifo":                  pathStat(1<<25|0o644, ""),
}

const testCheckID = "abababababababababababababababababababababababababababababababab"

// neverStartedCheck is an engine inspection of a created, never-started
// check container.
func neverStartedCheck(id string) map[string]any {
	return map[string]any{"Id": id, "Name": "/check", "Image": testImageID,
		"State": map[string]any{"Status": "created", "Running": false, "Pid": 0, "StartedAt": "0001-01-01T00:00:00Z", "FinishedAt": "0001-01-01T00:00:00Z"}}
}

// The helper pin refuses any extended attribute on the opened
// helper directory or helper file, such as a file capability set on the
// pinned binary, and accepts the same pin without it. The attribute is set
// through the writable source of the read-only pinned directory.
func TestOpsHelperPinRefusesExtendedAttributes(t *testing.T) {
	for _, target := range []string{"directory", "helper"} {
		t.Run(target, func(t *testing.T) {
			helper, source := pinnedHelperSource(t, "helper binary")
			if err := verifyHelper(helper); err != nil {
				t.Fatalf("pinned helper without attributes refused: %v", err)
			}
			path := source
			if target == "helper" {
				path = filepath.Join(source, sandboxops.HelperName)
			}
			if err := unix.Lsetxattr(path, "user.mscomputer-test", []byte("x"), 0); errors.Is(err, unix.ENOTSUP) {
				t.Skipf("TMPDIR's filesystem has no user extended attributes: %v", err)
			} else if err != nil {
				t.Fatal(err)
			}
			if err := verifyHelper(helper); err == nil || !strings.Contains(err.Error(), "extended attributes") {
				t.Fatalf("verifyHelper with an extended attribute on the %s = %v, want the extended-attribute refusal", target, err)
			}
		})
	}
}

// In ops mode, before the sandbox is
// created, a never-started container of the verified image without any
// mount is checked for /.mscomputer. Only an engine 404 for a check that
// still exists lets the create proceed; any entry refuses the lease as
// image_unavailable, a refusal that is not the miner's fault. The check is
// removed with its anonymous volumes either way. Without ops nothing is
// checked.
func TestOpsCreateChecksTheHelperTargetBeforeCreating(t *testing.T) {
	lease := testLease(nil)
	instance := instanceOf(lease)
	checkName := instance + imageCheckSuffix
	image := map[string]any{"Id": testImageID, "RepoDigests": []string{"busybox@" + testImageDigest}, "Os": "linux", "Architecture": "amd64",
		"Size": 4 << 20, "Config": map[string]any{"Cmd": []string{"sh"}}}
	// leaseEngine answers one Create: no container yet, a pull of the
	// image, its inspection, the check, and a refused real create, the end
	// of what these cases need.
	leaseEngine := func(stat int, header http.Header) *scriptedEngine {
		checkExists := false
		return &scriptedEngine{answer: func(c engineCall) (int, any, http.Header) {
			switch {
			case c.Method == http.MethodPost && c.Path == "/images/create":
				return 200, map[string]string{"status": "Status: Downloaded newer image for busybox@" + testImageDigest}, nil
			case c.Method == http.MethodGet && (c.Path == "/images/docker.io/library/busybox@"+testImageDigest+"/json" || c.Path == "/images/"+testImageID+"/json"):
				return 200, image, nil
			case c.Method == http.MethodGet && c.Path == "/containers/"+instance+"/json":
				return 404, map[string]string{"message": "No such container"}, nil
			case c.Method == http.MethodPost && c.Path == "/containers/create" && c.Query.Get("name") == checkName:
				checkExists = true
				return 201, map[string]any{"Id": testCheckID, "Warnings": []string{}}, nil
			case c.Method == http.MethodHead && c.Path == "/containers/"+testCheckID+"/archive":
				return stat, nil, header
			case c.Method == http.MethodGet && c.Path == "/containers/"+testCheckID+"/json":
				if !checkExists {
					return 404, map[string]string{"message": "No such container"}, nil
				}
				return 200, neverStartedCheck(testCheckID), nil
			case c.Method == http.MethodDelete && c.Path == "/containers/"+testCheckID:
				checkExists = false
				return 204, nil, nil
			case c.Method == http.MethodPost && c.Path == "/containers/create" && c.Query.Get("name") == instance:
				return 500, map[string]string{"message": "scripted end of the create"}, nil
			}
			return 500, map[string]string{"message": "unscripted " + c.String()}, nil
		}}
	}
	containerCalls := func(e *scriptedEngine) (calls []string, creates []engineCall) {
		for _, c := range e.log() {
			if strings.HasPrefix(c.Path, "/containers/") {
				calls = append(calls, c.String())
			}
			if c.Path == "/containers/create" {
				creates = append(creates, c)
			}
		}
		return calls, creates
	}
	mounts := func(create engineCall) any {
		host, _ := create.Body["HostConfig"].(map[string]any)
		return host["Mounts"]
	}
	inspectInstance := "GET /containers/" + instance + "/json"
	createCheck := "POST /containers/create?name=" + url.QueryEscape(checkName) + "&platform=linux%2Famd64"
	statCheck := "HEAD /containers/" + testCheckID + "/archive?path=%2F.mscomputer"
	inspectCheck := "GET /containers/" + testCheckID + "/json"
	removeImageCheck := "DELETE /containers/" + testCheckID + "?force=1&v=1"
	createSandbox := "POST /containers/create?name=" + url.QueryEscape(instance) + "&platform=linux%2Famd64"

	t.Run("ops off", func(t *testing.T) {
		e := leaseEngine(404, nil)
		err := scriptedBackend(t, e).Create(context.Background(), instance, lease)
		calls, creates := containerCalls(e)
		if want := []string{inspectInstance, createSandbox}; !slices.Equal(calls, want) || refusalCode(err) != "" {
			t.Fatalf("calls %q (err %v), want %q", calls, err, want)
		}
		if _, has := creates[0].Body["HostConfig"].(map[string]any)["Mounts"]; has {
			t.Fatal("a create without ops carries a Mounts member")
		}
	})

	helper := pinnedHelper(t, "helper binary")
	t.Run("absent", func(t *testing.T) {
		e := leaseEngine(404, nil)
		b := scriptedBackend(t, e)
		opsMode(t, b, helper)
		err := b.Create(context.Background(), instance, lease)
		calls, creates := containerCalls(e)
		want := []string{inspectInstance, createCheck, statCheck, inspectCheck, removeImageCheck, inspectCheck, createSandbox}
		if !slices.Equal(calls, want) || err == nil || refusalCode(err) != "" {
			t.Fatalf("calls %q (err %v), want %q and the scripted create failure", calls, err, want)
		}
		if check := creates[0]; check.Body["Image"] != testImageID || mounts(check) != nil {
			t.Fatalf("check create body %v, want the verified image and no mount", check.Body)
		}
		// The miner recognises a check by its lease label and its name (pkg/miner orphan sweep).
		if labels, _ := creates[0].Body["Labels"].(map[string]any); labels[LabelLeaseID] != protocol.SandboxLeaseIDV1(lease) || labels[LabelSandbox] != sandboxLabelV1 {
			t.Fatalf("check labels %v, want the lease label and the sandbox label", labels)
		}
		if mounts(creates[1]) == nil {
			t.Fatal("the sandbox create after the check lost the helper mount")
		}
		if _, has := creates[1].Body["Entrypoint"]; has {
			t.Fatalf("a create without keepalive replaces the entrypoint: %v", creates[1].Body)
		}
	})
	// Keepalive: the helper becomes PID 1 and runs the image's own command
	// as its child; the image's env, user and working directory are left
	// to the image (no such members). The check never runs the helper.
	t.Run("keepalive", func(t *testing.T) {
		e := leaseEngine(404, nil)
		b := scriptedBackend(t, e)
		keep := helper
		keep.Keepalive = true
		opsMode(t, b, keep)
		_ = b.Create(context.Background(), instance, lease)
		_, creates := containerCalls(e)
		if len(creates) != 2 {
			t.Fatalf("creates %v, want the check and the sandbox", creates)
		}
		if _, has := creates[0].Body["Entrypoint"]; has || creates[0].Body["Cmd"] != nil {
			t.Fatalf("check create body %v runs a command", creates[0].Body)
		}
		body := creates[1].Body
		if fmt.Sprint(body["Entrypoint"]) != "["+sandboxops.HelperPath+"]" || fmt.Sprint(body["Cmd"]) != "[keepalive sh]" || mounts(creates[1]) == nil {
			t.Fatalf("keepalive create body %v, want the helper running the image command sh", body)
		}
		for _, member := range []string{"Env", "User", "WorkingDir"} {
			if _, has := body[member]; has {
				t.Fatalf("keepalive create sets %s; the image's own applies", member)
			}
		}
	})
	for name, header := range helperTargetEntries {
		t.Run(name, func(t *testing.T) {
			e := leaseEngine(200, header)
			b := scriptedBackend(t, e)
			opsMode(t, b, helper)
			err := b.Create(context.Background(), instance, lease)
			calls, _ := containerCalls(e)
			if want := []string{inspectInstance, createCheck, statCheck, removeImageCheck, inspectCheck}; !slices.Equal(calls, want) || refusalCode(err) != "image_unavailable" {
				t.Fatalf("calls %q, err %v; want %q and image_unavailable", calls, err, want)
			}
		})
	}
}

// checkEngine scripts the engine's side of one image check: the check
// container exists from an answered create (or an unanswered one that still
// made it) until a removal the engine carries out.
type checkEngine struct {
	exists bool
	// creates answers successive check creates; 201 makes the container.
	creates []int
	// noID answers a create without the container's ID; lostCreate makes
	// the container though the create goes unanswered.
	noID, lostCreate bool
	// stat answers the archive stat; it may change exists first.
	stat func(p *checkEngine) int
	// inspect answers an inspection of an existing check: 0 a created,
	// never-started container, 1 a started one, or that status.
	inspect int
	// remove answers the removal of an existing check; 0 removes it.
	remove int
}

func (p *checkEngine) answer(c engineCall) (int, any, http.Header) {
	switch {
	case c.Method == http.MethodPost && c.Path == "/containers/create":
		status := 201
		if len(p.creates) > 0 {
			status, p.creates = p.creates[0], p.creates[1:]
		}
		switch {
		case status == 409 && p.exists, status == 404:
			return status, map[string]string{"message": "scripted refusal"}, nil
		case status == 201:
			p.exists = true
			if p.noID {
				return 201, map[string]any{"Warnings": []string{}}, nil
			}
			return 201, map[string]any{"Id": testCheckID, "Warnings": []string{}}, nil
		case status < 0:
			p.exists = p.lostCreate
			return status, nil, nil
		}
		return status, map[string]string{"message": "scripted refusal"}, nil
	case c.Method == http.MethodHead && c.Path == "/containers/"+testCheckID+"/archive":
		return p.stat(p), nil, nil
	case c.Method == http.MethodGet && strings.HasPrefix(c.Path, "/containers/") && strings.HasSuffix(c.Path, "/json"):
		switch {
		case !p.exists:
			return 404, map[string]string{"message": "No such container"}, nil
		case p.inspect == 0:
			return 200, neverStartedCheck(testCheckID), nil
		case p.inspect == 1:
			started := neverStartedCheck(testCheckID)
			started["State"] = map[string]any{"Status": "running", "Running": true, "Pid": 77, "StartedAt": "2026-10-19T00:00:01Z"}
			return 200, started, nil
		}
		return p.inspect, nil, nil
	case c.Method == http.MethodDelete && strings.HasPrefix(c.Path, "/containers/"):
		switch {
		case !p.exists:
			return 404, map[string]string{"message": "No such container"}, nil
		case p.remove != 0:
			return p.remove, map[string]string{"message": "driver failed to remove root filesystem"}, nil
		}
		p.exists = false
		return 204, nil, nil
	}
	return 500, map[string]string{"message": "unscripted " + c.String()}, nil
}

func statAnswer(status int) func(*checkEngine) int { return func(*checkEngine) int { return status } }

// Every answer the image check can get from the engine ends in one decision:
// the image holds nothing at the target, a non-fault image_unavailable, the
// miner's fault, or a missing image the caller pulls again. Whatever it
// decides, a check the engine created is removed with its volumes, also
// after the caller's context was cancelled, and a check that cannot be
// removed is the miner's fault even when a conflict was found.
func TestImageCheckedecidesOnEveryEngineAnswerAndRemovesTheCheck(t *testing.T) {
	const instance = "ms-sbx-check-test"
	checkName := instance + imageCheckSuffix
	create := "POST /containers/create?name=" + checkName + "&platform=linux%2Famd64"
	stat := "HEAD /containers/" + testCheckID + "/archive?path=%2F.mscomputer"
	inspect := "GET /containers/" + testCheckID + "/json"
	remove := "DELETE /containers/" + testCheckID + "?force=1&v=1"
	inspectName := "GET /containers/" + checkName + "/json"
	removeName := "DELETE /containers/" + checkName + "?force=1&v=1"
	removed := []string{remove, inspect}

	for _, tc := range []struct {
		name     string
		engine   checkEngine
		cancel   bool // the caller's context is cancelled during the stat
		decision string
		calls    []string
	}{
		{"absent", checkEngine{stat: statAnswer(404)}, false, "absent", append([]string{create, stat, inspect}, removed...)},
		{"entry", checkEngine{stat: statAnswer(200)}, false, "image_unavailable", append([]string{create, stat}, removed...)},
		{"stat refused for a never-started check", checkEngine{stat: statAnswer(500)}, false, "image_unavailable", append([]string{create, stat, inspect}, removed...)},
		{"stat refused and the check not inspected", checkEngine{stat: statAnswer(500), inspect: -1}, false, "fault", append([]string{create, stat, inspect}, removed...)},
		{"stat unanswered", checkEngine{stat: statAnswer(-1)}, false, "fault", append([]string{create, stat}, removed...)},
		{"caller cancelled during the stat", checkEngine{stat: statAnswer(-1)}, true, "fault", append([]string{create, stat}, removed...)},
		{"check vanished during the stat", checkEngine{stat: func(p *checkEngine) int { p.exists = false; return 404 }}, false, "fault",
			[]string{create, stat, inspect, remove, inspect}},
		{"check started", checkEngine{stat: statAnswer(404), inspect: 1}, false, "fault", append([]string{create, stat, inspect}, removed...)},
		{"entry but the check is not removed", checkEngine{stat: statAnswer(200), remove: 500}, false, "fault", []string{create, stat, remove}},
		{"absent but the check is not removed", checkEngine{stat: statAnswer(404), remove: 500}, false, "fault", []string{create, stat, inspect, remove}},
		{"image gone", checkEngine{creates: []int{404}}, false, "missing", []string{create}},
		{"check create refused", checkEngine{creates: []int{500}}, false, "fault", []string{create, removeName, inspectName}},
		{"check create unanswered", checkEngine{creates: []int{-1}, lostCreate: true}, false, "fault", []string{create, removeName, inspectName}},
		{"check created without an ID", checkEngine{noID: true}, false, "fault", []string{create, removeName, inspectName}},
		{"check left behind", checkEngine{exists: true, creates: []int{409, 201}, stat: statAnswer(404)}, false, "absent",
			append([]string{create, removeName, inspectName, create, stat, inspect}, removed...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p := tc.engine
			if tc.cancel {
				inner := p.stat
				p.stat = func(p *checkEngine) int { cancel(); return inner(p) }
			}
			e := &scriptedEngine{answer: p.answer}
			b := scriptedBackend(t, e)
			// The sandbox spec carries the helper mount; the check must not.
			b.opsHelper = &OpsHelper{Dir: "/srv/mc-ops-helper", SHA256: digestOf("helper binary")}
			missing, err := b.imageConflict(ctx, instance, testImageID, b.spec(testLease(nil), digestOf("lease"), testImageID))
			decision := "fault"
			switch {
			case missing && err == nil:
				decision = "missing"
			case err == nil:
				decision = "absent"
			case refusalCode(err) != "":
				decision = refusalCode(err)
			}
			calls := e.log()
			rendered := make([]string, len(calls))
			for i, c := range calls {
				rendered[i] = c.String()
				if c.Method == http.MethodDelete && c.Cancelled {
					t.Errorf("check removal %s ran on a cancelled context", c)
				}
				if c.Method == http.MethodPost {
					if host, _ := c.Body["HostConfig"].(map[string]any); host["Mounts"] != nil || c.Body["Image"] != testImageID {
						t.Errorf("check create body %v, want the verified image and no mount", c.Body)
					}
				}
			}
			if decision != tc.decision || !slices.Equal(rendered, tc.calls) {
				t.Fatalf("decision %s (missing %v, err %v), calls %q; want %s, calls %q", decision, missing, err, rendered, tc.decision, tc.calls)
			}
			if p.exists && p.remove == 0 {
				t.Errorf("the check container remains")
			}
			if p.remove != 0 && !strings.Contains(err.Error(), testCheckID) {
				t.Errorf("a check left in place is not named by its ID: %v", err)
			}
		})
	}
}
