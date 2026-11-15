// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package sandboxhost

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type dockerVectors struct {
	Docker        map[string]any `json:"docker"`
	DockerDigest  string         `json:"docker_digest"`
	InvalidDocker []struct {
		Name  string   `json:"name"`
		Path  []string `json:"path"`
		Value any      `json:"value"`
	} `json:"invalid_docker"`
}

func dockerProfile(t *testing.T) (map[string]any, dockerVectors) {
	t.Helper()
	raw, err := os.ReadFile("testdata/profile-docker-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v dockerVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	doc, _ := egressProfile(t)
	var docker map[string]any
	if err := json.Unmarshal(encode(t, v.Docker), &docker); err != nil {
		t.Fatal(err)
	}
	doc["docker"] = docker
	return doc, v
}

// The same vectors drive report.py's check_docker.
func TestDockerProfileVectorsMatchPythonReportTool(t *testing.T) {
	doc, v := dockerProfile(t)
	profile, err := DecodeProfile(encode(t, doc))
	if err != nil {
		t.Fatal(err)
	}
	if profile.Docker == nil || profile.Docker.Runtime != "runsc-docker" || profile.Docker.VolumeTmpfsMiB != 4096 ||
		strings.Join(profile.Docker.Args, " ") != strings.Join(DockerRuntimeArgs, " ") || profile.Runtime.Name != "runsc" {
		t.Fatalf("docker decoded as %+v", profile.Docker)
	}
	if digest, err := profile.Digest(); err != nil || digest != v.DockerDigest {
		t.Fatalf("digest %q, %v; want %q", digest, err, v.DockerDigest)
	}
	for _, c := range v.InvalidDocker {
		t.Run(c.Name, func(t *testing.T) {
			doc, _ := dockerProfile(t)
			target := doc
			for _, key := range c.Path[:len(c.Path)-1] {
				target = target[key].(map[string]any)
			}
			target[c.Path[len(c.Path)-1]] = c.Value
			if _, err := DecodeProfile(encode(t, doc)); err == nil {
				t.Fatal("profile accepted")
			}
		})
	}
}

// A profile without the member decodes with Docker nil, so a miner without
// docker is unchanged.
func TestProfileWithoutDockerHasNoDockerRuntime(t *testing.T) {
	doc, _ := egressProfile(t)
	profile, err := DecodeProfile(encode(t, doc))
	if err != nil || profile.Docker != nil {
		t.Fatalf("docker %+v, %v", profile.Docker, err)
	}
}
