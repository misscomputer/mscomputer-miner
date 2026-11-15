// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package main

import (
	"crypto/ed25519"
	"testing"

	"github.com/misscomputer/mscomputer-miner/pkg/artifact"
)

func TestOpenArtifactsPullBackend(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(nil)
	good := artifactConfig{Backend: "pull", PullURL: "https://api.ms.computer/v1/miner-artifacts", Network: "finney", NetUID: 24, Hotkey: "5Dk38RwXtHyqF8FvkyuGeE9ssUJzMtXqgrZ1bWhZsU37a9sE", ServiceKey: key}
	store, err := openArtifacts(good)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.(artifact.BlobOpener); !ok {
		t.Fatal("pull store must stream blobs")
	}
	for name, mutate := range map[string]func(*artifactConfig){
		"http url":         func(c *artifactConfig) { c.PullURL = "http://api.ms.computer/v1/miner-artifacts" },
		"missing url":      func(c *artifactConfig) { c.PullURL = "" },
		"dir too":          func(c *artifactConfig) { c.Dir = t.TempDir() },
		"no key":           func(c *artifactConfig) { c.ServiceKey = nil },
		"url without pull": func(c *artifactConfig) { c.Backend = "file"; c.Dir = t.TempDir() },
	} {
		config := good
		mutate(&config)
		if _, err := openArtifacts(config); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if _, err := openArtifacts(artifactConfig{Backend: "file", Dir: t.TempDir()}); err != nil {
		t.Fatalf("file backend: %v", err)
	}
}
