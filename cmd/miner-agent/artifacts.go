// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/misscomputer/mscomputer-miner/pkg/artifact"
)

type artifactConfig struct {
	Backend, Dir, PullURL, PullRedirectSuffix string
	Network                                   string
	NetUID                                    uint16
	Hotkey                                    string
	ServiceKey                                ed25519.PrivateKey
}

// operatorArtifacts, when set, opens an artifact backend other than file and
// pull. Only operator builds set it; the public miner build has none.
var operatorArtifacts func(c artifactConfig) (artifact.Store, bool, error)

// operatorPullOptions, when set, adjusts the pull store's request bounds.
var operatorPullOptions func(*artifact.PullStore)

// openArtifacts builds the miner's read store. The pull backend holds no
// storage credential: it signs each exact-key read with the service key the
// hotkey bound at registration, and the operator's gateway answers with a
// short-lived URL for that one object.
func openArtifacts(c artifactConfig) (artifact.Store, error) {
	backend := strings.ToLower(strings.TrimSpace(c.Backend))
	if backend != "pull" && c.PullURL != "" {
		return nil, errors.New("--artifact-pull-url requires --artifact-backend pull")
	}
	if operatorArtifacts != nil {
		if store, handled, err := operatorArtifacts(c); handled {
			return store, err
		}
	}
	if backend != "pull" {
		switch backend {
		case "", "file", "filesystem":
			if c.Dir == "" {
				return nil, errors.New("artifact directory is required for filesystem backend")
			}
			return artifact.FileStore{Root: filepath.Clean(c.Dir)}, nil
		default:
			return nil, fmt.Errorf("unsupported artifact backend %q", backend)
		}
	}
	if c.Dir != "" {
		return nil, errors.New("--artifact-backend pull takes no --artifact-dir")
	}
	store := artifact.PullStore{
		BaseURL: c.PullURL, Network: c.Network, NetUID: c.NetUID, Hotkey: c.Hotkey, ServiceKey: c.ServiceKey,
		LocationHostSuffix: c.PullRedirectSuffix,
	}
	if operatorPullOptions != nil {
		operatorPullOptions(&store)
	}
	if err := store.Validate(); err != nil {
		return nil, fmt.Errorf("invalid artifact pull configuration: %w", err)
	}
	return store, nil
}
