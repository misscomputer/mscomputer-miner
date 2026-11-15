// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package miner

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

// EndpointRoutes records the local runtime URL each active organic endpoint
// is bound to. A second binding of an endpoint to another URL is refused, and
// deactivation removes the binding.
type EndpointRoutes struct {
	mu        sync.RWMutex
	endpoints map[string]*url.URL
}

func NewEndpointRoutes() *EndpointRoutes {
	return &EndpointRoutes{endpoints: make(map[string]*url.URL)}
}

// Register binds endpointID to an absolute http or https URL without
// credentials, query or fragment.
func (r *EndpointRoutes) Register(endpointID, rawURL string) error {
	if strings.ContainsAny(rawURL, "?#") {
		return fmt.Errorf("invalid tunnel target %q", rawURL)
	}
	u, err := url.Parse(rawURL)
	if err != nil || u == nil {
		return fmt.Errorf("invalid tunnel target %q", rawURL)
	}
	portValid := true
	if u.Port() != "" {
		port, portErr := strconv.Atoi(u.Port())
		portValid = portErr == nil && port >= 1 && port <= 65535
	}
	if endpointID == "" || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || u.RawFragment != "" || u.Opaque != "" || !portValid {
		return fmt.Errorf("invalid tunnel target %q", rawURL)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, exists := r.endpoints[endpointID]; exists && existing.String() != u.String() {
		return fmt.Errorf("tunnel endpoint %q is already bound to another target", endpointID)
	}
	r.endpoints[endpointID] = u
	return nil
}

func (r *EndpointRoutes) Unregister(endpointID string) {
	r.mu.Lock()
	delete(r.endpoints, endpointID)
	r.mu.Unlock()
}

// Lookup returns a copy of the bound URL.
func (r *EndpointRoutes) Lookup(endpointID string) (*url.URL, error) {
	r.mu.RLock()
	value, exists := r.endpoints[endpointID]
	r.mu.RUnlock()
	if !exists {
		return nil, fmt.Errorf("tunnel endpoint %q is unavailable", endpointID)
	}
	copy := *value
	return &copy, nil
}
