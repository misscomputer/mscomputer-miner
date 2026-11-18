// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package sandbox

import (
	"encoding/json"
	"errors"
)

// DecodeNetworkPolicy parses a network_set payload: the exact canonical
// JSON ({"allow":[...],"mode":"..."}) of a valid NetworkPolicy.
func DecodeNetworkPolicy(payload []byte) (NetworkPolicy, error) {
	var policy NetworkPolicy
	if err := json.Unmarshal(payload, &policy); err != nil {
		return policy, err
	}
	if err := policy.Validate(); err != nil {
		return policy, err
	}
	if canonical, _ := json.Marshal(policy); string(canonical) != string(payload) {
		return policy, errors.New("network policy payload is not canonical")
	}
	return policy, nil
}
