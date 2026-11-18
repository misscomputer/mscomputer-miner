// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package organic

import "regexp"

// A blue-green attempt deployment ID names one runtime placement attempt of a
// route label: <parent-label>-r<8 lowercase hex>, one DNS label of at most 63
// characters, whose parent is a valid route label that is not itself an
// attempt ID. An attempt serves under its parent label's public host; its
// replica and endpoint IDs derive from the attempt ID itself.
var attemptDeploymentPattern = regexp.MustCompile(`^(.+)-r([0-9a-f]{8})$`)

// attemptParentLabel returns the parent route label of an attempt deployment
// ID; ok is false for anything that is not exactly one attempt of a valid,
// non-attempt route label.
func attemptParentLabel(deploymentID string) (parent string, ok bool) {
	if len(deploymentID) > 63 || !ValidRouteLabel(deploymentID) {
		return "", false
	}
	match := attemptDeploymentPattern.FindStringSubmatch(deploymentID)
	if match == nil || !ValidRouteLabel(match[1]) || attemptDeploymentPattern.MatchString(match[1]) {
		return "", false
	}
	return match[1], true
}

// manifestRouteLabel is the route label whose host an OCI manifest
// deployment serves under: an attempt's parent, otherwise the ID itself.
func manifestRouteLabel(deploymentID string) string {
	if parent, ok := attemptParentLabel(deploymentID); ok {
		return parent
	}
	return deploymentID
}
