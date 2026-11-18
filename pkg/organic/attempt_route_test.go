// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package organic_test

import (
	"strings"
	"testing"

	"github.com/misscomputer/mscomputer-miner/pkg/organic"
)

// renameDeployment moves the v2 golden's one deployment to deploymentID on
// routeHost and reseals every digest.
func renameDeployment(t *testing.T, deploymentID, routeHost string) organic.ActiveAssignmentManifestV2 {
	t.Helper()
	manifest := *decodeFixture(t, "active-assignment-manifest.v2", &organic.ActiveAssignmentManifestV2{})
	deployment := manifest.Deployments[0]
	old := deployment.DeploymentID
	replicas := append([]organic.OrganicAssignedReplica(nil), deployment.Replicas...)
	for index := range replicas {
		replicas[index].ReplicaID = deploymentID + strings.TrimPrefix(replicas[index].ReplicaID, old)
		replicas[index].EndpointID = deploymentID + strings.TrimPrefix(replicas[index].EndpointID, old)
	}
	deployment.Replicas = replicas
	deployment.DeploymentID = deploymentID
	deployment.RouteHost = routeHost
	return resealV2(t, manifest, deployment)
}

func resealV2(t *testing.T, manifest organic.ActiveAssignmentManifestV2, deployments ...organic.OrganicDeploymentAssignment) organic.ActiveAssignmentManifestV2 {
	t.Helper()
	var err error
	for index := range deployments {
		if deployments[index].AssignmentDigestSHA256, err = organic.DigestWithout(deployments[index], "assignment_digest_sha256"); err != nil {
			t.Fatal(err)
		}
	}
	manifest.Deployments = deployments
	if manifest.AssignmentVectorDigestSHA256, err = organic.DigestHex(deployments); err != nil {
		t.Fatal(err)
	}
	if manifest.ManifestDigestSHA256, err = organic.DigestWithout(manifest, "manifest_digest_sha256"); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func TestManifestAttemptDeploymentServesUnderParentHost(t *testing.T) {
	const parent = "hello-world-k3902"
	cases := []struct {
		deploymentID, host, err string
	}{
		{parent + "-r0a1b2c3d", parent + ".ms.computer", ""},
		{parent + "-r0a1b2c3d", parent + "-r0a1b2c3d.ms.computer", "manifest_route_host_invalid"},
		{parent + "-r0a1b2c3d", "blog-h2468.ms.computer", "manifest_route_host_invalid"},
		{parent + "-r0A1B2C3D", parent + ".ms.computer", "manifest assignment fields are invalid"},
		{parent + "-r0a1b2c3", parent + ".ms.computer", "manifest_route_host_invalid"},
		{parent + "-r0a1b2c3d4", parent + ".ms.computer", "manifest_route_host_invalid"},
		{parent + "-r0a1b2c3d-r0a1b2c3d", parent + "-r0a1b2c3d.ms.computer", "manifest_route_host_invalid"},
		{parent + "-r0a1b2c3d-r0a1b2c3d", parent + ".ms.computer", "manifest_route_host_invalid"},
		{"syn-x-r0a1b2c3d", "syn-x.ms.computer", "manifest assignment fields are invalid"},
		{"xn--x-r0a1b2c3d", "xn--x.ms.computer", "manifest assignment fields are invalid"},
		{strings.Repeat("x", 53) + "-r0a1b2c3d", strings.Repeat("x", 53) + ".ms.computer", ""},
		{strings.Repeat("x", 54) + "-r0a1b2c3d", strings.Repeat("x", 54) + ".ms.computer", "manifest assignment fields are invalid"},
		{"plain-r0123abcd", "plain-r0123abcd.ms.computer", "manifest_route_host_invalid"},
	}
	for _, tc := range cases {
		manifest := renameDeployment(t, tc.deploymentID, tc.host)
		err := manifest.Validate()
		if tc.err == "" && err != nil {
			t.Fatalf("%s on %s refused: %v", tc.deploymentID, tc.host, err)
		}
		if tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)) {
			t.Fatalf("%s on %s: got %v, want %s", tc.deploymentID, tc.host, err, tc.err)
		}
	}
}

func TestManifestRefusesTwoDeploymentsOnOneHost(t *testing.T) {
	const parent = "hello-world-k3902"
	attempt := renameDeployment(t, parent+"-r0a1b2c3d", parent+".ms.computer").Deployments[0]
	other := renameDeployment(t, parent+"-r99887766", parent+".ms.computer").Deployments[0]
	for _, other := range []organic.OrganicDeploymentAssignment{
		renameDeployment(t, parent, parent+".ms.computer").Deployments[0],
		other,
	} {
		base := *decodeFixture(t, "active-assignment-manifest.v2", &organic.ActiveAssignmentManifestV2{})
		first, second := other, attempt
		if first.DeploymentID > second.DeploymentID {
			first, second = second, first
		}
		// Distinct endpoints, one host.
		manifest := resealV2(t, base, first, second)
		if err := manifest.Validate(); err == nil || err.Error() != "manifest_route_host_duplicate" {
			t.Fatalf("two deployments on one host: %v", err)
		}
	}
}

func TestManifestV3AttemptHostOnlyForOCI(t *testing.T) {
	v3 := *decodeFixture(t, "active-assignment-manifest.v3", &organic.ActiveAssignmentManifestV3{})
	for index, kind := range []string{organic.WorkloadKindOCIImageV1, organic.WorkloadKindStaticSiteV1} {
		manifest := v3
		deployments := append([]organic.OrganicDeploymentAssignmentV3(nil), v3.Deployments...)
		deployment := deployments[index]
		if deployment.WorkloadKind != kind {
			t.Fatalf("v3 golden deployment %d is not %s", index, kind)
		}
		old := deployment.DeploymentID
		attempt := old + "-r0a1b2c3d"
		replicas := append([]organic.OrganicAssignedReplica(nil), deployment.Replicas...)
		for r := range replicas {
			replicas[r].ReplicaID = attempt + strings.TrimPrefix(replicas[r].ReplicaID, old)
			replicas[r].EndpointID = attempt + strings.TrimPrefix(replicas[r].EndpointID, old)
		}
		deployment.Replicas, deployment.DeploymentID = replicas, attempt
		var err error
		if deployment.AssignmentDigestSHA256, err = organic.DigestWithout(deployment, "assignment_digest_sha256"); err != nil {
			t.Fatal(err)
		}
		deployments[index] = deployment
		manifest.Deployments = deployments
		if manifest.AssignmentVectorDigestSHA256, err = organic.DigestHex(deployments); err != nil {
			t.Fatal(err)
		}
		if manifest.ManifestDigestSHA256, err = organic.DigestWithout(manifest, "manifest_digest_sha256"); err != nil {
			t.Fatal(err)
		}
		err = manifest.Validate()
		if kind == organic.WorkloadKindOCIImageV1 && err != nil {
			t.Fatalf("OCI attempt on its parent host refused: %v", err)
		}
		if kind == organic.WorkloadKindStaticSiteV1 && (err == nil || err.Error() != "manifest_route_host_invalid") {
			t.Fatalf("static attempt on its parent host: %v", err)
		}
	}
}
