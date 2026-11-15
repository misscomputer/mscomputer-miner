// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package sandbox

import "testing"

func TestImageTooLargeIsATenantError(t *testing.T) {
	attributed, known := ReceiptErrorAttribution[ImageTooLarge]
	if !known || attributed {
		t.Fatalf("image_too_large known=%v attributed=%v, want a known non-fault code", known, attributed)
	}
	if MaxTenantImageMiB != 10240 || TenantWorkingSpaceMiB != 5120 {
		t.Fatalf("cap %d working %d", MaxTenantImageMiB, TenantWorkingSpaceMiB)
	}
}
