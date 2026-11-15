// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package sandbox

// ImageTooLarge refuses a tenant image above the network-wide cap
// (MaxTenantImageMiB). It is a tenant error, never a miner fault; a gateway
// or broker refuses such an image before placement.
const ImageTooLarge = "image_too_large"

// MaxTenantImageMiB is the network-wide cap on one tenant image, unpacked.
// Miners cannot set it; a testnet may run a
// smaller explicit value.
const MaxTenantImageMiB = 10240

// TenantWorkingSpaceMiB is the writable working space of one floor slot
// beside its image: the smallest sandbox disk.
const TenantWorkingSpaceMiB = MinDiskMiB

// LedgerSource is the only accepted source of the used capacity a refusal is
// assessed against: the validator's own lease ledger, never the miner's claim.
const LedgerSource = "validator_ledger"
