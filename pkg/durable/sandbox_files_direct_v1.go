// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package durable

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// sandboxFileGrantSchema records every claimed direct file grant nonce until
// its grant expired, which makes a grant single-use across restarts.
const sandboxFileGrantSchema = `
CREATE TABLE IF NOT EXISTS sandbox_file_grants (
  nonce TEXT PRIMARY KEY,
  lease_id TEXT NOT NULL,
  expires_at_ns INTEGER NOT NULL,
  claimed_at_ns INTEGER NOT NULL
);
`

// ErrFileGrantReplayed is a grant whose nonce was already claimed.
var ErrFileGrantReplayed = errors.New("sandbox file grant was already used")

// ClaimFileGrant atomically checks that leaseID is still running at now
// (the lease's refusal code, "" when it is) and claims nonce, which must
// not have been claimed before. Nonces of grants that expired are pruned
// first: an expired grant is refused by its window, never by this table.
func (l *SandboxLeases) ClaimFileGrant(ctx context.Context, leaseID, nonce string, expiresAt, now time.Time) (string, error) {
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM sandbox_file_grants WHERE expires_at_ns<=?`, now.UnixNano()); err != nil {
		return "", err
	}
	records, err := sandboxLeasesWhere(ctx, tx, `lease_id=?`, leaseID)
	if err != nil {
		return "", err
	}
	if len(records) == 0 {
		return "", errors.New("sandbox file grant names no lease of this miner")
	}
	record := records[0]
	if code := (SandboxOpLeaseState{Status: record.Status, CleanupStatus: record.CleanupStatus, ExpiresAt: record.LeaseExpiresAt}).RefusalCode(now); code != "" {
		return code, nil
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO sandbox_file_grants(nonce,lease_id,expires_at_ns,claimed_at_ns) VALUES(?,?,?,?) ON CONFLICT(nonce) DO NOTHING`,
		nonce, leaseID, expiresAt.UnixNano(), now.UnixNano())
	if err != nil {
		return "", fmt.Errorf("claim sandbox file grant: %w", err)
	}
	if inserted, err := result.RowsAffected(); err != nil || inserted != 1 {
		return "", ErrFileGrantReplayed
	}
	return "", tx.Commit()
}

// LeaseRefusal is the lease's refusal code at now: "" while it is running
// and unexpired, else why it no longer admits work (or "lease_not_found").
func (l *SandboxLeases) LeaseRefusal(ctx context.Context, leaseID string, now time.Time) (string, error) {
	record, found, err := l.Lease(ctx, leaseID)
	if err != nil {
		return "", err
	}
	if !found {
		return "lease_not_found", nil
	}
	return SandboxOpLeaseState{Status: record.Status, CleanupStatus: record.CleanupStatus, ExpiresAt: record.LeaseExpiresAt}.RefusalCode(now), nil
}
