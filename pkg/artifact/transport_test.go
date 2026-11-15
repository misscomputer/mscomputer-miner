// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package artifact

import (
	"testing"
	"time"
)

func TestRetryDelayUsesBoundedEqualJitter(t *testing.T) {
	lower := func(minimum, _ time.Duration) time.Duration { return minimum }
	upper := func(_, maximum time.Duration) time.Duration { return maximum }
	below := func(minimum, _ time.Duration) time.Duration { return minimum - time.Second }
	above := func(_, maximum time.Duration) time.Duration { return maximum + time.Second }

	if got := retryDelay(100*time.Millisecond, 3, "", lower); got != 200*time.Millisecond {
		t.Fatalf("lower equal-jitter delay = %s", got)
	}
	if got := retryDelay(100*time.Millisecond, 3, "", upper); got != 400*time.Millisecond {
		t.Fatalf("upper equal-jitter delay = %s", got)
	}
	if got := retryDelay(100*time.Millisecond, 3, "", below); got != 200*time.Millisecond {
		t.Fatalf("below-bound injected delay = %s", got)
	}
	if got := retryDelay(100*time.Millisecond, 3, "", above); got != 400*time.Millisecond {
		t.Fatalf("above-bound injected delay = %s", got)
	}
	if got := retryDelay(10*time.Second, 1, "", upper); got != maxS3RetryDelay {
		t.Fatalf("oversize base delay = %s", got)
	}

	jitterCalled := false
	jitter := func(_, _ time.Duration) time.Duration {
		jitterCalled = true
		return 0
	}
	if got := retryDelay(time.Millisecond, 1, "2", jitter); got != 2*time.Second || jitterCalled {
		t.Fatalf("Retry-After delay=%s jitterCalled=%t", got, jitterCalled)
	}
	if got := retryDelay(time.Millisecond, 1, "999", jitter); got != maxS3RetryDelay || jitterCalled {
		t.Fatalf("capped Retry-After delay=%s jitterCalled=%t", got, jitterCalled)
	}
	if got := retryDelay(time.Millisecond, 1, "9223372036854775807", jitter); got != maxS3RetryDelay || jitterCalled {
		t.Fatalf("overflow-safe Retry-After delay=%s jitterCalled=%t", got, jitterCalled)
	}
}
