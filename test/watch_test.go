package test

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/user/dredge/internal/watcher"
)

// TestWatchExecutesCycleOnTick verifies the daemon executes the cycle on startup
// and again on each ticker interval.
func TestWatchExecutesCycleOnTick(t *testing.T) {
	var count int64

	cycleFn := func(_ context.Context) watcher.CycleResult {
		atomic.AddInt64(&count, 1)
		return watcher.CycleResult{Empty: true}
	}

	w := watcher.New(cycleFn, 10*time.Millisecond, newSweeperLogger())
	sigChan := make(chan os.Signal, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()

	err := w.Run(ctx, sigChan)
	assert.True(t, err == nil || errors.Is(err, context.DeadlineExceeded),
		"expected nil or DeadlineExceeded, got: %v", err)
	assert.GreaterOrEqual(t, atomic.LoadInt64(&count), int64(2),
		"should have run at least 2 cycles in 60ms with 10ms interval")
}

// TestWatchHandlesSignalGracefully verifies SIGTERM causes a clean shutdown
// with a nil error return.
func TestWatchHandlesSignalGracefully(t *testing.T) {
	cycleFn := func(_ context.Context) watcher.CycleResult {
		return watcher.CycleResult{Empty: true}
	}

	w := watcher.New(cycleFn, 500*time.Millisecond, newSweeperLogger())
	sigChan := make(chan os.Signal, 1)

	go func() {
		time.Sleep(20 * time.Millisecond)
		sigChan <- os.Interrupt
	}()

	err := w.Run(context.Background(), sigChan)
	assert.NoError(t, err, "signal must cause clean shutdown with nil error")
}

// TestWatchSIGTERMDuringSlowCyclePropagatesCancellation verifies that sending
// SIGTERM via sigChan while a slow cycle is running propagates context
// cancellation to the running cycle so it can exit early.
//
// This test uses context.Background() (the production path in watch.go) — NOT
// a pre-cancelled context — to reproduce the real scenario: the watcher must
// internally cancel the cycle context when it receives a signal, not just wait.
func TestWatchSIGTERMDuringSlowCyclePropagatesCancellation(t *testing.T) {
	// Cycle sleeps 500ms but exits early if its context is cancelled.
	cycleFn := func(ctx context.Context) watcher.CycleResult {
		select {
		case <-time.After(500 * time.Millisecond):
		case <-ctx.Done():
		}
		return watcher.CycleResult{Empty: true}
	}

	// Use context.Background() — this is what watch.go passes in production.
	// The watcher must cancel the cycle via its own mechanism, not rely on
	// the caller to cancel.
	w := watcher.New(cycleFn, 10*time.Second, newSweeperLogger())
	sigChan := make(chan os.Signal, 1)

	done := make(chan error, 1)
	go func() {
		done <- w.Run(context.Background(), sigChan)
	}()

	// Let the first cycle start, then send signal.
	time.Sleep(20 * time.Millisecond)
	sigChan <- os.Interrupt

	start := time.Now()
	select {
	case <-done:
		elapsed := time.Since(start)
		assert.Less(t, elapsed, 200*time.Millisecond,
			"Run must return within 200ms after signal — cycle must be cancelled, not awaited for 500ms")
	case <-time.After(600 * time.Millisecond):
		t.Fatal("Run blocked for 600ms after SIGTERM — signal did not propagate to running cycle")
	}
}

// TestWatchSkipsOverlappingCycles verifies a slow cycle prevents concurrent
// execution — the daemon must never run two cycles in parallel.
// [SECURITY] Prevent overlapping executions — race conditions against Docker state.
func TestWatchSkipsOverlappingCycles(t *testing.T) {
	var concurrent int64
	var maxConcurrent int64

	cycleFn := func(_ context.Context) watcher.CycleResult {
		current := atomic.AddInt64(&concurrent, 1)
		for {
			old := atomic.LoadInt64(&maxConcurrent)
			if current <= old {
				break
			}
			if atomic.CompareAndSwapInt64(&maxConcurrent, old, current) {
				break
			}
		}
		time.Sleep(80 * time.Millisecond)
		atomic.AddInt64(&concurrent, -1)
		return watcher.CycleResult{Empty: true}
	}

	w := watcher.New(cycleFn, 10*time.Millisecond, newSweeperLogger())
	sigChan := make(chan os.Signal, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	w.Run(ctx, sigChan) //nolint:errcheck

	assert.Equal(t, int64(1), atomic.LoadInt64(&maxConcurrent),
		"concurrent cycles must never exceed 1")
}
