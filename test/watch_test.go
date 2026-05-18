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
