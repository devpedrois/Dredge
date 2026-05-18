package watcher

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// CycleResult summarises the outcome of one watch cycle.
type CycleResult struct {
	Deleted int
	Failed  int
	Size    int64
	Empty   bool
}

// CycleFunc is the function the Watcher calls on each tick.
type CycleFunc func(ctx context.Context) CycleResult

// Watcher runs a CycleFunc on a fixed interval, skipping overlapping executions.
type Watcher struct {
	cycleFn  CycleFunc
	interval time.Duration
	logger   *slog.Logger
	// [SECURITY] Prevent overlapping executions — concurrent cycles could race
	// against Docker state, causing double-deletion or missed protections.
	running atomic.Int32
	wg      sync.WaitGroup
}

// New constructs a Watcher with the given cycle function and interval.
func New(cycleFn CycleFunc, interval time.Duration, logger *slog.Logger) *Watcher {
	return &Watcher{
		cycleFn:  cycleFn,
		interval: interval,
		logger:   logger,
	}
}

// Run starts the watch loop: executes one cycle immediately, then repeats every
// interval. Returns nil on signal receipt, ctx.Err() when the context is done.
// On shutdown, waits for any in-progress cycle to complete before returning.
func (w *Watcher) Run(ctx context.Context, sigChan <-chan os.Signal) error {
	w.logger.Info("starting dredge watch daemon", "interval", w.interval)

	w.launchCycle(ctx)

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			w.launchCycle(ctx)
		case sig := <-sigChan:
			w.logger.Info("received signal, shutting down gracefully", "signal", sig)
			w.wg.Wait()
			return nil
		case <-ctx.Done():
			w.logger.Info("context cancelled, stopping watch daemon")
			w.wg.Wait()
			return ctx.Err()
		}
	}
}

// launchCycle starts a cycle in a goroutine if no cycle is already running.
// [SECURITY] CAS prevents concurrent cycles — running two sweeps simultaneously
// could delete a resource that a concurrent policy pass marked as protected.
func (w *Watcher) launchCycle(ctx context.Context) {
	if !w.running.CompareAndSwap(0, 1) {
		w.logger.Warn("previous cycle still running, skipping")
		return
	}
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		defer w.running.Store(0)

		result := w.cycleFn(ctx)

		if result.Empty {
			w.logger.Info("cycle complete: nothing to clean")
			return
		}
		w.logger.Info("cycle complete",
			"deleted", result.Deleted,
			"failed", result.Failed,
			"size_bytes", result.Size,
		)
	}()
}
