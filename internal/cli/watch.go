package cli

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/user/dredge/internal/collector"
	"github.com/user/dredge/internal/planner"
	"github.com/user/dredge/internal/policy"
	"github.com/user/dredge/internal/sweeper"
	"github.com/user/dredge/internal/watcher"
)

var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Run as daemon, cleaning at intervals",
	Long:  "Run as a daemon, executing plan+sweep automatically at the configured interval. SIGTERM/SIGINT causes graceful shutdown.",
	RunE:  runWatch,
}

func runWatch(cmd *cobra.Command, _ []string) error {
	interval := appCtx.Config.Watch.Interval
	if override, _ := cmd.Flags().GetDuration("interval"); override > 0 {
		interval = override
	}

	// [SECURITY] Signal handling — SIGTERM and SIGINT trigger graceful shutdown
	// that waits for the current cycle to complete before stopping.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigChan)

	w := watcher.New(buildCycleFn(), interval, appCtx.Logger)
	return w.Run(context.Background(), sigChan)
}

// buildCycleFn returns the CycleFunc used by the daemon.
// Extracted so it can be replaced in tests without a live Docker daemon.
func buildCycleFn() watcher.CycleFunc {
	return func(ctx context.Context) watcher.CycleResult {
		// [SECURITY] Separate contexts: collectCtx bounds Docker list operations;
		// ctx (from the watcher loop) governs sweep execution so that signal-triggered
		// context cancellation aborts in-progress deletions quickly on graceful shutdown.
		collectCtx, collectCancel := context.WithTimeout(ctx, appCtx.Config.Docker.Timeout)
		defer collectCancel()

		coll := collector.New(appCtx.Docker, appCtx.Logger)
		inventory, err := coll.CollectAll(collectCtx)
		if err != nil {
			appCtx.Logger.Error("cycle: failed to collect resources", "error", err)
			return watcher.CycleResult{}
		}

		engine := policy.New(appCtx.Config, appCtx.Logger)
		decisions := engine.Evaluate(inventory)

		p := planner.New(appCtx.Logger, appCtx.Config.Protection.Label)
		plan := p.CreatePlan(decisions)
		plan.Timestamp = time.Now()

		if len(plan.Deletions) == 0 {
			return watcher.CycleResult{Empty: true}
		}

		sw := sweeper.New(appCtx.Docker, appCtx.Logger, appCtx.Config.Protection.Label)
		result := sw.Execute(ctx, plan)

		var recovered int64
		for _, d := range result.Succeeded {
			recovered += d.Resource.Size
		}

		return watcher.CycleResult{
			Deleted: len(result.Succeeded),
			Failed:  len(result.Failed),
			Size:    recovered,
		}
	}
}

func init() {
	watchCmd.Flags().Duration("interval", 0, "Override config watch interval (e.g. 6h, 30m)")
}
