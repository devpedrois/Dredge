package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/moby/term"
	"github.com/spf13/cobra"
	"github.com/user/dredge/internal/collector"
	"github.com/user/dredge/internal/output"
	"github.com/user/dredge/internal/planner"
	"github.com/user/dredge/internal/policy"
	"github.com/user/dredge/internal/sweeper"
)

var sweepCmd = &cobra.Command{
	Use:   "sweep",
	Short: "Execute cleanup based on policies",
	Long:  "Evaluate policies and delete matching resources. Requires --yes or interactive confirmation.",
	RunE:  runSweep,
}

func runSweep(cmd *cobra.Command, _ []string) error {
	yes, _ := cmd.Flags().GetBool("yes")

	// [SECURITY] Separate contexts for collection and execution:
	// - collectCtx: bounded timeout for Docker list operations.
	// - sweepCtx: unbounded at CLI level; each Docker call inside the sweeper
	//   adds its own per-operation timeout via the Docker client wrapper.
	// Using a single shared context caused sweep to inherit the collection's
	// expiry, making all deletions fail silently after interactive confirmation.
	collectCtx, collectCancel := context.WithTimeout(context.Background(), appCtx.Config.Docker.Timeout)
	defer collectCancel()

	// [SECURITY] Sweep uses same evaluate+plan code as plan command — dry-run parity guaranteed.
	coll := collector.New(appCtx.Docker, appCtx.Logger)
	inventory, err := coll.CollectAll(collectCtx)
	if err != nil {
		return fmt.Errorf("collecting Docker resources: %w", err)
	}

	engine := policy.New(appCtx.Config, appCtx.Logger)
	decisions := engine.Evaluate(inventory)

	p := planner.New(appCtx.Logger, appCtx.Config.Protection.Label)
	plan := p.CreatePlan(decisions)

	if len(plan.Deletions) == 0 {
		fmt.Fprintln(os.Stdout, "Nothing to clean. Your Docker is tidy!")
		return nil
	}

	format, _ := cmd.Flags().GetString("format")
	if format == "" {
		format = flagFormat
	}

	switch format {
	case "json":
		if err := output.FormatPlanJSON(plan, os.Stdout); err != nil {
			return fmt.Errorf("encoding plan as JSON: %w", err)
		}
	default:
		output.FormatPlanTable(plan, os.Stdout)
	}

	if !yes {
		// [SECURITY] Non-interactive sweep without --yes is an error — prevents accidental piped execution.
		if err := CheckSweepConfirmation(yes, term.IsTerminal(os.Stdin.Fd())); err != nil {
			return err
		}

		fmt.Fprintf(os.Stdout, "\nAbout to delete %d resources (%s). Continue? [y/N]: ",
			len(plan.Deletions),
			humanize.Bytes(uint64(plan.TotalSize)),
		)

		reader := bufio.NewReader(os.Stdin)
		answer, readErr := reader.ReadString('\n')
		if readErr != nil {
			return fmt.Errorf("reading confirmation: %w", readErr)
		}
		if answer = strings.TrimSpace(answer); answer != "y" && answer != "Y" {
			fmt.Fprintln(os.Stdout, "Sweep cancelled.")
			return nil
		}
	}

	// Bound total sweep time: each resource needs at most 2 Docker calls (verify + delete),
	// each capped at docker.Timeout. A floor of 5 minutes prevents premature cancellation
	// on small plans. cmd.Context() propagates SIGTERM/SIGINT cancellation.
	sweepTimeout := time.Duration(len(plan.Deletions)) * 2 * appCtx.Config.Docker.Timeout
	if sweepTimeout < 5*time.Minute {
		sweepTimeout = 5 * time.Minute
	}
	sweepCtx, sweepCancel := context.WithTimeout(cmd.Context(), sweepTimeout)
	defer sweepCancel()

	sw := sweeper.New(appCtx.Docker, appCtx.Logger, appCtx.Config.Protection.Label)
	result := sw.Execute(sweepCtx, plan)

	var recovered int64
	for _, d := range result.Succeeded {
		recovered += d.Resource.Size
	}

	fmt.Fprintf(os.Stdout, "\nSweep complete: %d deleted, %d failed, %s recovered (took %s)\n",
		len(result.Succeeded),
		len(result.Failed),
		humanize.Bytes(uint64(recovered)),
		result.Duration.Round(time.Millisecond),
	)

	if len(result.Failed) > 0 {
		fmt.Fprintln(os.Stdout, "\nFailed deletions:")
		for _, f := range result.Failed {
			fmt.Fprintf(os.Stdout, "  - %s %s (%s): %s\n",
				f.Deletion.Resource.Type,
				f.Deletion.Resource.Name,
				f.Deletion.Resource.ID,
				f.Error,
			)
		}
	}

	return nil
}

func init() {
	sweepCmd.Flags().Bool("yes", false, "Skip confirmation prompt")
	sweepCmd.Flags().String("format", "", "Output format: table, json (overrides --format global flag)")
}
