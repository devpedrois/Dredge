package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/user/dredge/internal/collector"
	"github.com/user/dredge/internal/output"
	"github.com/user/dredge/internal/planner"
	"github.com/user/dredge/internal/policy"
)

var planCmd = &cobra.Command{
	Use:   "plan",
	Short: "Show what would be removed (dry-run)",
	Long:  "Evaluate policies and show exactly which resources would be deleted, why, and how much space would be recovered. Does not modify anything.",
	RunE:  runPlan,
}

func runPlan(cmd *cobra.Command, _ []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), appCtx.Config.Docker.Timeout)
	defer cancel()

	coll := collector.New(appCtx.Docker, appCtx.Logger)

	inventory, err := coll.CollectAll(ctx)
	if err != nil {
		return fmt.Errorf("collecting Docker resources: %w", err)
	}

	engine := policy.New(appCtx.Config, appCtx.Logger)
	decisions := engine.Evaluate(inventory)

	p := planner.New(appCtx.Logger)
	plan := p.CreatePlan(decisions)

	plan.Timestamp = time.Now()

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

	// [SECURITY] Exit code 1 for pending deletions — enables scripting:
	// `dredge plan || dredge sweep --yes`
	if len(plan.Deletions) > 0 {
		os.Exit(1)
	}

	return nil
}

func init() {
	planCmd.Flags().String("format", "", "Output format: table, json (overrides --format global flag)")
}
