package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/user/dredge/internal/collector"
	"github.com/user/dredge/internal/output"
	"github.com/user/dredge/internal/stats"
)

var statsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show current Docker resource usage",
	Long:  "Show current Docker resource usage statistics. Read-only — does not modify anything.",
	RunE:  runStats,
}

func runStats(cmd *cobra.Command, _ []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), appCtx.Config.Docker.Timeout)
	defer cancel()

	// [SECURITY] Stats is strictly read-only — no removal methods are called.
	coll := collector.New(appCtx.Docker, appCtx.Logger)
	inventory, err := coll.CollectAll(ctx)
	if err != nil {
		return fmt.Errorf("collecting Docker resources: %w", err)
	}

	s := stats.Calculate(inventory)

	format, _ := cmd.Flags().GetString("format")
	if format == "" {
		format = flagFormat
	}

	switch format {
	case "json":
		if err := output.FormatStatsJSON(s, os.Stdout); err != nil {
			return fmt.Errorf("encoding stats as JSON: %w", err)
		}
	default:
		output.FormatStatsTable(s, os.Stdout)
	}

	return nil
}

func init() {
	statsCmd.Flags().String("format", "", "Output format: table, json (overrides --format global flag)")
}
