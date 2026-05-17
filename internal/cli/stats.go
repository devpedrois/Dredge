package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var statsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show current Docker resource usage",
	RunE: func(cmd *cobra.Command, _ []string) error {
		fmt.Println("Stats command not yet implemented — coming in PR #6")
		return nil
	},
}
