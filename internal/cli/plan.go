package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var planCmd = &cobra.Command{
	Use:   "plan",
	Short: "Show what would be removed (dry-run)",
	RunE: func(cmd *cobra.Command, _ []string) error {
		fmt.Println("Plan command not yet implemented — coming in PR #4")
		return nil
	},
}
