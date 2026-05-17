package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Run as daemon, cleaning at intervals",
	RunE: func(cmd *cobra.Command, _ []string) error {
		fmt.Println("Watch command not yet implemented — coming in PR #6")
		return nil
	},
}
