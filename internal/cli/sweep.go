package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var sweepCmd = &cobra.Command{
	Use:   "sweep",
	Short: "Execute cleanup based on policies",
	RunE: func(cmd *cobra.Command, _ []string) error {
		fmt.Println("Sweep command not yet implemented — coming in PR #5")
		return nil
	},
}
