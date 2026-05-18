package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/user/dredge/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		// ErrPendingDeletions means the plan ran successfully but found resources
		// to delete. Exit 1 signals "pending work" without printing an error line —
		// the plan output already informed the user.
		if errors.Is(err, cli.ErrPendingDeletions) {
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
