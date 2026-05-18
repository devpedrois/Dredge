package cli

import "fmt"

// CheckSweepConfirmation returns an error when a non-interactive sweep is
// attempted without the --yes flag.
// Pure function — accepts isTTY as a parameter so tests can simulate any environment.
// [SECURITY] Non-interactive sweep without --yes must fail — prevents accidental piped execution.
func CheckSweepConfirmation(yes bool, isTTY bool) error {
	if !yes && !isTTY {
		return fmt.Errorf("sweep requires --yes flag for non-interactive execution")
	}
	return nil
}
