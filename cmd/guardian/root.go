package main

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

// exitError carries an explicit process exit code from a command up to main,
// which calls os.Exit with it. This implements guardian's 0/1/2 exit scheme:
// cobra's default behavior maps any RunE error to exit 1, which is too coarse
// for the policy gating (0 clean / 1 findings / 2 confirmed-malicious). A
// command that wants a specific code returns an *exitError; main inspects it.
// A plain (non-exitError) error still results in exit 1 via cobra's usual path.
type exitError struct {
	code int
	err  error // optional underlying error to print; may be nil for a clean exit code
}

func (e *exitError) Error() string {
	if e.err != nil {
		return e.err.Error()
	}
	return fmt.Sprintf("exit code %d", e.code)
}

func (e *exitError) Unwrap() error { return e.err }

// withCode returns an exitError carrying the given code and (optionally) an
// error to report. A nil err with a non-zero code is a silent gating exit.
func withCode(code int, err error) *exitError {
	return &exitError{code: code, err: err}
}

// codeFromError extracts the intended process exit code from a command error.
// An *exitError yields its code; any other non-nil error is exit 1; nil is 0.
func codeFromError(err error) int {
	if err == nil {
		return 0
	}
	var ee *exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	return 1
}

// newRootCmd builds the guardian command tree.
func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "guardian",
		Short: "Local-first supply-chain exposure scanner",
		Long: "guardian wraps a vendored Bumblebee scan engine with catalog management,\n" +
			"local scan history, diffing, scheduling, and notifications.\n\n" +
			"Bumblebee answers \"what's on this machine?\"; guardian answers\n" +
			"\"is any of it risky, what changed, and who should know?\"",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(
		newScanCmd(),
		newStatusCmd(),
		newDiffCmd(),
		newCatalogCmd(),
		newRunCmd(),
		newServiceCmd(),
		newSuppressCmd(),
		newDoctorCmd(),
		newVersionCmd(),
	)
	return root
}
