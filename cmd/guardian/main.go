// Command guardian is the guardian CLI: a single binary wrapping a vendored
// Bumblebee scan engine with catalog management, scan history, diffing,
// scheduling, and notifications.
package main

import (
	"fmt"
	"os"
)

func main() {
	root := newRootCmd()
	err := root.Execute()
	if err != nil {
		// Print the error unless it is a silent gating exit (an *exitError with
		// no wrapped error, e.g. policy exit code 1/2 on a successful scan).
		if msg := err.Error(); msg != "" {
			if ee, ok := err.(*exitError); !ok || ee.err != nil {
				fmt.Fprintln(os.Stderr, "guardian:", msg)
			}
		}
	}
	os.Exit(codeFromError(err))
}
