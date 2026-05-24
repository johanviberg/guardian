//go:build darwin

package notify

import (
	"fmt"
	"os/exec"
)

// runCmd is the exec hook; overridable in tests.
var runCmd = func(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

// lookPath is the tool-discovery hook; overridable in tests.
var lookPath = exec.LookPath

// sendDesktop posts a macOS notification via osascript. If osascript is not on
// PATH it is a no-op (returns nil).
func sendDesktop(title, body string) error {
	path, err := lookPath("osascript")
	if err != nil {
		return nil // tool missing: no-op, never hard-fail a scan
	}
	script := fmt.Sprintf("display notification %q with title %q", body, title)
	return runCmd(path, "-e", script)
}
