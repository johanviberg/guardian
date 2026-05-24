//go:build darwin

package notify

import (
	"fmt"
	"os/exec"
)

// runCmd is the exec hook; overridable in tests. The only production caller
// (sendDesktop) passes the fixed system binary osascript plus the literal -e
// flag; the sole dynamic value is the AppleScript notification text carried as
// a single argv element (not a shell string), so no command injection exists.
var runCmd = func(name string, args ...string) error {
	// #nosec G204 -- name is the fixed osascript binary; args are a literal flag
	// plus a single AppleScript argument, never a shell-interpreted string.
	return exec.Command(name, args...).Run()
}

// lookPath is the tool-discovery hook; overridable in tests.
var lookPath = exec.LookPath

// osascriptBin is the fixed system binary used to post notifications. Keeping
// it a constant ensures the executable is never attacker-influenced; only the
// notification text below is dynamic.
const osascriptBin = "osascript"

// sendDesktop posts a macOS notification via osascript. If osascript is not on
// PATH it is a no-op (returns nil).
func sendDesktop(title, body string) error {
	path, err := lookPath(osascriptBin)
	if err != nil {
		return nil // tool missing: no-op, never hard-fail a scan
	}
	script := fmt.Sprintf("display notification %q with title %q", body, title)
	return runCmd(path, "-e", script)
}
