//go:build linux

package notify

import "os/exec"

// runCmd is the exec hook; overridable in tests.
var runCmd = func(name string, args ...string) error {
	// G204: callers pass a fixed tool name ("notify-send") resolved via
	// lookPath; args are notification title/body, not shell-interpreted.
	return exec.Command(name, args...).Run() // #nosec G204 -- fixed binary, no shell
}

// lookPath is the tool-discovery hook; overridable in tests.
var lookPath = exec.LookPath

// sendDesktop posts a Linux notification via notify-send. If notify-send is not
// on PATH it is a no-op (returns nil).
func sendDesktop(title, body string) error {
	path, err := lookPath("notify-send")
	if err != nil {
		return nil // tool missing: no-op, never hard-fail a scan
	}
	return runCmd(path, title, body)
}
