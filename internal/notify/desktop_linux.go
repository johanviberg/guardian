//go:build linux

package notify

import "os/exec"

// runCmd is the exec hook; overridable in tests.
var runCmd = func(name string, args ...string) error {
	return exec.Command(name, args...).Run()
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
