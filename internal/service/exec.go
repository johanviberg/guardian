package service

import (
	"os/exec"
	"strings"
)

// stdinRunner runs a command, piping stdin into it, returning combined output.
// It is the exec seam used for `crontab -`, which reads the new crontab from
// stdin. Tests replace it to capture both the stdin payload and the argv.
type stdinRunner func(stdin string, name string, args ...string) ([]byte, error)

// runCommandStdin is the package-level seam for stdin-fed commands.
var runCommandStdin stdinRunner = func(stdin string, name string, args ...string) ([]byte, error) {
	// #nosec G204 -- generic exec seam for service managers; name is a fixed
	// scheduler binary (e.g. crontab) chosen by guardian, and args are built
	// from the local user's own service config, not from untrusted input.
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	return cmd.CombinedOutput()
}
