package service

import (
	"fmt"
	"strings"
)

// windowsManager registers a Scheduled Task via schtasks. This is simpler and
// less privileged than registering a Windows Service.
type windowsManager struct{}

// schtasksCreateArgs builds the argument vector for `schtasks /Create`. It is
// shared by Render (for display/golden tests) and Install (for exec) so the
// command that runs and the command that is shown are guaranteed identical.
func schtasksCreateArgs(c Config) []string {
	return []string{
		"/Create",
		"/SC", "MINUTE",
		"/MO", fmt.Sprintf("%d", c.IntervalMinutes),
		"/TN", c.Label,
		"/TR", schtasksRunString(c),
		"/F", // overwrite an existing task with the same name
	}
}

// schtasksRunString is the /TR value: the quoted executable followed by args.
func schtasksRunString(c Config) string {
	parts := make([]string, 0, len(c.Args)+1)
	parts = append(parts, quoteWindows(c.ExecPath))
	for _, a := range c.Args {
		parts = append(parts, quoteWindows(a))
	}
	return strings.Join(parts, " ")
}

// Render returns the full schtasks command line that would be executed. There
// is no on-disk unit file for a Scheduled Task, so the rendered "unit" is the
// command itself.
func (m *windowsManager) Render(c Config) (string, error) {
	if err := c.validate(true); err != nil {
		return "", err
	}
	parts := append([]string{"schtasks"}, schtasksCreateArgs(c)...)
	// Quote the /TR payload as a single argument for readability.
	for i, p := range parts {
		if i > 0 && parts[i-1] == "/TR" {
			parts[i] = `"` + p + `"`
		}
	}
	return strings.Join(parts, " "), nil
}

// UnitPath returns "" because schtasks manages the task in the Task Scheduler
// store, not on the filesystem.
func (m *windowsManager) UnitPath(c Config) string {
	return ""
}

func (m *windowsManager) Install(c Config) error {
	if err := c.validate(true); err != nil {
		return err
	}
	if out, err := runCommand("schtasks", schtasksCreateArgs(c)...); err != nil {
		return fmt.Errorf("service: schtasks /Create: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *windowsManager) Uninstall(label string) error {
	if out, err := runCommand("schtasks", "/Delete", "/TN", label, "/F"); err != nil {
		return fmt.Errorf("service: schtasks /Delete: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *windowsManager) Status(label string) (bool, error) {
	out, err := runCommand("schtasks", "/Query", "/TN", label)
	if err != nil {
		// /Query exits non-zero when the task does not exist.
		return false, nil
	}
	return strings.Contains(string(out), label), nil
}
