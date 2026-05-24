// Package service generates and installs native scheduling units that run
// guardian on a timer: launchd agents on macOS, systemd user units on Linux,
// and Scheduled Tasks on Windows, plus a portable cron fallback.
//
// No third-party supervisor libraries are used — only text/template, os/exec
// and runtime from the standard library.
//
// # Design
//
// Unit-file rendering is pure: Render(Config) returns the exact file content
// (or, for Windows, the schtasks invocation) as a string with no filesystem or
// exec side effects, so it can be golden-tested on any host regardless of GOOS.
//
// The concrete Manager is chosen at runtime via New() switching on
// runtime.GOOS — not via build tags — so every platform's rendering logic
// compiles and is testable everywhere. Only the Install/Uninstall/Status steps
// that must shell out are platform-gated by behaviour (they invoke launchctl,
// systemctl, schtasks). All exec calls go through the package-level runCommand
// var, which tests replace with a stub to assert the commands that *would* run.
package service

import (
	"fmt"
	"os/exec"
	"runtime"
)

// Config describes a scheduling unit to install.
//
// Two scheduling shapes are supported:
//
//   - Daemon mode: Args is typically ["run"] and guardian stays resident,
//     scheduling internally. IntervalMinutes is still emitted where the unit
//     itself owns the cadence (launchd StartInterval, schtasks /MO).
//   - Cron mode: Args is typically ["scan","baseline"] and the unit re-launches
//     guardian every IntervalMinutes for a one-shot scan.
type Config struct {
	// Label is the reverse-DNS unit identifier, e.g. "io.guardian.agent".
	// Used as the launchd Label, the systemd unit base name, and the
	// schtasks task name.
	Label string

	// ExecPath is the absolute path to the guardian binary.
	ExecPath string

	// Args are the arguments passed to ExecPath, e.g. ["run"] for daemon mode
	// or ["scan","baseline"] for cron-style repeated one-shot scans.
	Args []string

	// IntervalMinutes is the cadence at which the unit fires. Must be > 0 for
	// interval-based units (launchd StartInterval, systemd timer, schtasks,
	// cron). Ignored by long-running daemon-only units that self-schedule.
	IntervalMinutes int

	// Description is a human-readable label used where the platform supports
	// one (systemd Description). Optional.
	Description string

	// WorkingDir, if set, is the working directory the unit runs in. Optional.
	WorkingDir string

	// EnvVars are extra environment variables set for the unit, in "K=V" form.
	// Optional.
	EnvVars []string

	// UseTimer, when true on systemd, splits scheduling into a companion
	// .timer unit (OnUnitActiveSec) instead of a self-restarting service.
	// Ignored on other platforms.
	UseTimer bool
}

// Manager installs and inspects native scheduling units for one platform.
//
// Render is pure and side-effect free on every platform. Install, Uninstall
// and Status perform filesystem and/or exec side effects appropriate to the
// host OS.
type Manager interface {
	// Install renders the unit, writes it to UnitPath (where applicable), and
	// activates it via the platform scheduler.
	Install(c Config) error

	// Uninstall deactivates and removes the unit identified by label.
	Uninstall(label string) error

	// Status reports whether a unit with the given label is currently
	// installed/loaded.
	Status(label string) (installed bool, err error)

	// UnitPath returns the on-disk path the unit file is written to. For
	// platforms with no file (Windows schtasks) it returns "".
	UnitPath(c Config) string

	// Render returns the exact unit-file content (or scheduler invocation, for
	// Windows) as a string, with no side effects.
	Render(c Config) (string, error)
}

// commandRunner runs an external command and returns its combined output. It
// is the single seam through which all platform managers shell out, so tests
// can stub it to capture the command + args without executing anything.
type commandRunner func(name string, args ...string) ([]byte, error)

// runCommand is the package-level exec seam. Production code runs the real
// binary; tests overwrite this var to record invocations.
var runCommand commandRunner = func(name string, args ...string) ([]byte, error) {
	// #nosec G204 -- single exec seam for platform service managers; name is a
	// fixed init/scheduler binary (launchctl, systemctl, crontab) selected by
	// guardian per-GOOS, and args derive from the local user's own service
	// config for their own machine, never from external/untrusted input.
	return exec.Command(name, args...).CombinedOutput()
}

// New returns the Manager appropriate for the current GOOS. The selection is
// done at runtime (not via build tags) so that every platform's rendering code
// is compiled and reachable on any host.
func New() Manager {
	switch runtime.GOOS {
	case "darwin":
		return &launchdManager{}
	case "linux":
		return &systemdManager{}
	case "windows":
		return &windowsManager{}
	default:
		// Fall back to cron-based management on anything else (BSDs, etc.).
		return &cronManager{}
	}
}

// validate performs the shared sanity checks every renderer relies on.
func (c Config) validate(requireInterval bool) error {
	if c.Label == "" {
		return fmt.Errorf("service: Config.Label is required")
	}
	if c.ExecPath == "" {
		return fmt.Errorf("service: Config.ExecPath is required")
	}
	if requireInterval && c.IntervalMinutes <= 0 {
		return fmt.Errorf("service: Config.IntervalMinutes must be > 0, got %d", c.IntervalMinutes)
	}
	return nil
}
