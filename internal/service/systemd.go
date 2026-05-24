package service

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

// systemdManager installs a systemd *user* unit on Linux. With UseTimer it
// emits a oneshot service plus a companion .timer; otherwise it emits a
// self-restarting service whose RestartSec equals the interval.
type systemdManager struct{}

// serviceTmpl renders a .service unit. ExecStart is the binary plus args,
// shell-quoted so paths/args containing spaces survive.
var serviceTmpl = template.Must(template.New("service").Parse(`[Unit]
Description={{.Description}}
After=network-online.target
Wants=network-online.target

[Service]
Type={{.Type}}
ExecStart={{.ExecStart}}
{{- if .WorkingDir}}
WorkingDirectory={{.WorkingDir}}
{{- end}}
{{- range .EnvVars}}
Environment={{.}}
{{- end}}
{{- if .Restart}}
Restart=always
RestartSec={{.RestartSec}}
{{- end}}

[Install]
WantedBy=default.target
`))

// timerTmpl renders the companion .timer unit used when Config.UseTimer is set.
var timerTmpl = template.Must(template.New("timer").Parse(`[Unit]
Description={{.Description}} timer

[Timer]
OnBootSec={{.IntervalSec}}
OnUnitActiveSec={{.IntervalSec}}
Persistent=true

[Install]
WantedBy=timers.target
`))

type serviceData struct {
	Description string
	Type        string
	ExecStart   string
	WorkingDir  string
	EnvVars     []string
	Restart     bool
	RestartSec  int
}

type timerData struct {
	Description string
	IntervalSec int
}

func (m *systemdManager) description(c Config) string {
	if c.Description != "" {
		return c.Description
	}
	return "Guardian agent (" + c.Label + ")"
}

func (m *systemdManager) renderService(c Config) (string, error) {
	data := serviceData{
		Description: m.description(c),
		ExecStart:   shellJoin(append([]string{c.ExecPath}, c.Args...)),
		WorkingDir:  c.WorkingDir,
		EnvVars:     c.EnvVars,
	}
	if c.UseTimer {
		data.Type = "oneshot"
	} else {
		data.Type = "simple"
		data.Restart = true
		data.RestartSec = c.IntervalMinutes * 60
	}
	var buf bytes.Buffer
	if err := serviceTmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("service: render systemd .service: %w", err)
	}
	return buf.String(), nil
}

func (m *systemdManager) renderTimer(c Config) (string, error) {
	var buf bytes.Buffer
	if err := timerTmpl.Execute(&buf, timerData{
		Description: m.description(c),
		IntervalSec: c.IntervalMinutes * 60,
	}); err != nil {
		return "", fmt.Errorf("service: render systemd .timer: %w", err)
	}
	return buf.String(), nil
}

// Render returns the .service content. When UseTimer is set, the .timer
// content is appended after a separator comment so the single string still
// captures everything that would be written (and remains golden-testable).
func (m *systemdManager) Render(c Config) (string, error) {
	if err := c.validate(true); err != nil {
		return "", err
	}
	svc, err := m.renderService(c)
	if err != nil {
		return "", err
	}
	if !c.UseTimer {
		return svc, nil
	}
	timer, err := m.renderTimer(c)
	if err != nil {
		return "", err
	}
	return svc + "\n# ---- " + c.Label + ".timer ----\n" + timer, nil
}

func systemdUserDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "systemd", "user")
}

func (m *systemdManager) UnitPath(c Config) string {
	return filepath.Join(systemdUserDir(), c.Label+".service")
}

func (m *systemdManager) timerPath(c Config) string {
	return filepath.Join(systemdUserDir(), c.Label+".timer")
}

func (m *systemdManager) Install(c Config) error {
	if err := c.validate(true); err != nil {
		return err
	}
	dir := systemdUserDir()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("service: create systemd user dir: %w", err)
	}
	svc, err := m.renderService(c)
	if err != nil {
		return err
	}
	if err := os.WriteFile(m.UnitPath(c), []byte(svc), 0o600); err != nil {
		return fmt.Errorf("service: write .service: %w", err)
	}

	unitToEnable := c.Label + ".service"
	if c.UseTimer {
		timer, err := m.renderTimer(c)
		if err != nil {
			return err
		}
		if err := os.WriteFile(m.timerPath(c), []byte(timer), 0o600); err != nil {
			return fmt.Errorf("service: write .timer: %w", err)
		}
		unitToEnable = c.Label + ".timer"
	}

	if out, err := runCommand("systemctl", "--user", "daemon-reload"); err != nil {
		return fmt.Errorf("service: systemctl daemon-reload: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := runCommand("systemctl", "--user", "enable", "--now", unitToEnable); err != nil {
		return fmt.Errorf("service: systemctl enable --now: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *systemdManager) Uninstall(label string) error {
	// Try disabling both possible units; ignore "not loaded" errors.
	_, _ = runCommand("systemctl", "--user", "disable", "--now", label+".timer")
	_, _ = runCommand("systemctl", "--user", "disable", "--now", label+".service")

	dir := systemdUserDir()
	for _, suffix := range []string{".service", ".timer"} {
		if err := os.Remove(filepath.Join(dir, label+suffix)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("service: remove %s%s: %w", label, suffix, err)
		}
	}
	if out, err := runCommand("systemctl", "--user", "daemon-reload"); err != nil {
		return fmt.Errorf("service: systemctl daemon-reload: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *systemdManager) Status(label string) (bool, error) {
	// is-enabled exits non-zero when the unit is absent/disabled. Check the
	// timer first (preferred when present), then the service.
	for _, unit := range []string{label + ".timer", label + ".service"} {
		out, err := runCommand("systemctl", "--user", "is-enabled", unit)
		state := strings.TrimSpace(string(out))
		if err == nil && (state == "enabled" || state == "static") {
			return true, nil
		}
	}
	return false, nil
}
