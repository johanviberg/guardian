package service

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
)

// launchdManager installs a per-user LaunchAgent on macOS.
type launchdManager struct{}

// launchdTmpl renders a launchd property list. StartInterval gives cron-style
// repetition (seconds); RunAtLoad fires once on load so the first scan does not
// wait a full interval.
var launchdTmpl = template.Must(template.New("plist").Funcs(template.FuncMap{
	"xml": xmlEscape,
}).Parse(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{{xml .Label}}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{{xml .ExecPath}}</string>
{{- range .Args}}
		<string>{{xml .}}</string>
{{- end}}
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>StartInterval</key>
	<integer>{{.IntervalSeconds}}</integer>
{{- if .WorkingDir}}
	<key>WorkingDirectory</key>
	<string>{{xml .WorkingDir}}</string>
{{- end}}
{{- if .EnvVars}}
	<key>EnvironmentVariables</key>
	<dict>
{{- range .EnvVars}}
		<key>{{xml .Key}}</key>
		<string>{{xml .Value}}</string>
{{- end}}
	</dict>
{{- end}}
	<key>StandardOutPath</key>
	<string>{{xml .LogOut}}</string>
	<key>StandardErrorPath</key>
	<string>{{xml .LogErr}}</string>
	<key>ProcessType</key>
	<string>Background</string>
</dict>
</plist>
`))

type launchdData struct {
	Label           string
	ExecPath        string
	Args            []string
	IntervalSeconds int
	WorkingDir      string
	EnvVars         []kv
	LogOut          string
	LogErr          string
}

type kv struct {
	Key   string
	Value string
}

func (m *launchdManager) Render(c Config) (string, error) {
	if err := c.validate(true); err != nil {
		return "", err
	}
	data := launchdData{
		Label:           c.Label,
		ExecPath:        c.ExecPath,
		Args:            c.Args,
		IntervalSeconds: c.IntervalMinutes * 60,
		WorkingDir:      c.WorkingDir,
		EnvVars:         splitEnv(c.EnvVars),
		LogOut:          fmt.Sprintf("/tmp/%s.out.log", c.Label),
		LogErr:          fmt.Sprintf("/tmp/%s.err.log", c.Label),
	}
	var buf bytes.Buffer
	if err := launchdTmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("service: render launchd plist: %w", err)
	}
	return buf.String(), nil
}

func (m *launchdManager) UnitPath(c Config) string {
	return launchdPlistPath(c.Label)
}

func launchdPlistPath(label string) string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", label+".plist")
}

func (m *launchdManager) Install(c Config) error {
	content, err := m.Render(c)
	if err != nil {
		return err
	}
	path := m.UnitPath(c)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("service: create LaunchAgents dir: %w", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("service: write plist: %w", err)
	}
	domain := guiDomain()
	// Replace any existing instance, then bootstrap the new one.
	_, _ = runCommand("launchctl", "bootout", domain+"/"+c.Label)
	if out, err := runCommand("launchctl", "bootstrap", domain, path); err != nil {
		return fmt.Errorf("service: launchctl bootstrap: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *launchdManager) Uninstall(label string) error {
	domain := guiDomain()
	if out, err := runCommand("launchctl", "bootout", domain+"/"+label); err != nil {
		// bootout failing because it was not loaded is not fatal; still remove
		// the file below.
		_ = out
	}
	path := launchdPlistPath(label)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("service: remove plist: %w", err)
	}
	return nil
}

func (m *launchdManager) Status(label string) (bool, error) {
	domain := guiDomain()
	out, err := runCommand("launchctl", "print", domain+"/"+label)
	if err != nil {
		// print returns non-zero when the service is not loaded.
		return false, nil
	}
	return len(bytes.TrimSpace(out)) > 0, nil
}

func guiDomain() string {
	return "gui/" + strconv.Itoa(os.Getuid())
}
