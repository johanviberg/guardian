package service

import (
	"strings"
	"testing"
)

// recordedCmd captures a single stubbed exec invocation.
type recordedCmd struct {
	Name  string
	Args  []string
	Stdin string
}

// stubExec replaces both exec seams with recorders and returns a pointer to
// the captured invocations plus a restore func. Each stubbed call returns
// success with empty output unless out is configured.
func stubExec(t *testing.T) (*[]recordedCmd, func()) {
	t.Helper()
	var calls []recordedCmd
	origRun := runCommand
	origStdin := runCommandStdin
	runCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, recordedCmd{Name: name, Args: args})
		return nil, nil
	}
	runCommandStdin = func(stdin, name string, args ...string) ([]byte, error) {
		calls = append(calls, recordedCmd{Name: name, Args: args, Stdin: stdin})
		return nil, nil
	}
	return &calls, func() {
		runCommand = origRun
		runCommandStdin = origStdin
	}
}

func sampleConfig() Config {
	return Config{
		Label:           "io.guardian.agent",
		ExecPath:        "/usr/local/bin/guardian",
		Args:            []string{"scan", "baseline"},
		IntervalMinutes: 15,
	}
}

// ---- launchd ----

func TestLaunchdRender(t *testing.T) {
	m := &launchdManager{}
	out, err := m.Render(sampleConfig())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	checks := []string{
		`<string>io.guardian.agent</string>`,
		`<string>/usr/local/bin/guardian</string>`,
		`<string>scan</string>`,
		`<string>baseline</string>`,
		`<key>StartInterval</key>`,
		`<integer>900</integer>`, // 15 * 60
		`<key>RunAtLoad</key>`,
	}
	for _, c := range checks {
		if !strings.Contains(out, c) {
			t.Errorf("launchd plist missing %q\n---\n%s", c, out)
		}
	}
}

func TestLaunchdRenderEscapesXML(t *testing.T) {
	c := sampleConfig()
	c.Args = []string{"scan", "--root", "a&b<c>"}
	out, err := (&launchdManager{}).Render(c)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "a&amp;b&lt;c&gt;") {
		t.Errorf("expected XML-escaped arg, got:\n%s", out)
	}
}

// ---- systemd ----

func TestSystemdRenderService(t *testing.T) {
	c := sampleConfig()
	c.Args = []string{"run"}
	out, err := (&systemdManager{}).Render(c)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	checks := []string{
		"[Unit]",
		"[Service]",
		"Type=simple",
		"ExecStart=/usr/local/bin/guardian run",
		"Restart=always",
		"RestartSec=900",
		"WantedBy=default.target",
	}
	for _, want := range checks {
		if !strings.Contains(out, want) {
			t.Errorf("systemd .service missing %q\n---\n%s", want, out)
		}
	}
}

func TestSystemdRenderTimer(t *testing.T) {
	c := sampleConfig()
	c.UseTimer = true
	out, err := (&systemdManager{}).Render(c)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	checks := []string{
		"Type=oneshot",
		"OnUnitActiveSec=900",
		"WantedBy=timers.target",
		".timer ----",
	}
	for _, want := range checks {
		if !strings.Contains(out, want) {
			t.Errorf("systemd timer render missing %q\n---\n%s", want, out)
		}
	}
	if strings.Contains(out, "Restart=always") {
		t.Errorf("timer-based service should not self-restart:\n%s", out)
	}
}

func TestSystemdExecStartQuotesSpaces(t *testing.T) {
	c := sampleConfig()
	c.ExecPath = "/opt/my apps/guardian"
	out, err := (&systemdManager{}).Render(c)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "ExecStart='/opt/my apps/guardian' scan baseline") {
		t.Errorf("expected quoted ExecStart, got:\n%s", out)
	}
}

// ---- windows ----

func TestWindowsRender(t *testing.T) {
	c := sampleConfig()
	c.ExecPath = `C:\Program Files\guardian\guardian.exe`
	out, err := (&windowsManager{}).Render(c)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	checks := []string{
		"schtasks",
		"/Create",
		"/SC MINUTE",
		"/MO 15",
		"/TN io.guardian.agent",
		`/TR "`,
		`"C:\Program Files\guardian\guardian.exe" scan baseline`,
		"/F",
	}
	for _, want := range checks {
		if !strings.Contains(out, want) {
			t.Errorf("schtasks command missing %q\n---\n%s", want, out)
		}
	}
}

func TestWindowsInstallExec(t *testing.T) {
	calls, restore := stubExec(t)
	defer restore()

	if err := (&windowsManager{}).Install(sampleConfig()); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if len(*calls) != 1 {
		t.Fatalf("expected 1 exec call, got %d: %+v", len(*calls), *calls)
	}
	got := (*calls)[0]
	if got.Name != "schtasks" {
		t.Errorf("expected schtasks, got %q", got.Name)
	}
	joined := strings.Join(got.Args, " ")
	for _, want := range []string{"/Create", "/MO", "15", "/TN", "io.guardian.agent", "/TR", "/F"} {
		if !strings.Contains(joined, want) {
			t.Errorf("schtasks args missing %q: %v", want, got.Args)
		}
	}
}

func TestWindowsUninstallExec(t *testing.T) {
	calls, restore := stubExec(t)
	defer restore()

	if err := (&windowsManager{}).Uninstall("io.guardian.agent"); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if len(*calls) != 1 || (*calls)[0].Name != "schtasks" {
		t.Fatalf("unexpected calls: %+v", *calls)
	}
	joined := strings.Join((*calls)[0].Args, " ")
	if !strings.Contains(joined, "/Delete") || !strings.Contains(joined, "/F") {
		t.Errorf("expected /Delete /F, got %v", (*calls)[0].Args)
	}
}

// ---- validation ----

func TestRenderValidation(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{"no label", Config{ExecPath: "/x", IntervalMinutes: 5}},
		{"no exec", Config{Label: "l", IntervalMinutes: 5}},
		{"bad interval", Config{Label: "l", ExecPath: "/x", IntervalMinutes: 0}},
	}
	mgrs := map[string]Manager{
		"launchd": &launchdManager{},
		"systemd": &systemdManager{},
		"windows": &windowsManager{},
		"cron":    &cronManager{},
	}
	for _, tt := range tests {
		for mn, m := range mgrs {
			t.Run(tt.name+"/"+mn, func(t *testing.T) {
				if _, err := m.Render(tt.cfg); err == nil {
					t.Errorf("expected error for invalid config")
				}
			})
		}
	}
}
