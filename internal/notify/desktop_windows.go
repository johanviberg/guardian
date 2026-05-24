//go:build windows

package notify

import (
	"fmt"
	"os/exec"
	"strings"
)

// runCmd is the exec hook; overridable in tests.
var runCmd = func(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

// lookPath is the tool-discovery hook; overridable in tests.
var lookPath = exec.LookPath

// psEscape single-quotes a string for safe embedding in a PowerShell literal.
func psEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// sendDesktop posts a Windows toast via PowerShell using the WinRT toast APIs.
// If powershell is not on PATH it is a no-op (returns nil).
func sendDesktop(title, body string) error {
	path, err := lookPath("powershell")
	if err != nil {
		return nil // tool missing: no-op, never hard-fail a scan
	}
	script := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$texts = $template.GetElementsByTagName('text')
$texts.Item(0).AppendChild($template.CreateTextNode(%s)) | Out-Null
$texts.Item(1).AppendChild($template.CreateTextNode(%s)) | Out-Null
$toast = [Windows.UI.Notifications.ToastNotification]::new($template)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('guardian').Show($toast)
`, psEscape(title), psEscape(body))
	return runCmd(path, "-NoProfile", "-NonInteractive", "-Command", script)
}
