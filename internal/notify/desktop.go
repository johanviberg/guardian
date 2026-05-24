package notify

import "context"

// sendDesktopFn is the platform-specific desktop delivery function. It is a
// package var (not a direct reference to sendDesktop) so tests can stub it
// without invoking real OS notification tooling.
var sendDesktopFn = sendDesktop

// DesktopNotifier shows a native desktop notification. The actual delivery is
// platform-specific (see desktop_darwin.go, desktop_linux.go,
// desktop_windows.go, desktop_other.go), selected at build time via build tags.
//
// If the underlying OS tool is unavailable (exec.LookPath fails), delivery is a
// no-op returning nil: a scan must never hard-fail over a missing notifier.
type DesktopNotifier struct{}

// NewDesktopNotifier returns a DesktopNotifier.
func NewDesktopNotifier() *DesktopNotifier { return &DesktopNotifier{} }

// Name implements Notifier.
func (d *DesktopNotifier) Name() string { return "desktop" }

// Notify implements Notifier by handing off to the platform sender. The context
// is accepted for interface symmetry; the OS tools are fast, fire-and-forget.
func (d *DesktopNotifier) Notify(_ context.Context, n Notification) error {
	return sendDesktopFn(n.Title, n.Body)
}
