//go:build !darwin && !linux && !windows

package notify

// sendDesktop is a no-op on platforms without a supported desktop notifier.
func sendDesktop(title, body string) error { return nil }
