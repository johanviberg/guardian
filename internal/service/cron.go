package service

import (
	"fmt"
	"strings"
)

// cronMarker bounds the guardian-managed block in the user crontab. The label
// is embedded so multiple guardian units can coexist and be removed
// independently. Lines between the begin/end markers are owned by guardian and
// are replaced wholesale on install and stripped on uninstall.
const (
	cronMarkerBegin = "# >>> guardian managed: %s >>>"
	cronMarkerEnd   = "# <<< guardian managed: %s <<<"
)

// cronManager is the portable fallback used when no native scheduler is
// available (or when the user passes --cron). It edits the user crontab via
// `crontab -l` / `crontab -`.
type cronManager struct{}

// CronLines returns the crontab entries for c, e.g. for a 15-minute baseline
// scan: ["*/15 * * * * /usr/local/bin/guardian scan baseline"].
//
// It is exported and GOOS-independent so the --cron flag can use it on any
// platform that has cron. Returns an error if the interval is invalid.
func CronLines(c Config) ([]string, error) {
	if err := c.validate(true); err != nil {
		return nil, err
	}
	schedule, err := cronSchedule(c.IntervalMinutes)
	if err != nil {
		return nil, err
	}
	parts := append([]string{c.ExecPath}, c.Args...)
	line := schedule + " " + shellJoin(parts)
	return []string{line}, nil
}

// cronSchedule maps an interval in minutes to a 5-field cron expression.
//   - <60 and a divisor of 60      -> "*/N * * * *"
//   - exact multiple of 60 (hours) -> "0 */H * * *"
//   - otherwise                    -> "*/N * * * *" (best effort, minute step)
func cronSchedule(minutes int) (string, error) {
	if minutes <= 0 {
		return "", fmt.Errorf("service: cron interval must be > 0, got %d", minutes)
	}
	switch {
	case minutes < 60:
		return fmt.Sprintf("*/%d * * * *", minutes), nil
	case minutes%60 == 0:
		return fmt.Sprintf("0 */%d * * *", minutes/60), nil
	default:
		return fmt.Sprintf("*/%d * * * *", minutes), nil
	}
}

// Render returns the managed crontab block (markers + lines) for c. This is
// the exact text injected into the user crontab.
func (m *cronManager) Render(c Config) (string, error) {
	lines, err := CronLines(c)
	if err != nil {
		return "", err
	}
	return buildCronBlock(c.Label, lines), nil
}

func buildCronBlock(label string, lines []string) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf(cronMarkerBegin, label))
	b.WriteString("\n")
	for _, l := range lines {
		b.WriteString(l)
		b.WriteString("\n")
	}
	b.WriteString(fmt.Sprintf(cronMarkerEnd, label))
	return b.String()
}

// UnitPath returns "" — cron has no per-unit file; entries live in the user
// crontab.
func (m *cronManager) UnitPath(c Config) string { return "" }

// mergeCrontab returns the new crontab contents after installing the managed
// block for label. Any pre-existing block for the same label is replaced; all
// other content is preserved. It is pure (string-in/string-out) so the
// idempotency logic is unit-testable without touching the real crontab.
func mergeCrontab(existing, label, block string) string {
	cleaned := removeCronBlock(existing, label)
	cleaned = strings.TrimRight(cleaned, "\n")
	if cleaned == "" {
		return block + "\n"
	}
	return cleaned + "\n" + block + "\n"
}

// removeCronBlock returns existing with the guardian-managed block for label
// removed (markers inclusive). Content outside the block is left untouched. It
// is pure so uninstall idempotency is unit-testable.
func removeCronBlock(existing, label string) string {
	begin := fmt.Sprintf(cronMarkerBegin, label)
	end := fmt.Sprintf(cronMarkerEnd, label)

	lines := strings.Split(existing, "\n")
	out := make([]string, 0, len(lines))
	inBlock := false
	for _, l := range lines {
		switch {
		case strings.TrimSpace(l) == begin:
			inBlock = true
			continue
		case strings.TrimSpace(l) == end:
			inBlock = false
			continue
		case inBlock:
			continue
		default:
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// Install writes the managed block into the user crontab, replacing any prior
// block for the same label (idempotent).
func (m *cronManager) Install(c Config) error {
	block, err := m.Render(c)
	if err != nil {
		return err
	}
	existing := readCrontab()
	merged := mergeCrontab(existing, c.Label, block)
	return writeCrontab(merged)
}

// Uninstall strips the managed block for label from the user crontab. Removing
// an absent block is a no-op (idempotent).
func (m *cronManager) Uninstall(label string) error {
	existing := readCrontab()
	cleaned := removeCronBlock(existing, label)
	cleaned = strings.TrimRight(cleaned, "\n")
	if cleaned != "" {
		cleaned += "\n"
	}
	return writeCrontab(cleaned)
}

// Status reports whether a managed block for label exists in the user crontab.
func (m *cronManager) Status(label string) (bool, error) {
	existing := readCrontab()
	begin := fmt.Sprintf(cronMarkerBegin, label)
	for _, l := range strings.Split(existing, "\n") {
		if strings.TrimSpace(l) == begin {
			return true, nil
		}
	}
	return false, nil
}

// readCrontab returns the current user crontab, or "" when none is installed
// (crontab -l exits non-zero with "no crontab for ...").
func readCrontab() string {
	out, err := runCommand("crontab", "-l")
	if err != nil {
		return ""
	}
	return string(out)
}

// writeCrontab replaces the user crontab with content via `crontab -` reading
// from stdin. It goes through the same exec seam so tests can capture it.
func writeCrontab(content string) error {
	if out, err := runCommandStdin(content, "crontab", "-"); err != nil {
		return fmt.Errorf("service: crontab -: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// CronManager returns a Manager backed by the user crontab, regardless of the
// host GOOS. This powers the `--cron` flag.
func CronManager() Manager { return &cronManager{} }
