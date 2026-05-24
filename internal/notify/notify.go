// Package notify delivers guardian scan alerts to one or more output channels
// (terminal, desktop, webhook/Slack) behind a single Notifier interface.
//
// A Dispatcher fans a Notification out to every enabled Notifier, aggregating
// per-channel failures with errors.Join so that one broken channel never stops
// the others — a scan must never hard-fail because a notification could not be
// delivered. Gating (severity threshold + quiet hours) decides whether anything
// is sent at all; notifications fire only on NEW critical/malicious findings,
// which the caller supplies via NotificationFromNew.
package notify

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/johanviberg/guardian/internal/model"
)

// Notification is a single alert to be delivered across channels.
type Notification struct {
	Title    string
	Body     string
	Findings []model.Finding
	Severity model.Severity
}

// Notifier is a single delivery channel.
type Notifier interface {
	// Notify delivers n. It must honor ctx cancellation/deadline.
	Notify(ctx context.Context, n Notification) error
	// Name is a short, stable identifier for the channel (used in errors/logs).
	Name() string
}

// severityRank orders severities from most to least severe. Higher rank means
// more severe. Unknown severities rank below info.
func severityRank(s model.Severity) int {
	switch s {
	case model.SeverityCritical:
		return 4
	case model.SeverityHigh:
		return 3
	case model.SeverityMedium:
		return 2
	case model.SeverityLow:
		return 1
	case model.SeverityInfo:
		return 0
	default:
		return -1
	}
}

// atLeast reports whether got is at least as severe as want.
func atLeast(got, want model.Severity) bool {
	return severityRank(got) >= severityRank(want)
}

// maxSeverity returns the most severe severity among findings, or SeverityInfo
// if findings is empty.
func maxSeverity(findings []model.Finding) model.Severity {
	best := model.SeverityInfo
	for _, f := range findings {
		if severityRank(f.Severity) > severityRank(best) {
			best = f.Severity
		}
	}
	return best
}

// QuietHours is a daily do-not-disturb window in local wall-clock time. When
// Start == End the window is empty (never quiet). A window that wraps past
// midnight (Start > End, e.g. 22:00–07:00) is supported.
type QuietHours struct {
	// Enabled gates the whole feature; a zero QuietHours is never quiet.
	Enabled bool
	// Start and End are minutes since local midnight, [0,1440).
	Start int
	End   int
}

// Contains reports whether t (in its own location) falls inside the window.
func (q QuietHours) Contains(t time.Time) bool {
	if !q.Enabled || q.Start == q.End {
		return false
	}
	m := t.Hour()*60 + t.Minute()
	if q.Start < q.End {
		return m >= q.Start && m < q.End
	}
	// Wrapping window (e.g. 22:00–07:00).
	return m >= q.Start || m < q.End
}

// Config controls Dispatcher gating.
type Config struct {
	// Threshold is the minimum severity that triggers a notification.
	// Defaults to SeverityCritical when empty.
	Threshold model.Severity
	// QuietHours suppresses delivery during a daily window unless the
	// notification is at OverrideQuiet severity or above.
	QuietHours QuietHours
	// OverrideQuiet, when set, lets sufficiently severe notifications pierce
	// quiet hours. Empty means quiet hours suppress everything.
	OverrideQuiet model.Severity
	// Now is an injectable clock for tests; defaults to time.Now.
	Now func() time.Time
}

func (c Config) threshold() model.Severity {
	if c.Threshold == "" {
		return model.SeverityCritical
	}
	return c.Threshold
}

func (c Config) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Dispatcher fans a Notification out to its enabled notifiers, subject to Config.
type Dispatcher struct {
	cfg       Config
	notifiers []Notifier
}

// NewDispatcher builds a Dispatcher from a config and a set of channels.
func NewDispatcher(cfg Config, notifiers ...Notifier) *Dispatcher {
	return &Dispatcher{cfg: cfg, notifiers: notifiers}
}

// ShouldSend reports whether a notification of the given severity should be
// delivered under the current config and clock. It is exported so callers can
// skip building a Notification entirely when nothing would be sent.
func (d *Dispatcher) ShouldSend(sev model.Severity) bool {
	if !atLeast(sev, d.cfg.threshold()) {
		return false
	}
	if d.cfg.QuietHours.Contains(d.cfg.now()) {
		// Suppressed unless severe enough to override quiet hours.
		if d.cfg.OverrideQuiet == "" || !atLeast(sev, d.cfg.OverrideQuiet) {
			return false
		}
	}
	return true
}

// Dispatch delivers n to every enabled notifier if gating permits. It returns
// nil when gating suppresses the notification (this is not an error). Errors
// from individual channels are aggregated with errors.Join; one failing channel
// does not prevent the others from being attempted.
func (d *Dispatcher) Dispatch(ctx context.Context, n Notification) error {
	if !d.ShouldSend(n.Severity) {
		return nil
	}
	errs := make([]error, 0, len(d.notifiers))
	for _, ch := range d.notifiers {
		if err := ch.Notify(ctx, n); err != nil {
			errs = append(errs, fmt.Errorf("notify %s: %w", ch.Name(), err))
		}
	}
	return errors.Join(errs...)
}

// NotificationFromNew builds a Notification from the NEW findings of a diff,
// filtered to those at or above threshold. The send return is false when no
// finding clears the threshold, in which case the Notification is the zero
// value and the caller should not dispatch.
//
// It takes the new-finding slice directly (e.g. diff.Result.New) rather than the
// diff type so this package depends only on internal/model.
func NotificationFromNew(newFindings []model.Finding, threshold model.Severity) (Notification, bool) {
	if threshold == "" {
		threshold = model.SeverityCritical
	}
	var kept []model.Finding
	for _, f := range newFindings {
		if f.Suppressed {
			continue
		}
		if atLeast(f.Severity, threshold) {
			kept = append(kept, f)
		}
	}
	if len(kept) == 0 {
		return Notification{}, false
	}
	sev := maxSeverity(kept)
	return Notification{
		Title:    titleFor(kept, sev),
		Body:     bodyFor(kept),
		Findings: kept,
		Severity: sev,
	}, true
}

func titleFor(findings []model.Finding, sev model.Severity) string {
	n := len(findings)
	noun := "finding"
	if n != 1 {
		noun = "findings"
	}
	return fmt.Sprintf("guardian: %d new %s %s", n, sev, noun)
}

func bodyFor(findings []model.Finding) string {
	lines := make([]string, 0, len(findings))
	for _, f := range findings {
		lines = append(lines, fmt.Sprintf("[%s] %s %s@%s (%s) — %s",
			f.Severity, f.Ecosystem, f.Name, f.Version, f.CatalogID, f.Class))
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}
