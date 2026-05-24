package notify

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/johanviberg/guardian/internal/model"
)

// fakeNotifier records calls and optionally errors.
type fakeNotifier struct {
	name  string
	err   error
	calls int
	lastN Notification
}

func (f *fakeNotifier) Name() string { return f.name }
func (f *fakeNotifier) Notify(_ context.Context, n Notification) error {
	f.calls++
	f.lastN = n
	return f.err
}

func critFinding() model.Finding {
	return model.Finding{
		CatalogID: "MAL-2026-104",
		Severity:  model.SeverityCritical,
		Class:     model.ClassConfirmedMalicious,
		Ecosystem: "npm",
		Name:      "evil-pkg",
		Version:   "1.2.3",
	}
}

func TestDispatchFanOutAndErrorAggregation(t *testing.T) {
	ok1 := &fakeNotifier{name: "term"}
	boom := &fakeNotifier{name: "hook", err: errors.New("boom")}
	ok2 := &fakeNotifier{name: "desk"}

	d := NewDispatcher(Config{Threshold: model.SeverityCritical}, ok1, boom, ok2)
	n := Notification{Title: "t", Severity: model.SeverityCritical}

	err := d.Dispatch(context.Background(), n)
	if err == nil {
		t.Fatal("expected aggregated error, got nil")
	}
	if !strings.Contains(err.Error(), "boom") || !strings.Contains(err.Error(), "hook") {
		t.Errorf("error should name the failing channel: %v", err)
	}
	// One failing channel must not stop the others.
	if ok1.calls != 1 || ok2.calls != 1 {
		t.Errorf("all channels should be called even when one errors: ok1=%d ok2=%d", ok1.calls, ok2.calls)
	}
	if boom.calls != 1 {
		t.Errorf("erroring channel should still be attempted: %d", boom.calls)
	}
}

func TestDispatchAllSucceed(t *testing.T) {
	a := &fakeNotifier{name: "a"}
	b := &fakeNotifier{name: "b"}
	d := NewDispatcher(Config{Threshold: model.SeverityCritical}, a, b)
	if err := d.Dispatch(context.Background(), Notification{Severity: model.SeverityCritical}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestThresholdGating(t *testing.T) {
	tests := []struct {
		name      string
		threshold model.Severity
		sev       model.Severity
		want      bool
	}{
		{"default threshold critical, high suppressed", "", model.SeverityHigh, false},
		{"default threshold critical, critical sent", "", model.SeverityCritical, true},
		{"high threshold, high sent", model.SeverityHigh, model.SeverityHigh, true},
		{"high threshold, medium suppressed", model.SeverityHigh, model.SeverityMedium, false},
		{"high threshold, critical sent", model.SeverityHigh, model.SeverityCritical, true},
		{"info threshold, info sent", model.SeverityInfo, model.SeverityInfo, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch := &fakeNotifier{name: "x"}
			d := NewDispatcher(Config{Threshold: tt.threshold}, ch)
			err := d.Dispatch(context.Background(), Notification{Severity: tt.sev})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			gotSent := ch.calls == 1
			if gotSent != tt.want {
				t.Errorf("sent=%v want=%v", gotSent, tt.want)
			}
		})
	}
}

func atMinute(h, m int) func() time.Time {
	return func() time.Time {
		return time.Date(2026, 5, 24, h, m, 0, 0, time.Local)
	}
}

func TestQuietHoursGating(t *testing.T) {
	tests := []struct {
		name     string
		quiet    QuietHours
		override model.Severity
		sev      model.Severity
		now      func() time.Time
		want     bool
	}{
		{
			name:  "inside simple window suppresses",
			quiet: QuietHours{Enabled: true, Start: 9 * 60, End: 17 * 60},
			sev:   model.SeverityCritical,
			now:   atMinute(12, 0),
			want:  false,
		},
		{
			name:  "outside simple window sends",
			quiet: QuietHours{Enabled: true, Start: 9 * 60, End: 17 * 60},
			sev:   model.SeverityCritical,
			now:   atMinute(20, 0),
			want:  true,
		},
		{
			name:  "wrapping window inside (late night) suppresses",
			quiet: QuietHours{Enabled: true, Start: 22 * 60, End: 7 * 60},
			sev:   model.SeverityCritical,
			now:   atMinute(23, 30),
			want:  false,
		},
		{
			name:  "wrapping window inside (early morning) suppresses",
			quiet: QuietHours{Enabled: true, Start: 22 * 60, End: 7 * 60},
			sev:   model.SeverityCritical,
			now:   atMinute(3, 0),
			want:  false,
		},
		{
			name:  "wrapping window outside sends",
			quiet: QuietHours{Enabled: true, Start: 22 * 60, End: 7 * 60},
			sev:   model.SeverityCritical,
			now:   atMinute(12, 0),
			want:  true,
		},
		{
			name:     "override pierces quiet hours",
			quiet:    QuietHours{Enabled: true, Start: 9 * 60, End: 17 * 60},
			override: model.SeverityCritical,
			sev:      model.SeverityCritical,
			now:      atMinute(12, 0),
			want:     true,
		},
		{
			name:     "below override stays suppressed in quiet hours",
			quiet:    QuietHours{Enabled: true, Start: 9 * 60, End: 17 * 60},
			override: model.SeverityCritical,
			sev:      model.SeverityHigh,
			now:      atMinute(12, 0),
			want:     false,
		},
		{
			name:  "disabled quiet hours never suppress",
			quiet: QuietHours{Enabled: false, Start: 9 * 60, End: 17 * 60},
			sev:   model.SeverityCritical,
			now:   atMinute(12, 0),
			want:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Threshold:     model.SeverityHigh,
				QuietHours:    tt.quiet,
				OverrideQuiet: tt.override,
				Now:           tt.now,
			}
			d := NewDispatcher(cfg)
			if got := d.ShouldSend(tt.sev); got != tt.want {
				t.Errorf("ShouldSend=%v want=%v", got, tt.want)
			}
		})
	}
}

func TestNotificationFromNew(t *testing.T) {
	crit := critFinding()
	high := model.Finding{CatalogID: "ADV-1", Severity: model.SeverityHigh, Class: model.ClassVulnerable, Ecosystem: "pypi", Name: "lib", Version: "0.1"}
	low := model.Finding{CatalogID: "ADV-2", Severity: model.SeverityLow, Class: model.ClassVulnerable, Ecosystem: "go", Name: "m", Version: "2"}
	suppressed := crit
	suppressed.Suppressed = true

	t.Run("filters to threshold", func(t *testing.T) {
		n, send := NotificationFromNew([]model.Finding{crit, high, low}, model.SeverityCritical)
		if !send {
			t.Fatal("expected send=true")
		}
		if len(n.Findings) != 1 || n.Findings[0].CatalogID != "MAL-2026-104" {
			t.Errorf("expected only critical finding, got %+v", n.Findings)
		}
		if n.Severity != model.SeverityCritical {
			t.Errorf("severity=%v", n.Severity)
		}
	})

	t.Run("no findings clear threshold", func(t *testing.T) {
		_, send := NotificationFromNew([]model.Finding{low}, model.SeverityCritical)
		if send {
			t.Error("expected send=false")
		}
	})

	t.Run("suppressed excluded", func(t *testing.T) {
		_, send := NotificationFromNew([]model.Finding{suppressed}, model.SeverityCritical)
		if send {
			t.Error("suppressed findings must not trigger a notification")
		}
	})

	t.Run("max severity chosen", func(t *testing.T) {
		n, send := NotificationFromNew([]model.Finding{high, crit}, model.SeverityHigh)
		if !send || n.Severity != model.SeverityCritical {
			t.Errorf("expected critical max severity, got send=%v sev=%v", send, n.Severity)
		}
	})
}

func TestDesktopNotifierUsesStub(t *testing.T) {
	orig := sendDesktopFn
	defer func() { sendDesktopFn = orig }()

	var gotTitle, gotBody string
	sendDesktopFn = func(title, body string) error {
		gotTitle, gotBody = title, body
		return nil
	}
	d := NewDesktopNotifier()
	if err := d.Notify(context.Background(), Notification{Title: "T", Body: "B"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotTitle != "T" || gotBody != "B" {
		t.Errorf("stub got title=%q body=%q", gotTitle, gotBody)
	}
}
