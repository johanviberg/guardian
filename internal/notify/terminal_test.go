package notify

import (
	"bytes"
	"context"
	"testing"

	"github.com/johanviberg/guardian/internal/model"
)

func TestTerminalNotifierGolden(t *testing.T) {
	findings := []model.Finding{critFinding()}
	n, send := NotificationFromNew(findings, model.SeverityCritical)
	if !send {
		t.Fatal("expected send")
	}

	var buf bytes.Buffer
	tn := NewTerminalNotifier(&buf)
	if err := tn.Notify(context.Background(), n); err != nil {
		t.Fatalf("notify: %v", err)
	}

	want := "────────────────────────────────────────\n" +
		"guardian: 1 new critical finding\n" +
		"severity: critical\n" +
		"────────────────────────────────────────\n" +
		"[critical] npm evil-pkg@1.2.3 (MAL-2026-104) — confirmed-malicious\n" +
		"────────────────────────────────────────\n"

	if got := buf.String(); got != want {
		t.Errorf("golden mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}
