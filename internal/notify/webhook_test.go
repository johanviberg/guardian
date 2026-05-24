package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/johanviberg/guardian/internal/model"
)

func TestWebhookGenericPayload(t *testing.T) {
	var gotBody []byte
	var gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wn := NewWebhookNotifier(srv.URL)
	if wn.useSlack() {
		t.Fatal("non-slack URL must not use slack shape")
	}
	if wn.Name() != "webhook" {
		t.Errorf("name=%q", wn.Name())
	}

	n := Notification{
		Title:    "guardian: 1 new critical finding",
		Body:     "body line",
		Severity: model.SeverityCritical,
		Findings: []model.Finding{critFinding()},
	}
	if err := wn.Notify(context.Background(), n); err != nil {
		t.Fatalf("notify: %v", err)
	}

	if gotCT != "application/json" {
		t.Errorf("content-type=%q", gotCT)
	}
	var p guardianPayload
	if err := json.Unmarshal(gotBody, &p); err != nil {
		t.Fatalf("unmarshal generic payload: %v (body=%s)", err, gotBody)
	}
	if p.Title != n.Title || p.Severity != model.SeverityCritical || len(p.Findings) != 1 {
		t.Errorf("unexpected generic payload: %+v", p)
	}
	if p.Findings[0].CatalogID != "MAL-2026-104" {
		t.Errorf("finding not preserved: %+v", p.Findings[0])
	}
}

func TestWebhookSlackPayload(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Force Slack shape (the test server URL is not hooks.slack.com).
	wn := &WebhookNotifier{URL: srv.URL, Slack: true}
	if wn.Name() != "slack" {
		t.Errorf("name=%q", wn.Name())
	}

	n := Notification{Title: "guardian: alert", Body: "detail"}
	if err := wn.Notify(context.Background(), n); err != nil {
		t.Fatalf("notify: %v", err)
	}

	var p slackPayload
	if err := json.Unmarshal(gotBody, &p); err != nil {
		t.Fatalf("unmarshal slack payload: %v (body=%s)", err, gotBody)
	}
	// Slack shape is exactly {"text": "..."}.
	var raw map[string]any
	if err := json.Unmarshal(gotBody, &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 1 {
		t.Errorf("slack payload should have exactly one field, got %v", raw)
	}
	if p.Text != "guardian: alert\ndetail" {
		t.Errorf("slack text=%q", p.Text)
	}
}

func TestWebhookSlackURLAutoDetect(t *testing.T) {
	wn := NewWebhookNotifier("https://hooks.slack.com/services/T000/B000/xyz")
	if !wn.useSlack() {
		t.Error("slack URL should be auto-detected")
	}
}

func TestWebhookNon2xxErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	wn := NewWebhookNotifier(srv.URL)
	if err := wn.Notify(context.Background(), Notification{Title: "x"}); err == nil {
		t.Error("expected error on non-2xx status")
	}
}

func TestWebhookEmptyURL(t *testing.T) {
	wn := &WebhookNotifier{}
	if err := wn.Notify(context.Background(), Notification{}); err == nil {
		t.Error("expected error on empty URL")
	}
}
