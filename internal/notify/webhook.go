package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/johanviberg/guardian/internal/model"
)

// defaultWebhookTimeout bounds a single delivery attempt when the caller's
// context carries no deadline.
const defaultWebhookTimeout = 10 * time.Second

// WebhookNotifier POSTs a JSON notification to a configured URL using stdlib
// net/http. When the URL is a Slack incoming-webhook, it sends Slack's
// {"text": "..."} shape; otherwise it sends a structured guardian payload.
type WebhookNotifier struct {
	// URL is the endpoint to POST to; required.
	URL string
	// Client is the HTTP client; defaults to a client with defaultWebhookTimeout.
	Client *http.Client
	// Slack forces Slack payload shape. When false, the shape is auto-detected
	// from the URL (hooks.slack.com).
	Slack bool
}

// guardianPayload is the structured payload sent to non-Slack endpoints.
type guardianPayload struct {
	Title    string          `json:"title"`
	Body     string          `json:"body"`
	Severity model.Severity  `json:"severity"`
	Findings []model.Finding `json:"findings"`
}

// slackPayload is the Slack incoming-webhook shape.
type slackPayload struct {
	Text string `json:"text"`
}

// NewWebhookNotifier returns a WebhookNotifier for url. Slack shape is detected
// from the URL host.
func NewWebhookNotifier(url string) *WebhookNotifier {
	return &WebhookNotifier{URL: url, Slack: isSlackURL(url)}
}

func isSlackURL(url string) bool {
	return strings.Contains(url, "hooks.slack.com")
}

// Name implements Notifier.
func (w *WebhookNotifier) Name() string {
	if w.useSlack() {
		return "slack"
	}
	return "webhook"
}

func (w *WebhookNotifier) useSlack() bool {
	return w.Slack || isSlackURL(w.URL)
}

func (w *WebhookNotifier) client() *http.Client {
	if w.Client != nil {
		return w.Client
	}
	return &http.Client{Timeout: defaultWebhookTimeout}
}

// Notify implements Notifier by POSTing the appropriate JSON payload.
func (w *WebhookNotifier) Notify(ctx context.Context, n Notification) error {
	if w.URL == "" {
		return fmt.Errorf("webhook: empty URL")
	}

	var (
		payload any
	)
	if w.useSlack() {
		text := n.Title
		if n.Body != "" {
			text = n.Title + "\n" + n.Body
		}
		payload = slackPayload{Text: text}
	} else {
		payload = guardianPayload{
			Title:    n.Title,
			Body:     n.Body,
			Severity: n.Severity,
			Findings: n.Findings,
		}
	}

	buf, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("webhook: marshal: %w", err)
	}

	// Apply a default timeout only if the caller's ctx has no deadline.
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultWebhookTimeout)
		defer cancel()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("webhook: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := w.client().Do(req)
	if err != nil {
		return fmt.Errorf("webhook: post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook: unexpected status %d", resp.StatusCode)
	}
	return nil
}
