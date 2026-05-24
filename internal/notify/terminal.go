package notify

import (
	"context"
	"fmt"
	"io"
	"strings"
)

// TerminalNotifier writes a formatted notification block to an io.Writer.
// It is always-on and never fails on gating (gating is the Dispatcher's job).
type TerminalNotifier struct {
	// W is the destination; required.
	W io.Writer
}

// NewTerminalNotifier returns a TerminalNotifier writing to w.
func NewTerminalNotifier(w io.Writer) *TerminalNotifier {
	return &TerminalNotifier{W: w}
}

// Name implements Notifier.
func (t *TerminalNotifier) Name() string { return "terminal" }

// Notify implements Notifier by writing a bordered text block.
func (t *TerminalNotifier) Notify(_ context.Context, n Notification) error {
	var b strings.Builder
	const rule = "────────────────────────────────────────"
	b.WriteString(rule)
	b.WriteByte('\n')
	fmt.Fprintf(&b, "%s\n", n.Title)
	fmt.Fprintf(&b, "severity: %s\n", n.Severity)
	b.WriteString(rule)
	b.WriteByte('\n')
	if n.Body != "" {
		b.WriteString(n.Body)
		b.WriteByte('\n')
	}
	b.WriteString(rule)
	b.WriteByte('\n')
	_, err := io.WriteString(t.W, b.String())
	return err
}
